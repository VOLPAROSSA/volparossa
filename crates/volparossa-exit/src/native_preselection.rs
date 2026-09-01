//! Callerless Exit-side ownership for one endpoint-separated native preselection probe.
//!
//! This module intentionally has no runtime entry point. It proves the smallest safe Exit-side
//! transition boundary while the helper still lacks a same-connection prepared-lease/lifecycle
//! provider and post-baseline challenge evidence. The only state that can reach readiness retains a
//! typed projection from an `ExitEndpointLease`, and the only state that can reach a result consumes
//! a private helper/datapath observation. The projection is not helper-resource custody, and no
//! phase seam is visible outside this module. The authenticated node/Peer-ID arguments are raw test
//! inputs until a future connection-owning caller supplies them. Every produced phase caps its own
//! local lifetime and retains the process boot incarnation; the bounded request replay cache itself
//! is deliberately process-local.

use zeroize::Zeroizing;

use volparossa_protocol::{
    MAX_NATIVE_PROBE_LIFETIME_MS, NativeProbeEndpointBinding, NativeProbeExitReady,
    NativeProbeExitResult, NativeProbeLeaseProof, NativeProbePathScope, NativeProbePermit,
    NativeProbePermitRequest, ObservationNetworkPrefix, PreselectionActorBinding, TimePolicy,
    generate_nonce, native_probe_challenge_hash, native_probe_exit_ready_hash,
    native_probe_permit_hash, native_probe_permit_request_hash,
    native_probe_prepared_lease_commitment, node_id_from_public_key, sign_control_message_with,
    verify_control_message,
};
use volparossa_wireguard::ExitEndpointLease;

use super::{ExitError, ExitService, NODE_ID_BYTES, wire_endpoint};

const ID_BYTES: usize = 16;
const NONCE_BYTES: usize = 32;

/// Exact endpoint-free request and Exit permit, consumed by readiness once.
#[must_use = "an issued native-probe permit must be consumed or expire"]
struct IssuedNativeProbePermit {
    signed_request: Vec<u8>,
    signed_permit: Vec<u8>,
    scope: NativeProbePathScope,
    exit_boot_id: [u8; ID_BYTES],
    expires_at_ms: u64,
}

impl IssuedNativeProbePermit {
    /// Borrow the exact request for forwarding to the selected data Relay.
    fn signed_request(&self) -> &[u8] {
        &self.signed_request
    }

    /// Borrow the exact Exit permit for client and data-Relay verification.
    fn signed_permit(&self) -> &[u8] {
        &self.signed_permit
    }
}

/// Typed projection of one local Exit endpoint plus a claimed helper runtime.
///
/// `ExitEndpointLease` is `Copy`, so this value is deliberately not described as affine helper
/// custody, same-connection provenance or cleanup authority. Construction and use stay inside this
/// callerless module until a future provider owns the actual helper context and bounded
/// Destroy/reaper lifecycle.
#[must_use = "a native-probe Exit endpoint projection must remain phase-bound"]
struct PreparedNativeProbeExitProjection {
    _lease_projection: ExitEndpointLease,
    binding: NativeProbeEndpointBinding,
}

impl PreparedNativeProbeExitProjection {
    fn from_typed_exit_lease_projection(
        helper_runtime_id: [u8; NODE_ID_BYTES],
        lease: ExitEndpointLease,
    ) -> Result<Self, ExitError> {
        if helper_runtime_id == [0; NODE_ID_BYTES] {
            return Err(ExitError::LeaseInvariant);
        }
        let endpoint = wire_endpoint(lease.public_endpoint());
        let commitment = native_probe_prepared_lease_commitment(
            &helper_runtime_id,
            lease.route_context_id(),
            lease.lease_handle().as_bytes(),
            &endpoint,
        )?;
        Ok(Self {
            _lease_projection: lease,
            binding: NativeProbeEndpointBinding {
                helper_runtime_id: helper_runtime_id.to_vec(),
                route_context_id: lease.route_context_id().to_vec(),
                endpoint: Some(endpoint),
                prepared_lease_commitment: commitment.to_vec(),
            },
        })
    }
}

/// Exit readiness plus the exact local projection retained for terminal proof binding.
#[must_use = "native-probe Exit readiness must retain its projection until result"]
struct IssuedNativeProbeExitReady {
    permit: IssuedNativeProbePermit,
    signed_ready: Vec<u8>,
    prepared_exit: PreparedNativeProbeExitProjection,
    exit_boot_id: [u8; ID_BYTES],
    expires_at_ms: u64,
}

impl IssuedNativeProbeExitReady {
    /// Borrow the exact readiness message for the authenticated data Relay only.
    fn signed_ready(&self) -> &[u8] {
        &self.signed_ready
    }
}

/// Private result of the future helper/datapath challenge provider.
///
/// There is deliberately no production constructor. A later provider must derive all lease facts
/// from strict post-baseline helper observations and return the exact challenge only after it
/// traversed the two-leg route. Unit tests construct fixtures inside this module only.
#[must_use = "a native-probe observation may complete exactly one Exit result"]
struct NativeProbeExitObservation {
    helper_runtime_id: [u8; NODE_ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    prepared_lease_commitment: [u8; NODE_ID_BYTES],
    challenge_response: Zeroizing<[u8; NONCE_BYTES]>,
    observed_network_prefix: ObservationNetworkPrefix,
    latest_handshake_unix: u64,
    received_bytes_after_baseline: u64,
    transmitted_bytes_after_baseline: u64,
}

/// Endpoint-free terminal Exit result for delivery through the exact data Relay.
#[must_use = "a signed native-probe Exit result must be delivered or dropped"]
struct IssuedNativeProbeExitResult {
    signed_result: Vec<u8>,
}

impl IssuedNativeProbeExitResult {
    /// Borrow the exact signed result.
    fn signed_result(&self) -> &[u8] {
        &self.signed_result
    }
}

impl ExitService {
    /// Verify one exact client request and mint one affine endpoint-free Exit permit.
    ///
    /// The caller-supplied authenticated channel identity must match the signed control Relay.
    /// Enabled-role, current exact policy, Exit identity, every actor's node/key/Peer-ID binding
    /// and all signed ceilings are checked before the signer can run. Any failure after replay
    /// insertion rolls that insertion back so an unmodified legitimate retry is not consumed.
    #[allow(
        clippy::too_many_arguments,
        reason = "all authenticated channel, local identity and signing authorities stay explicit"
    )]
    fn issue_native_probe_permit_with<F>(
        &mut self,
        signed_request: Vec<u8>,
        authenticated_control_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_control_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        signer: F,
    ) -> Result<IssuedNativeProbePermit, ExitError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_native_probe_local_identity(local_public_key)?;
        let verified = verify_control_message::<NativeProbePermitRequest>(
            &signed_request,
            now_ms,
            native_time_policy(),
            &mut self.native_probe_request_replay,
        )?;
        let replay_entry = (*verified.sender_id(), *verified.nonce());
        let request = verified.message().clone();
        let outcome = (|| {
            let scope = request
                .scope
                .clone()
                .ok_or(ExitError::InvalidGrant("native probe request scope"))?;
            self.validate_live_native_probe_scope(&scope, now_ms, local_public_key)?;
            require_authenticated_actor(
                scope.control.as_ref(),
                authenticated_control_relay_node_id,
                authenticated_control_relay_peer_id,
                "native probe control Relay",
            )
            .map_err(|_| ExitError::ControlRelayMismatch)?;
            if verified.sender_public_key() != scope.client_session_public_key.as_slice() {
                return Err(ExitError::InvalidGrant("native probe client session"));
            }

            let expires_at_ms = native_probe_phase_expiry(request.expires_at_ms, now_ms)?;
            let nonce = generate_nonce();
            let permit = NativeProbePermit {
                request_hash: native_probe_permit_request_hash(&signed_request)?.to_vec(),
                scope: Some(scope.clone()),
                issued_at_ms: now_ms,
                expires_at_ms,
                nonce: nonce.to_vec(),
            };
            let signed_permit = sign_control_message_with(
                &permit,
                local_public_key,
                now_ms,
                permit.expires_at_ms,
                nonce,
                native_time_policy(),
                signer,
            )?;
            Ok(IssuedNativeProbePermit {
                signed_request,
                signed_permit,
                scope,
                exit_boot_id: self.exit_boot_id,
                expires_at_ms: permit.expires_at_ms,
            })
        })();
        if outcome.is_err() {
            let _ = self
                .native_probe_request_replay
                .rollback(&replay_entry.0, &replay_entry.1);
        }
        outcome
    }

    /// Consume a permit and mint readiness only for the supplied exact data-Relay identity.
    ///
    /// The `RelayExit` endpoint is accepted only on that authenticated Relay channel. The Exit
    /// endpoint is derived from the private typed helper-prepared lease; its opaque handle is used
    /// solely in the domain-separated commitment and is never serialized.
    #[allow(
        clippy::too_many_arguments,
        reason = "all authenticated channel, prepared lease and signing authorities stay explicit"
    )]
    fn issue_native_probe_ready_with<F>(
        &mut self,
        permit: IssuedNativeProbePermit,
        authenticated_data_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_data_relay_peer_id: &[u8],
        relay_exit_endpoint: NativeProbeEndpointBinding,
        prepared_exit: PreparedNativeProbeExitProjection,
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        signer: F,
    ) -> Result<IssuedNativeProbeExitReady, ExitError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_native_probe_local_identity(local_public_key)?;
        self.validate_live_native_probe_scope(&permit.scope, now_ms, local_public_key)?;
        require_authenticated_actor(
            permit.scope.data_relay.as_ref(),
            authenticated_data_relay_node_id,
            authenticated_data_relay_peer_id,
            "native probe data Relay",
        )?;
        if permit.exit_boot_id != self.exit_boot_id {
            return Err(ExitError::ExitBootMismatch);
        }
        if now_ms >= permit.expires_at_ms
            || prepared_exit.binding.route_context_id != permit.scope.probe_id
        {
            return Err(ExitError::InvalidGrant("native probe prepared Exit lease"));
        }

        let expires_at_ms = native_probe_phase_expiry(permit.expires_at_ms, now_ms)?;
        let nonce = generate_nonce();
        let ready = NativeProbeExitReady {
            permit_hash: native_probe_permit_hash(&permit.signed_permit)?.to_vec(),
            scope: Some(permit.scope.clone()),
            relay_exit_endpoint: Some(relay_exit_endpoint),
            exit_endpoint: Some(prepared_exit.binding.clone()),
            ready_at_ms: now_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        let signed_ready = sign_control_message_with(
            &ready,
            local_public_key,
            now_ms,
            ready.expires_at_ms,
            nonce,
            native_time_policy(),
            signer,
        )?;
        Ok(IssuedNativeProbeExitReady {
            permit,
            signed_ready,
            prepared_exit,
            exit_boot_id: self.exit_boot_id,
            expires_at_ms: ready.expires_at_ms,
        })
    }

    /// Consume readiness and one private helper/datapath observation into an Exit result.
    ///
    /// Exact helper runtime, route context and lease commitment must still match the retained
    /// prepared lease. The signed payload validation additionally enforces challenge hash, prefix
    /// family, strict non-zero post-baseline RX/TX growth, handshake and all lifetime bindings.
    #[allow(
        clippy::too_many_arguments,
        reason = "all authenticated channel, observation and signing authorities stay explicit"
    )]
    fn issue_native_probe_result_with<F>(
        &mut self,
        ready: IssuedNativeProbeExitReady,
        observation: NativeProbeExitObservation,
        authenticated_data_relay_node_id: &[u8; NODE_ID_BYTES],
        authenticated_data_relay_peer_id: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        signer: F,
    ) -> Result<IssuedNativeProbeExitResult, ExitError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        self.require_enabled()?;
        self.policy.ensure_active_at(now_ms)?;
        self.ensure_native_probe_local_identity(local_public_key)?;
        self.validate_live_native_probe_scope(&ready.permit.scope, now_ms, local_public_key)?;
        require_authenticated_actor(
            ready.permit.scope.data_relay.as_ref(),
            authenticated_data_relay_node_id,
            authenticated_data_relay_peer_id,
            "native probe data Relay",
        )?;
        let binding = &ready.prepared_exit.binding;
        if ready.exit_boot_id != self.exit_boot_id || ready.permit.exit_boot_id != self.exit_boot_id
        {
            return Err(ExitError::ExitBootMismatch);
        }
        if now_ms >= ready.expires_at_ms
            || observation.helper_runtime_id.as_slice() != binding.helper_runtime_id
            || observation.route_context_id.as_slice() != binding.route_context_id
            || observation.prepared_lease_commitment.as_slice() != binding.prepared_lease_commitment
            || native_probe_challenge_hash(&observation.challenge_response)
                != ready.permit.scope.challenge_hash.as_slice()
        {
            return Err(ExitError::InvalidGrant(
                "native probe helper/datapath observation",
            ));
        }

        let expires_at_ms = native_probe_phase_expiry(ready.expires_at_ms, now_ms)?;
        let nonce = generate_nonce();
        let lease_proof = NativeProbeLeaseProof {
            helper_runtime_id: observation.helper_runtime_id.to_vec(),
            route_context_id: observation.route_context_id.to_vec(),
            prepared_lease_commitment: observation.prepared_lease_commitment.to_vec(),
            latest_handshake_unix: observation.latest_handshake_unix,
            received_bytes_after_baseline: observation.received_bytes_after_baseline,
            transmitted_bytes_after_baseline: observation.transmitted_bytes_after_baseline,
        };
        let result = NativeProbeExitResult {
            permit_hash: native_probe_permit_hash(&ready.permit.signed_permit)?.to_vec(),
            exit_ready_hash: native_probe_exit_ready_hash(&ready.signed_ready)?.to_vec(),
            scope: Some(ready.permit.scope),
            challenge_response: observation.challenge_response.to_vec(),
            observed_network_prefix: Some(observation.observed_network_prefix),
            exit_lease: Some(lease_proof),
            measured_at_ms: now_ms,
            expires_at_ms,
            nonce: nonce.to_vec(),
        };
        let signed_result = sign_control_message_with(
            &result,
            local_public_key,
            now_ms,
            result.expires_at_ms,
            nonce,
            native_time_policy(),
            signer,
        )?;
        Ok(IssuedNativeProbeExitResult { signed_result })
    }

    fn validate_live_native_probe_scope(
        &self,
        scope: &NativeProbePathScope,
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
    ) -> Result<(), ExitError> {
        self.policy.ensure_active_at(now_ms)?;
        if now_ms >= scope.attempt_expires_at_ms
            || scope.policy_version != self.policy.manifest_version()
            || scope.policy_hash.as_slice() != self.policy.policy_hash()
            || scope.policy_expires_at_ms != self.policy.expires_at_ms()
        {
            return Err(ExitError::InvalidGrant("native probe policy scope"));
        }
        let exit = exact_actor(scope.exit.as_ref(), now_ms, "native probe Exit actor")?;
        if exit.node_id != self.config.node_id || exit.public_key != local_public_key {
            return Err(ExitError::LocalIdentityMismatch);
        }
        let _ = exact_actor(
            scope.control.as_ref(),
            now_ms,
            "native probe control Relay actor",
        )?;
        let _ = exact_actor(
            scope.data_relay.as_ref(),
            now_ms,
            "native probe data Relay actor",
        )?;
        Ok(())
    }

    fn ensure_native_probe_local_identity(
        &self,
        local_public_key: [u8; NODE_ID_BYTES],
    ) -> Result<(), ExitError> {
        if node_id_from_public_key(&local_public_key) == self.config.node_id {
            Ok(())
        } else {
            Err(ExitError::LocalIdentityMismatch)
        }
    }
}

struct ExactActor {
    node_id: [u8; NODE_ID_BYTES],
    public_key: [u8; NODE_ID_BYTES],
    peer_id: Vec<u8>,
}

fn exact_actor(
    actor: Option<&PreselectionActorBinding>,
    now_ms: u64,
    field: &'static str,
) -> Result<ExactActor, ExitError> {
    let actor = actor.ok_or(ExitError::InvalidGrant(field))?;
    let public_key: [u8; NODE_ID_BYTES] = actor
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| ExitError::InvalidGrant(field))?;
    let node_id: [u8; NODE_ID_BYTES] = actor
        .node_id
        .as_slice()
        .try_into()
        .map_err(|_| ExitError::InvalidGrant(field))?;
    let peer_id =
        peer_id_from_public_key(&public_key).map_err(|()| ExitError::InvalidGrant(field))?;
    if node_id_from_public_key(&public_key) != node_id
        || actor.peer_id != peer_id
        || now_ms >= actor.advertisement_expires_at_ms
        || now_ms >= actor.capability_expires_at_ms
    {
        return Err(ExitError::InvalidGrant(field));
    }
    Ok(ExactActor {
        node_id,
        public_key,
        peer_id,
    })
}

fn require_authenticated_actor(
    actor: Option<&PreselectionActorBinding>,
    authenticated_node_id: &[u8; NODE_ID_BYTES],
    authenticated_peer_id: &[u8],
    field: &'static str,
) -> Result<(), ExitError> {
    let actor = exact_actor(actor, 0, field)?;
    if actor.node_id != *authenticated_node_id || actor.peer_id != authenticated_peer_id {
        return Err(ExitError::InvalidGrant(field));
    }
    Ok(())
}

fn peer_id_from_public_key(public_key: &[u8; NODE_ID_BYTES]) -> Result<Vec<u8>, ()> {
    let ed25519 =
        libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key).map_err(|_| ())?;
    Ok(libp2p_identity::PublicKey::from(ed25519)
        .to_peer_id()
        .to_bytes())
}

fn native_time_policy() -> TimePolicy {
    TimePolicy {
        maximum_lifetime_ms: MAX_NATIVE_PROBE_LIFETIME_MS,
        maximum_clock_skew_ms: TimePolicy::default().maximum_clock_skew_ms,
    }
}

fn native_probe_phase_expiry(parent_expires_at_ms: u64, now_ms: u64) -> Result<u64, ExitError> {
    let local_ceiling = now_ms
        .checked_add(MAX_NATIVE_PROBE_LIFETIME_MS)
        .ok_or(ExitError::InvalidGrant("native probe phase lifetime"))?;
    let expires_at_ms = parent_expires_at_ms.min(local_ceiling);
    if now_ms >= expires_at_ms {
        return Err(ExitError::InvalidGrant("native probe phase lifetime"));
    }
    Ok(expires_at_ms)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ed25519_dalek::{Signer as _, SigningKey};
    use volparossa_core::Bandwidth;
    use volparossa_policy::VerifiedManifest;
    use volparossa_protocol::{
        NativeProbeExitResult, ObservationAddressFamily, ProtocolError, ReplayCache, Transport,
        WireguardEndpoint, sign_control_message, sign_native_probe_relay_ready,
        sign_native_probe_start, verify_control_message, verify_native_probe_exit_ready,
        verify_native_probe_exit_result_for_relay, verify_native_probe_permit,
        verify_native_probe_relay_ready, verify_native_probe_start_for_relay,
    };
    use volparossa_test_support::verified_development_manifest;
    use volparossa_wireguard::{
        EndpointRole, HelperContextHandle, HelperLeaseHandle, PublicWireGuardEndpoint,
        WireGuardPublicKey,
    };

    use super::*;
    use crate::ExitServiceConfig;

    const NOW_MS: u64 = 1_900_000_000_000;
    const ATTEMPT_EXPIRY_MS: u64 = NOW_MS + 30_000;
    const PROBE_ID: [u8; ID_BYTES] = [2; ID_BYTES];
    const CHALLENGE: [u8; NONCE_BYTES] = [7; NONCE_BYTES];
    const EXIT_HELPER_RUNTIME: [u8; NODE_ID_BYTES] = [0xe1; NODE_ID_BYTES];

    struct Fixture {
        service: ExitService,
        policy: VerifiedManifest,
        exit_key: SigningKey,
        client_key: SigningKey,
        control_key: SigningKey,
        relay_key: SigningKey,
        scope: NativeProbePathScope,
        signed_request: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let exit_key = SigningKey::from_bytes(&[4; NODE_ID_BYTES]);
            let control_key = SigningKey::from_bytes(&[2; NODE_ID_BYTES]);
            let relay_key = SigningKey::from_bytes(&[3; NODE_ID_BYTES]);
            let client_key = SigningKey::from_bytes(&[1; NODE_ID_BYTES]);
            let policy = verified_development_manifest(NOW_MS, Vec::new()).expect("policy");
            let scope = scope(
                &client_key,
                &control_key,
                &relay_key,
                &exit_key,
                policy.manifest_version(),
                *policy.policy_hash(),
                policy.expires_at_ms(),
            );
            let request = NativeProbePermitRequest {
                scope: Some(scope.clone()),
                created_at_ms: NOW_MS,
                expires_at_ms: ATTEMPT_EXPIRY_MS,
                nonce: vec![10; NONCE_BYTES],
            };
            let signed_request = sign_control_message(
                &request,
                &client_key,
                NOW_MS,
                ATTEMPT_EXPIRY_MS,
                [10; NONCE_BYTES],
                native_time_policy(),
            )
            .expect("request");
            let service = ExitService::new_with_boot_id(
                ExitServiceConfig::enabled(
                    node_id_from_public_key(&exit_key.verifying_key().to_bytes()),
                    Bandwidth::new(100, 100).expect("bandwidth"),
                    8,
                    900,
                    30,
                    64,
                ),
                policy.clone(),
                None,
                [0xb0; ID_BYTES],
            )
            .expect("service");
            Self {
                service,
                policy,
                exit_key,
                client_key,
                control_key,
                relay_key,
                scope,
                signed_request,
            }
        }

        fn exit_public_key(&self) -> [u8; NODE_ID_BYTES] {
            self.exit_key.verifying_key().to_bytes()
        }

        fn control_node_id(&self) -> [u8; NODE_ID_BYTES] {
            node_id_from_public_key(&self.control_key.verifying_key().to_bytes())
        }

        fn control_peer_id(&self) -> Vec<u8> {
            peer_id_from_public_key(&self.control_key.verifying_key().to_bytes())
                .expect("control Peer ID")
        }

        fn relay_node_id(&self) -> [u8; NODE_ID_BYTES] {
            node_id_from_public_key(&self.relay_key.verifying_key().to_bytes())
        }

        fn relay_peer_id(&self) -> Vec<u8> {
            peer_id_from_public_key(&self.relay_key.verifying_key().to_bytes())
                .expect("Relay Peer ID")
        }

        fn issue_permit_at(&mut self, now_ms: u64) -> Result<IssuedNativeProbePermit, ExitError> {
            let control_node_id = self.control_node_id();
            let control_peer_id = self.control_peer_id();
            let public_key = self.exit_public_key();
            let exit_key = &self.exit_key;
            self.service.issue_native_probe_permit_with(
                self.signed_request.clone(),
                &control_node_id,
                &control_peer_id,
                now_ms,
                public_key,
                |message| Some(exit_key.sign(message).to_bytes()),
            )
        }

        fn issue_permit(&mut self) -> IssuedNativeProbePermit {
            self.issue_permit_at(NOW_MS + 1).expect("permit")
        }

        fn issue_ready(&mut self) -> IssuedNativeProbeExitReady {
            let permit = self.issue_permit();
            let relay_node_id = self.relay_node_id();
            let relay_peer_id = self.relay_peer_id();
            let relay_exit = relay_exit_binding(&self.scope);
            let prepared_exit = prepared_exit_lease(PROBE_ID);
            let public_key = self.exit_public_key();
            let exit_key = &self.exit_key;
            self.service
                .issue_native_probe_ready_with(
                    permit,
                    &relay_node_id,
                    &relay_peer_id,
                    relay_exit,
                    prepared_exit,
                    NOW_MS + 2,
                    public_key,
                    |message| Some(exit_key.sign(message).to_bytes()),
                )
                .expect("ready")
        }

        fn restart_service(&mut self, exit_boot_id: [u8; ID_BYTES]) {
            self.service = ExitService::new_with_boot_id(
                ExitServiceConfig::enabled(
                    node_id_from_public_key(&self.exit_public_key()),
                    Bandwidth::new(100, 100).expect("bandwidth"),
                    8,
                    900,
                    30,
                    64,
                ),
                self.policy.clone(),
                None,
                exit_boot_id,
            )
            .expect("restarted service");
        }
    }

    fn scope(
        client: &SigningKey,
        control: &SigningKey,
        relay: &SigningKey,
        exit: &SigningKey,
        policy_version: u64,
        policy_hash: [u8; NODE_ID_BYTES],
        policy_expires_at_ms: u64,
    ) -> NativeProbePathScope {
        let client_public_key = client.verifying_key().to_bytes();
        NativeProbePathScope {
            attempt_id: vec![1; ID_BYTES],
            probe_id: PROBE_ID.to_vec(),
            candidate_set_hash: vec![5; NODE_ID_BYTES],
            candidate_ordinal: 2,
            data_relay: Some(actor(relay, policy_expires_at_ms)),
            control: Some(actor(control, policy_expires_at_ms)),
            exit: Some(actor(exit, policy_expires_at_ms)),
            client_session_id: node_id_from_public_key(&client_public_key).to_vec(),
            client_session_public_key: client_public_key.to_vec(),
            transport: Transport::TcpMptcp as i32,
            address_family: ObservationAddressFamily::Ipv4 as i32,
            policy_version,
            policy_hash: policy_hash.to_vec(),
            policy_expires_at_ms,
            challenge_hash: native_probe_challenge_hash(&CHALLENGE).to_vec(),
            attempt_expires_at_ms: ATTEMPT_EXPIRY_MS,
        }
    }

    fn actor(key: &SigningKey, expires_at_ms: u64) -> PreselectionActorBinding {
        let public_key = key.verifying_key().to_bytes();
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: peer_id_from_public_key(&public_key).expect("Peer ID"),
            public_key: public_key.to_vec(),
            advertisement_sequence: 1,
            advertisement_expires_at_ms: expires_at_ms,
            advertisement_payload_hash: vec![0xa1; NODE_ID_BYTES],
            capability_expires_at_ms: expires_at_ms,
        }
    }

    fn prepared_exit_lease(route_context_id: [u8; ID_BYTES]) -> PreparedNativeProbeExitProjection {
        let endpoint = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([0xe2; NODE_ID_BYTES]),
            IpAddr::V4(Ipv4Addr::new(84, 1, 1, 1)),
            20_001,
        )
        .expect("Exit endpoint");
        let lease = ExitEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([0xe3; NODE_ID_BYTES]).expect("context handle"),
            HelperLeaseHandle::from_bytes([0xe4; NODE_ID_BYTES]).expect("lease handle"),
            1,
            EndpointRole::Exit,
            endpoint,
        )
        .expect("Exit lease");
        PreparedNativeProbeExitProjection::from_typed_exit_lease_projection(
            EXIT_HELPER_RUNTIME,
            lease,
        )
        .expect("prepared Exit projection")
    }

    fn relay_exit_binding(scope: &NativeProbePathScope) -> NativeProbeEndpointBinding {
        binding_with_material(
            scope,
            [0xd1; NODE_ID_BYTES],
            [0xd3; NODE_ID_BYTES],
            WireguardEndpoint {
                public_key: vec![0xd2; NODE_ID_BYTES],
                underlay_ip: vec![83, 1, 1, 1],
                listen_port: 20_002,
            },
        )
    }

    fn relay_binding_with_endpoint(
        scope: &NativeProbePathScope,
        endpoint: WireguardEndpoint,
    ) -> NativeProbeEndpointBinding {
        binding_with_material(
            scope,
            [0xd1; NODE_ID_BYTES],
            [0xd3; NODE_ID_BYTES],
            endpoint,
        )
    }

    fn relay_client_binding(scope: &NativeProbePathScope) -> NativeProbeEndpointBinding {
        binding_with_material(
            scope,
            [0xd1; NODE_ID_BYTES],
            [0xd4; NODE_ID_BYTES],
            WireguardEndpoint {
                public_key: vec![0xd5; NODE_ID_BYTES],
                underlay_ip: vec![83, 1, 1, 2],
                listen_port: 20_003,
            },
        )
    }

    fn client_binding(scope: &NativeProbePathScope) -> NativeProbeEndpointBinding {
        binding_with_material(
            scope,
            [0xc1; NODE_ID_BYTES],
            [0xc2; NODE_ID_BYTES],
            WireguardEndpoint {
                public_key: vec![0xc3; NODE_ID_BYTES],
                underlay_ip: vec![82, 1, 1, 1],
                listen_port: 20_004,
            },
        )
    }

    fn binding_with_material(
        scope: &NativeProbePathScope,
        runtime: [u8; NODE_ID_BYTES],
        lease_handle: [u8; NODE_ID_BYTES],
        endpoint: WireguardEndpoint,
    ) -> NativeProbeEndpointBinding {
        let route_context_id: [u8; ID_BYTES] =
            scope.probe_id.as_slice().try_into().expect("probe ID");
        let commitment = native_probe_prepared_lease_commitment(
            &runtime,
            &route_context_id,
            &lease_handle,
            &endpoint,
        )
        .expect("Relay commitment");
        NativeProbeEndpointBinding {
            helper_runtime_id: runtime.to_vec(),
            route_context_id: route_context_id.to_vec(),
            endpoint: Some(endpoint),
            prepared_lease_commitment: commitment.to_vec(),
        }
    }

    fn observation(ready: &IssuedNativeProbeExitReady) -> NativeProbeExitObservation {
        NativeProbeExitObservation {
            helper_runtime_id: ready
                .prepared_exit
                .binding
                .helper_runtime_id
                .as_slice()
                .try_into()
                .expect("runtime"),
            route_context_id: ready
                .prepared_exit
                .binding
                .route_context_id
                .as_slice()
                .try_into()
                .expect("context"),
            prepared_lease_commitment: ready
                .prepared_exit
                .binding
                .prepared_lease_commitment
                .as_slice()
                .try_into()
                .expect("commitment"),
            challenge_response: Zeroizing::new(CHALLENGE),
            observed_network_prefix: ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv4 as i32,
                network_prefix: vec![82, 1, 1],
            },
            latest_handshake_unix: NOW_MS / 1_000,
            received_bytes_after_baseline: 64,
            transmitted_bytes_after_baseline: 64,
        }
    }

    #[test]
    fn exact_affine_exit_phases_produce_a_verifiable_chain() {
        let mut fixture = Fixture::new();
        let permit = fixture.issue_permit();
        let signed_request = permit.signed_request().to_vec();
        let signed_permit = permit.signed_permit().to_vec();
        let relay_node_id = fixture.relay_node_id();
        let relay_peer_id = fixture.relay_peer_id();
        let relay_exit = relay_exit_binding(&fixture.scope);
        let relay_exit_for_chain = relay_exit.clone();
        let public_key = fixture.exit_public_key();
        let exit_key = &fixture.exit_key;
        let ready = fixture
            .service
            .issue_native_probe_ready_with(
                permit,
                &relay_node_id,
                &relay_peer_id,
                relay_exit,
                prepared_exit_lease(PROBE_ID),
                NOW_MS + 2,
                public_key,
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .expect("ready");
        let signed_ready = ready.signed_ready().to_vec();
        let observation = observation(&ready);
        let exit_key = &fixture.exit_key;
        let result = fixture
            .service
            .issue_native_probe_result_with(
                ready,
                observation,
                &relay_node_id,
                &relay_peer_id,
                NOW_MS + 3,
                public_key,
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .expect("result");

        let mut relay_replay = ReplayCache::new(16).expect("Relay replay");
        let relay_permit = verify_native_probe_permit(
            signed_request.clone(),
            signed_permit.clone(),
            NOW_MS + 3,
            &mut relay_replay,
        )
        .expect("Relay verifies permit");
        let exit_ready = verify_native_probe_exit_ready(
            relay_permit,
            signed_ready,
            NOW_MS + 3,
            &mut relay_replay,
        )
        .expect("Relay verifies hidden Exit readiness");
        let relay_ready = sign_native_probe_relay_ready(
            exit_ready,
            relay_client_binding(&fixture.scope),
            relay_exit_for_chain,
            &fixture.relay_key,
            NOW_MS + 3,
            [21; NONCE_BYTES],
        )
        .expect("Relay readiness");
        let signed_relay_ready = relay_ready.encoded_relay_ready().to_vec();

        let mut client_replay = ReplayCache::new(16).expect("client replay");
        let client_permit = verify_native_probe_permit(
            signed_request,
            signed_permit,
            NOW_MS + 3,
            &mut client_replay,
        )
        .expect("client verifies permit");
        let client_ready = verify_native_probe_relay_ready(
            client_permit,
            signed_relay_ready,
            NOW_MS + 3,
            &mut client_replay,
        )
        .expect("client verifies Relay readiness");
        let start = sign_native_probe_start(
            client_ready,
            client_binding(&fixture.scope),
            &fixture.client_key,
            NOW_MS + 4,
            [22; NONCE_BYTES],
        )
        .expect("client start");
        let start = verify_native_probe_start_for_relay(
            relay_ready,
            start.encoded_start().to_vec(),
            NOW_MS + 4,
            &mut relay_replay,
        )
        .expect("Relay verifies four-endpoint start topology");
        let _verified_result = verify_native_probe_exit_result_for_relay(
            start,
            result.signed_result().to_vec(),
            NOW_MS + 4,
            &mut relay_replay,
        )
        .expect("Relay verifies result against the hidden Exit lease");
    }

    #[test]
    fn disabled_exit_rejects_before_verification_or_signing() {
        let fixture = Fixture::new();
        let policy = verified_development_manifest(NOW_MS, Vec::new()).expect("policy");
        let mut disabled = ExitService::new_with_boot_id(
            ExitServiceConfig::disabled(node_id_from_public_key(&fixture.exit_public_key())),
            policy,
            None,
            [0xb1; ID_BYTES],
        )
        .expect("disabled service");
        assert!(matches!(
            disabled.issue_native_probe_permit_with(
                fixture.signed_request.clone(),
                &fixture.control_node_id(),
                &fixture.control_peer_id(),
                NOW_MS + 1,
                fixture.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("disabled role must reject before signing")
                },
            ),
            Err(ExitError::Disabled)
        ));
        assert!(disabled.native_probe_request_replay.is_empty());
    }

    #[test]
    fn exact_control_lineage_failure_rolls_back_for_an_unmodified_retry() {
        let mut fixture = Fixture::new();
        let public_key = fixture.exit_public_key();
        assert!(matches!(
            fixture.service.issue_native_probe_permit_with(
                fixture.signed_request.clone(),
                &[0xf1; NODE_ID_BYTES],
                &fixture.control_peer_id(),
                NOW_MS + 1,
                public_key,
                |_message| -> Option<[u8; 64]> {
                    panic!("wrong control lineage must reject before signing")
                },
            ),
            Err(ExitError::ControlRelayMismatch)
        ));
        assert!(fixture.service.native_probe_request_replay.is_empty());

        assert!(matches!(
            fixture.service.issue_native_probe_permit_with(
                fixture.signed_request.clone(),
                &fixture.control_node_id(),
                &[0xf2; 38],
                NOW_MS + 1,
                public_key,
                |_message| -> Option<[u8; 64]> {
                    panic!("wrong control Peer ID must reject before signing")
                },
            ),
            Err(ExitError::ControlRelayMismatch)
        ));
        assert!(fixture.service.native_probe_request_replay.is_empty());
        assert!(fixture.issue_permit().signed_permit().len() > NONCE_BYTES);
    }

    #[test]
    fn signing_failure_rolls_back_for_an_unmodified_retry() {
        let mut fixture = Fixture::new();
        let control_node_id = fixture.control_node_id();
        let control_peer_id = fixture.control_peer_id();
        let public_key = fixture.exit_public_key();
        assert!(matches!(
            fixture.service.issue_native_probe_permit_with(
                fixture.signed_request.clone(),
                &control_node_id,
                &control_peer_id,
                NOW_MS + 1,
                public_key,
                |_message| None,
            ),
            Err(ExitError::Protocol(ProtocolError::SigningFailed))
        ));
        assert!(fixture.service.native_probe_request_replay.is_empty());
        assert!(fixture.issue_permit().signed_permit().len() > NONCE_BYTES);
    }

    #[test]
    fn full_window_is_skew_safe_and_every_local_phase_caps_its_own_lifetime() {
        let mut fixture = Fixture::new();
        let permit_now = NOW_MS - 1;
        let permit = fixture
            .issue_permit_at(permit_now)
            .expect("full-window request with Exit clock behind");
        assert_eq!(
            permit.expires_at_ms,
            permit_now + MAX_NATIVE_PROBE_LIFETIME_MS
        );
        let signed_request = permit.signed_request().to_vec();
        let signed_permit = permit.signed_permit().to_vec();
        let mut permit_replay = ReplayCache::new(8).expect("permit replay");
        verify_native_probe_permit(signed_request, signed_permit, NOW_MS, &mut permit_replay)
            .expect("capped full-window permit verifies");

        let ready_now = NOW_MS - 2;
        let relay_node_id = fixture.relay_node_id();
        let relay_peer_id = fixture.relay_peer_id();
        let exit_public_key = fixture.exit_public_key();
        let exit_key = &fixture.exit_key;
        let ready = fixture
            .service
            .issue_native_probe_ready_with(
                permit,
                &relay_node_id,
                &relay_peer_id,
                relay_exit_binding(&fixture.scope),
                prepared_exit_lease(PROBE_ID),
                ready_now,
                exit_public_key,
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .expect("backward-skewed readiness");
        assert_eq!(
            ready.expires_at_ms,
            ready_now + MAX_NATIVE_PROBE_LIFETIME_MS
        );
        let signed_ready = ready.signed_ready().to_vec();
        let mut ready_replay = ReplayCache::new(8).expect("ready replay");
        let verified_ready = verify_control_message::<NativeProbeExitReady>(
            &signed_ready,
            NOW_MS,
            native_time_policy(),
            &mut ready_replay,
        )
        .expect("capped readiness verifies");
        assert_eq!(
            verified_ready.message().expires_at_ms,
            ready_now + MAX_NATIVE_PROBE_LIFETIME_MS
        );

        let result_now = NOW_MS - 3;
        let mut observed = observation(&ready);
        observed.latest_handshake_unix = result_now / 1_000;
        let exit_key = &fixture.exit_key;
        let result = fixture
            .service
            .issue_native_probe_result_with(
                ready,
                observed,
                &relay_node_id,
                &relay_peer_id,
                result_now,
                exit_public_key,
                |message| Some(exit_key.sign(message).to_bytes()),
            )
            .expect("backward-skewed result");
        let mut result_replay = ReplayCache::new(8).expect("result replay");
        let verified_result = verify_control_message::<NativeProbeExitResult>(
            result.signed_result(),
            NOW_MS,
            native_time_policy(),
            &mut result_replay,
        )
        .expect("capped result verifies");
        assert_eq!(
            verified_result.message().expires_at_ms,
            result_now + MAX_NATIVE_PROBE_LIFETIME_MS
        );
    }

    #[test]
    fn service_restart_invalidates_permit_and_ready_before_signing() {
        let mut permit_fixture = Fixture::new();
        let permit = permit_fixture.issue_permit();
        let relay_node_id = permit_fixture.relay_node_id();
        let relay_peer_id = permit_fixture.relay_peer_id();
        let exit_public_key = permit_fixture.exit_public_key();
        permit_fixture.restart_service([0xb1; ID_BYTES]);
        assert!(matches!(
            permit_fixture.service.issue_native_probe_ready_with(
                permit,
                &relay_node_id,
                &relay_peer_id,
                relay_exit_binding(&permit_fixture.scope),
                prepared_exit_lease(PROBE_ID),
                NOW_MS + 2,
                exit_public_key,
                |_message| -> Option<[u8; 64]> {
                    panic!("cross-boot permit must reject before signing")
                },
            ),
            Err(ExitError::ExitBootMismatch)
        ));

        let mut ready_fixture = Fixture::new();
        let ready = ready_fixture.issue_ready();
        let observed = observation(&ready);
        let relay_node_id = ready_fixture.relay_node_id();
        let relay_peer_id = ready_fixture.relay_peer_id();
        let exit_public_key = ready_fixture.exit_public_key();
        ready_fixture.restart_service([0xb2; ID_BYTES]);
        assert!(matches!(
            ready_fixture.service.issue_native_probe_result_with(
                ready,
                observed,
                &relay_node_id,
                &relay_peer_id,
                NOW_MS + 3,
                exit_public_key,
                |_message| -> Option<[u8; 64]> {
                    panic!("cross-boot readiness must reject before signing")
                },
            ),
            Err(ExitError::ExitBootMismatch)
        ));
    }

    #[test]
    fn ready_and_result_signer_failures_are_terminal() {
        let mut ready_fixture = Fixture::new();
        let permit = ready_fixture.issue_permit();
        assert!(matches!(
            ready_fixture.service.issue_native_probe_ready_with(
                permit,
                &ready_fixture.relay_node_id(),
                &ready_fixture.relay_peer_id(),
                relay_exit_binding(&ready_fixture.scope),
                prepared_exit_lease(PROBE_ID),
                NOW_MS + 2,
                ready_fixture.exit_public_key(),
                |_message| None,
            ),
            Err(ExitError::Protocol(ProtocolError::SigningFailed))
        ));

        let mut result_fixture = Fixture::new();
        let ready = result_fixture.issue_ready();
        let observed = observation(&ready);
        assert!(matches!(
            result_fixture.service.issue_native_probe_result_with(
                ready,
                observed,
                &result_fixture.relay_node_id(),
                &result_fixture.relay_peer_id(),
                NOW_MS + 3,
                result_fixture.exit_public_key(),
                |_message| None,
            ),
            Err(ExitError::Protocol(ProtocolError::SigningFailed))
        ));
    }

    #[test]
    fn accepted_request_is_replay_protected_before_signing() {
        let mut fixture = Fixture::new();
        let _permit = fixture.issue_permit();
        assert_eq!(fixture.service.native_probe_request_replay.len(), 1);
        assert!(matches!(
            fixture.service.issue_native_probe_permit_with(
                fixture.signed_request.clone(),
                &fixture.control_node_id(),
                &fixture.control_peer_id(),
                NOW_MS + 2,
                fixture.exit_public_key(),
                |_message| -> Option<[u8; 64]> { panic!("replay must reject before signing") },
            ),
            Err(ExitError::Protocol(ProtocolError::Replay))
        ));
        assert_eq!(fixture.service.native_probe_request_replay.len(), 1);
    }

    #[test]
    fn stale_or_peer_substituted_request_never_reaches_the_signer() {
        let mut expired = Fixture::new();
        assert!(matches!(
            expired.service.issue_native_probe_permit_with(
                expired.signed_request.clone(),
                &expired.control_node_id(),
                &expired.control_peer_id(),
                ATTEMPT_EXPIRY_MS,
                expired.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("expired request must reject before signing")
                },
            ),
            Err(ExitError::Protocol(ProtocolError::Expired))
        ));
        assert!(expired.service.native_probe_request_replay.is_empty());

        let mut substituted = Fixture::new();
        let client_key = SigningKey::from_bytes(&[1; NODE_ID_BYTES]);
        substituted.scope.exit.as_mut().expect("Exit actor").peer_id = vec![0xaa; 38];
        let request = NativeProbePermitRequest {
            scope: Some(substituted.scope.clone()),
            created_at_ms: NOW_MS,
            expires_at_ms: ATTEMPT_EXPIRY_MS,
            nonce: vec![11; NONCE_BYTES],
        };
        substituted.signed_request = sign_control_message(
            &request,
            &client_key,
            NOW_MS,
            ATTEMPT_EXPIRY_MS,
            [11; NONCE_BYTES],
            native_time_policy(),
        )
        .expect("request whose opaque Peer ID is structurally valid");
        assert!(matches!(
            substituted.service.issue_native_probe_permit_with(
                substituted.signed_request.clone(),
                &substituted.control_node_id(),
                &substituted.control_peer_id(),
                NOW_MS + 1,
                substituted.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("Peer-ID substitution must reject before signing")
                },
            ),
            Err(ExitError::InvalidGrant("native probe Exit actor"))
        ));
        assert!(substituted.service.native_probe_request_replay.is_empty());
    }

    #[test]
    fn exact_policy_drift_rolls_back_before_signing() {
        let mut fixture = Fixture::new();
        let drifted_policy = verified_development_manifest(NOW_MS, Vec::new()).expect("policy");
        fixture.service = ExitService::new_with_boot_id(
            ExitServiceConfig::enabled(
                node_id_from_public_key(&fixture.exit_public_key()),
                Bandwidth::new(100, 100).expect("bandwidth"),
                8,
                900,
                30,
                64,
            ),
            drifted_policy,
            None,
            [0xb2; ID_BYTES],
        )
        .expect("drifted service");
        assert!(matches!(
            fixture.service.issue_native_probe_permit_with(
                fixture.signed_request.clone(),
                &fixture.control_node_id(),
                &fixture.control_peer_id(),
                NOW_MS + 1,
                fixture.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("policy drift must reject before signing")
                },
            ),
            Err(ExitError::InvalidGrant("native probe policy scope"))
        ));
        assert!(fixture.service.native_probe_request_replay.is_empty());
    }

    #[test]
    fn readiness_rejects_relay_context_expiry_and_socket_substitution() {
        let mut wrong_relay = Fixture::new();
        let permit = wrong_relay.issue_permit();
        let public_key = wrong_relay.exit_public_key();
        assert!(matches!(
            wrong_relay.service.issue_native_probe_ready_with(
                permit,
                &[0xf2; NODE_ID_BYTES],
                &wrong_relay.relay_peer_id(),
                relay_exit_binding(&wrong_relay.scope),
                prepared_exit_lease(PROBE_ID),
                NOW_MS + 2,
                public_key,
                |_message| -> Option<[u8; 64]> {
                    panic!("wrong data Relay must reject before signing")
                },
            ),
            Err(ExitError::InvalidGrant("native probe data Relay"))
        ));

        let mut wrong_relay_peer = Fixture::new();
        let permit = wrong_relay_peer.issue_permit();
        assert!(matches!(
            wrong_relay_peer.service.issue_native_probe_ready_with(
                permit,
                &wrong_relay_peer.relay_node_id(),
                &[0xf3; 38],
                relay_exit_binding(&wrong_relay_peer.scope),
                prepared_exit_lease(PROBE_ID),
                NOW_MS + 2,
                wrong_relay_peer.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("wrong data-Relay Peer ID must reject before signing")
                },
            ),
            Err(ExitError::InvalidGrant("native probe data Relay"))
        ));

        let mut wrong_context = Fixture::new();
        let permit = wrong_context.issue_permit();
        assert!(matches!(
            wrong_context.service.issue_native_probe_ready_with(
                permit,
                &wrong_context.relay_node_id(),
                &wrong_context.relay_peer_id(),
                relay_exit_binding(&wrong_context.scope),
                prepared_exit_lease([9; ID_BYTES]),
                NOW_MS + 2,
                wrong_context.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("wrong helper context must reject before signing")
                },
            ),
            Err(ExitError::InvalidGrant("native probe prepared Exit lease"))
        ));

        let mut expired = Fixture::new();
        let permit = expired.issue_permit();
        assert!(matches!(
            expired.service.issue_native_probe_ready_with(
                permit,
                &expired.relay_node_id(),
                &expired.relay_peer_id(),
                relay_exit_binding(&expired.scope),
                prepared_exit_lease(PROBE_ID),
                ATTEMPT_EXPIRY_MS,
                expired.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("expired owner must reject before signing")
                },
            ),
            Err(ExitError::InvalidGrant("native probe policy scope"))
        ));

        let mut collision = Fixture::new();
        let permit = collision.issue_permit();
        let local = prepared_exit_lease(PROBE_ID);
        let local_endpoint = local.binding.endpoint.clone().expect("local endpoint");
        let colliding_relay = relay_binding_with_endpoint(
            &collision.scope,
            WireguardEndpoint {
                public_key: vec![0xd4; NODE_ID_BYTES],
                ..local_endpoint
            },
        );
        assert!(matches!(
            collision.service.issue_native_probe_ready_with(
                permit,
                &collision.relay_node_id(),
                &collision.relay_peer_id(),
                colliding_relay,
                local,
                NOW_MS + 2,
                collision.exit_public_key(),
                |_message| -> Option<[u8; 64]> {
                    panic!("socket collision must reject before signing")
                },
            ),
            Err(ExitError::Protocol(ProtocolError::InvalidField(
                "native exit ready endpoints"
            )))
        ));
    }

    #[test]
    fn result_rejects_helper_commitment_and_challenge_substitution() {
        for mutation in 0_u8..4 {
            let mut fixture = Fixture::new();
            let ready = fixture.issue_ready();
            let mut observation = observation(&ready);
            match mutation {
                0 => observation.helper_runtime_id[0] ^= 1,
                1 => observation.route_context_id[0] ^= 1,
                2 => observation.prepared_lease_commitment[0] ^= 1,
                3 => observation.challenge_response[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(matches!(
                fixture.service.issue_native_probe_result_with(
                    ready,
                    observation,
                    &fixture.relay_node_id(),
                    &fixture.relay_peer_id(),
                    NOW_MS + 3,
                    fixture.exit_public_key(),
                    |_message| -> Option<[u8; 64]> {
                        panic!("substituted observation must reject before signing")
                    },
                ),
                Err(ExitError::InvalidGrant(
                    "native probe helper/datapath observation"
                ))
            ));
        }
    }

    #[test]
    fn result_rejects_invalid_observation_evidence_before_signing() {
        for mutation in 0_u8..5 {
            let mut fixture = Fixture::new();
            let ready = fixture.issue_ready();
            let mut observed = observation(&ready);
            match mutation {
                0 => observed.observed_network_prefix.network_prefix = vec![10, 0, 0],
                1 => {
                    observed.observed_network_prefix.address_family =
                        ObservationAddressFamily::Ipv6 as i32;
                }
                2 => observed.latest_handshake_unix = 0,
                3 => observed.received_bytes_after_baseline = 0,
                4 => observed.transmitted_bytes_after_baseline = 0,
                _ => unreachable!(),
            }
            assert!(matches!(
                fixture.service.issue_native_probe_result_with(
                    ready,
                    observed,
                    &fixture.relay_node_id(),
                    &fixture.relay_peer_id(),
                    NOW_MS + 3,
                    fixture.exit_public_key(),
                    |_message| -> Option<[u8; 64]> {
                        panic!("invalid observation must reject before signing")
                    },
                ),
                Err(ExitError::Protocol(_))
            ));
        }
    }

    #[test]
    fn result_rejects_data_relay_node_and_peer_substitution_before_signing() {
        for wrong_peer in [false, true] {
            let mut fixture = Fixture::new();
            let ready = fixture.issue_ready();
            let observed = observation(&ready);
            let relay_node_id = if wrong_peer {
                fixture.relay_node_id()
            } else {
                [0xf5; NODE_ID_BYTES]
            };
            let relay_peer_id = if wrong_peer {
                vec![0xf6; 38]
            } else {
                fixture.relay_peer_id()
            };
            assert!(matches!(
                fixture.service.issue_native_probe_result_with(
                    ready,
                    observed,
                    &relay_node_id,
                    &relay_peer_id,
                    NOW_MS + 3,
                    fixture.exit_public_key(),
                    |_message| -> Option<[u8; 64]> {
                        panic!("wrong data Relay must reject before signing")
                    },
                ),
                Err(ExitError::InvalidGrant("native probe data Relay"))
            ));
        }
    }

    #[test]
    fn private_inputs_have_no_exported_constructor_or_clone_escape() {
        let source = include_str!("native_preselection.rs");
        assert!(source.contains("fn from_typed_exit_lease_projection("));
        let crate_visibility = ["pub", "(crate)"].concat();
        assert!(!source.contains(&crate_visibility));
        let observation_impl = ["impl ", "NativeProbeExitObservation"].concat();
        assert!(!source.contains(&observation_impl));
        for owner in [
            "IssuedNativeProbePermit",
            "PreparedNativeProbeExitProjection",
            "IssuedNativeProbeExitReady",
            "NativeProbeExitObservation",
            "IssuedNativeProbeExitResult",
        ] {
            for trait_name in ["Clone", "Copy"] {
                let explicit_impl = format!("impl {trait_name} for {owner}");
                assert!(!source.contains(&explicit_impl));
            }
            let declaration = format!("struct {owner} {{");
            let declaration_at = source.find(&declaration).expect("phase owner declaration");
            let prefix = &source[declaration_at.saturating_sub(128)..declaration_at];
            assert!(!prefix.contains("#[derive"));
        }
    }
}
