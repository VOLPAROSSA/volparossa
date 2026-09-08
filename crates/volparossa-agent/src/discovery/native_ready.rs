//! Bounded, nonblocking complete-set admission for the Exit's shared native Ready batch.

use volparossa_protocol::{UnderlayScope, WireguardEndpoint};

use super::{
    AgentState, Arc, ConnectionId, ContextRole, DirectRelayCapability, DiscoveryRuntime,
    EndpointTraversalBinding, ExitForwardOperation, ExitForwardRequest, ExitForwardResponse,
    FORWARD_ID_BYTES, Libp2pPeerId, MAX_CONCURRENT_FORWARDING_STREAMS, NativeProbePathScope,
    NativeProbeReadyForwardRequest, PrepareLeaseBatch, RwLock, TraversalEndpointHint,
    UpstreamExitForwardResponse, WireguardRole, fixed_bytes, log_relay_forward_admission,
    native_service_prepare_request, request_response, unix_millis,
};

pub(super) struct PendingExitNativeReady {
    pub(super) authenticated_data_relay: Libp2pPeerId,
    pub(super) connection_id: ConnectionId,
    pub(super) request: ExitForwardRequest,
    pub(super) forward: NativeProbeReadyForwardRequest,
    pub(super) scope: NativeProbePathScope,
    pub(super) authorized_data_relay: DirectRelayCapability,
    pub(super) data_relay_node_id: [u8; 32],
    pub(super) channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
}

impl PendingExitNativeReady {
    fn retained_bytes(&self) -> usize {
        // Request + decoded signed frame + copied scope, with bounded actor/endpoint overhead.
        self.request
            .canonical_request()
            .len()
            .saturating_mul(3)
            .saturating_add(4096)
    }
}

/// No helper owner exists while any required ordinal is absent.
pub(super) struct ExitNativeReadySet {
    plan: ExitNativeReadyPlan,
    pending: Vec<PendingExitNativeReady>,
    retained_bytes: usize,
}

impl ExitNativeReadySet {
    pub(super) fn entry_count(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(super) fn retained_bytes_for_peer(&self, peer: Libp2pPeerId) -> usize {
        self.pending
            .iter()
            .filter(|entry| entry.authenticated_data_relay == peer)
            .map(PendingExitNativeReady::retained_bytes)
            .fold(0, usize::saturating_add)
    }
}

struct ExitNativeReadyPath {
    scope: NativeProbePathScope,
    binding: EndpointTraversalBinding,
    endpoint: WireguardEndpoint,
    deadline_ms: u64,
}

#[derive(Default)]
struct ExitNativeReadyPlan {
    paths: Vec<ExitNativeReadyPath>,
}

impl ExitNativeReadyPlan {
    fn expires_at_ms(&self) -> u64 {
        self.paths
            .iter()
            .map(|path| path.deadline_ms)
            .min()
            .unwrap_or(0)
    }

    /// Insert only one exact, distinct actor per ordinal from one immutable signed attempt.
    fn insert(&mut self, path: ExitNativeReadyPath, now_ms: u64) -> Result<bool, ()> {
        let scope = &path.scope;
        let count = usize::try_from(scope.required_path_count).map_err(|_| ())?;
        if !(1..=volparossa_protocol::MAX_NATIVE_PROBE_PATHS).contains(&count)
            || !(1..=scope.required_path_count).contains(&scope.candidate_ordinal)
            || path.deadline_ms <= now_ms
            || path.deadline_ms > scope.attempt_expires_at_ms
            || path
                .endpoint
                .validate("native Ready adjacent endpoint")
                .is_err()
            || self.paths.iter().any(|existing| {
                !same_attempt(&existing.scope, scope)
                    || existing.scope.candidate_ordinal == scope.candidate_ordinal
                    || existing.binding.observer_id == path.binding.observer_id
                    || existing.binding.observer_peer_id == path.binding.observer_peer_id
                    || existing.scope.probe_id == scope.probe_id
                    || existing.deadline_ms <= now_ms
            })
        {
            return Err(());
        }
        self.paths.push(path);
        self.paths
            .sort_unstable_by_key(|path| path.scope.candidate_ordinal);
        Ok(self.paths.len() == count)
    }

    fn prepare(&self, hints: Vec<TraversalEndpointHint>, now_ms: u64) -> Option<PrepareLeaseBatch> {
        let first = self.paths.first()?;
        if self.paths.len() != usize::try_from(first.scope.required_path_count).ok()?
            || self.expires_at_ms() <= now_ms
            || self
                .paths
                .iter()
                .enumerate()
                .any(|(index, path)| usize::try_from(path.scope.candidate_ordinal) != Ok(index + 1))
        {
            return None;
        }
        let mut prepare = native_service_prepare_request(
            &first.scope,
            ContextRole::Exit,
            &[WireguardRole::Exit],
            now_ms,
        )?;
        prepare.traversal_hints = bind_exit_traversal_hints(&self.paths, hints)?;
        Some(prepare)
    }
}

fn same_attempt(left: &NativeProbePathScope, right: &NativeProbePathScope) -> bool {
    // Client signatures and Exit Permits have already authenticated each complete scope. The
    // client deliberately mints a fresh ephemeral signing identity per path, alongside its
    // probe/challenge. Those fields remain pinned to that path, not shared across the attempt.
    let mut common = left.clone();
    common.probe_id.clone_from(&right.probe_id);
    common.candidate_ordinal = right.candidate_ordinal;
    common.data_relay.clone_from(&right.data_relay);
    common
        .client_session_id
        .clone_from(&right.client_session_id);
    common
        .client_session_public_key
        .clone_from(&right.client_session_public_key);
    common.challenge_hash.clone_from(&right.challenge_hash);
    common == *right
}

fn bind_exit_traversal_hints(
    paths: &[ExitNativeReadyPath],
    hints: Vec<TraversalEndpointHint>,
) -> Option<Vec<TraversalEndpointHint>> {
    if hints.len() > paths.len().checked_mul(2)? {
        return None;
    }
    let mut bound = Vec::<TraversalEndpointHint>::with_capacity(paths.len());
    for hint in hints {
        let path = paths
            .iter()
            .find(|path| path.binding.path_id == hint.path_id)?;
        if hint.role != WireguardRole::Exit as i32
            || hint.observer_id != path.binding.observer_id
            || hint.observer_peer_id != path.binding.observer_peer_id.to_bytes()
        {
            return None;
        }
        let matches = match UnderlayScope::try_from(path.endpoint.underlay_scope).ok()? {
            UnderlayScope::DirectLocalLan => hint.on_link.as_ref().is_some_and(|link| {
                hint.observed_address.is_empty()
                    && link.peer_address == path.endpoint.underlay_ip
                    && link.local_address.len() == path.endpoint.underlay_ip.len()
            }),
            UnderlayScope::PublicInternet => {
                hint.on_link.is_none()
                    && hint.observed_address.len() == path.endpoint.underlay_ip.len()
            }
        };
        if matches {
            if bound
                .iter()
                .any(|existing| existing.path_id == hint.path_id)
            {
                return None;
            }
            bound.push(hint);
        }
    }
    if paths.iter().any(|path| {
        path.endpoint.underlay_scope == UnderlayScope::DirectLocalLan as i32
            && !bound
                .iter()
                .any(|hint| hint.path_id == path.binding.path_id)
    }) {
        return None;
    }
    bound.sort_unstable_by_key(|hint| hint.path_id);
    Some(bound)
}

impl DiscoveryRuntime {
    pub(super) async fn collect_exit_native_ready(
        &mut self,
        pending: PendingExitNativeReady,
        state: &Arc<RwLock<AgentState>>,
    ) {
        let now_ms = unix_millis();
        self.expire_pending_exit_native_ready(now_ms);
        let Some(attempt_id) = fixed_bytes::<FORWARD_ID_BYTES>(&pending.scope.attempt_id) else {
            self.reject_pending_exit_native_ready(pending);
            return;
        };
        let retained_bytes = pending.retained_bytes();
        if self.exit_native_ready_attempts.contains_key(&attempt_id)
            || (!self.pending_exit_native_ready.contains_key(&attempt_id)
                && self
                    .pending_exit_native_ready
                    .len()
                    .saturating_add(self.exit_native_ready_attempts.len())
                    >= MAX_CONCURRENT_FORWARDING_STREAMS)
            || !self.ledger_can_reserve(pending.authenticated_data_relay, retained_bytes)
        {
            self.reject_pending_exit_native_ready(pending);
            return;
        }
        let Some(endpoint) = pending
            .forward
            .relay_exit_endpoint()
            .and_then(|binding| binding.endpoint.clone())
        else {
            self.reject_pending_exit_native_ready(pending);
            return;
        };
        let path = ExitNativeReadyPath {
            scope: pending.scope.clone(),
            binding: EndpointTraversalBinding {
                path_id: pending.scope.candidate_ordinal,
                role: WireguardRole::Exit,
                observer_id: pending.data_relay_node_id,
                observer_peer_id: pending.authenticated_data_relay,
            },
            endpoint,
            deadline_ms: pending
                .request
                .deadline_unix_ms()
                .min(pending.scope.attempt_expires_at_ms),
        };
        let set = self
            .pending_exit_native_ready
            .entry(attempt_id)
            .or_insert_with(|| ExitNativeReadySet {
                plan: ExitNativeReadyPlan::default(),
                pending: Vec::new(),
                retained_bytes: 0,
            });
        let Ok(complete) = set.plan.insert(path, now_ms) else {
            log_relay_forward_admission(Some(state), "NATIVE_PROBE_READY_EXIT_SET_SCOPE_REJECTED");
            let set = self.pending_exit_native_ready.remove(&attempt_id);
            self.reject_pending_exit_native_ready(pending);
            if let Some(set) = set {
                self.reject_exit_native_ready_set(set);
            }
            return;
        };
        set.retained_bytes = set.retained_bytes.saturating_add(retained_bytes);
        set.pending.push(pending);
        if !complete {
            return;
        }
        let Some(set) = self.pending_exit_native_ready.remove(&attempt_id) else {
            return;
        };
        self.prepare_complete_exit_native_ready(attempt_id, set, state)
            .await;
    }

    async fn prepare_complete_exit_native_ready(
        &mut self,
        attempt_id: [u8; FORWARD_ID_BYTES],
        mut set: ExitNativeReadySet,
        state: &Arc<RwLock<AgentState>>,
    ) {
        // Re-read every authenticated observation only once the complete signed set exists.
        let hints = self
            .exact_endpoint_traversal_hints(
                set.plan
                    .paths
                    .iter()
                    .map(|path| path.binding.clone())
                    .collect(),
            )
            .unwrap_or_default();
        let Some(prepare) = set.plan.prepare(hints, unix_millis()) else {
            log_relay_forward_admission(
                Some(state),
                "NATIVE_PROBE_READY_EXIT_SET_TRAVERSAL_REJECTED",
            );
            self.reject_exit_native_ready_set(set);
            return;
        };
        if set.pending.iter().any(|entry| {
            self.service
                .bind_native_probe_data_relay_connection(
                    entry.authenticated_data_relay,
                    entry.connection_id,
                )
                .is_err()
        }) {
            self.reject_exit_native_ready_set(set);
            return;
        }
        set.pending
            .sort_unstable_by_key(|entry| entry.scope.candidate_ordinal);
        let mut pending = set.pending.into_iter();
        while let Some(entry) = pending.next() {
            let ordinal = entry.scope.candidate_ordinal;
            if entry.request.deadline_unix_ms() <= unix_millis() {
                self.reject_pending_exit_native_ready(entry);
            } else {
                self.finish_exit_native_ready(entry, prepare.clone(), state)
                    .await;
                if self
                    .exit_native_ready_attempts
                    .get(&attempt_id)
                    .is_some_and(|attempt| attempt.ready_paths.contains(&ordinal))
                {
                    continue;
                }
            }
            for remaining in pending {
                self.reject_pending_exit_native_ready(remaining);
            }
            if let Some(attempt) = self.exit_native_ready_attempts.remove(&attempt_id) {
                self.destroy_helper_owner(attempt.helper_owner);
            }
            return;
        }
    }

    pub(super) fn expire_pending_exit_native_ready(&mut self, now_ms: u64) {
        let expired = self
            .pending_exit_native_ready
            .iter()
            .filter_map(|(id, set)| (set.plan.expires_at_ms() <= now_ms).then_some(*id))
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(set) = self.pending_exit_native_ready.remove(&id) {
                self.reject_exit_native_ready_set(set);
            }
        }
    }

    fn reject_exit_native_ready_set(&mut self, set: ExitNativeReadySet) {
        for entry in set.pending {
            self.reject_pending_exit_native_ready(entry);
        }
    }

    fn reject_pending_exit_native_ready(&mut self, pending: PendingExitNativeReady) {
        if let Ok(response) = ExitForwardResponse::unavailable(
            pending.request.forward_id().to_vec(),
            ExitForwardOperation::NativeProbeReady,
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
        ) {
            let _ = self
                .service
                .send_exit_forward_upstream_response(pending.channel, response.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use volparossa_protocol::{
        NativeProbePermit, NativeProbePermitRequest, ObservationAddressFamily, ReplayCache,
        TimePolicy, native_probe_permit_request_hash, node_id_from_public_key,
        sign_control_message, verify_native_probe_permit,
    };

    use super::super::{PreselectionActorBinding, Transport};
    use super::*;

    const NOW: u64 = 100_000;

    fn actor(seed: u8) -> PreselectionActorBinding {
        let public_key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let ed25519 = libp2p::identity::ed25519::PublicKey::try_from_bytes(&public_key).unwrap();
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: libp2p::identity::PublicKey::from(ed25519)
                .to_peer_id()
                .to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: 1,
            advertisement_expires_at_ms: NOW + 30_000,
            advertisement_payload_hash: vec![seed; 32],
            capability_expires_at_ms: NOW + 30_000,
        }
    }

    fn path(ordinal: u8, local: bool) -> ExitNativeReadyPath {
        let relay = actor(ordinal);
        let node_id = relay.node_id.clone().try_into().unwrap();
        let peer_id = Libp2pPeerId::from_bytes(&relay.peer_id).unwrap();
        // Production mint_path_authorities creates a different ephemeral key for every path.
        let session_key = SigningKey::from_bytes(&[ordinal + 10; 32]);
        let session_public_key = session_key.verifying_key().to_bytes();
        let scope = NativeProbePathScope {
            attempt_id: vec![1; 16],
            probe_id: vec![ordinal; 16],
            candidate_set_hash: vec![2; 32],
            candidate_ordinal: u32::from(ordinal),
            required_path_count: 2,
            attempt_expires_at_ms: NOW + 20_000,
            transport: Transport::MultipathQuic as i32,
            data_relay: Some(relay),
            control: Some(actor(3)),
            exit: Some(actor(4)),
            client_session_id: node_id_from_public_key(&session_public_key).to_vec(),
            client_session_public_key: session_public_key.to_vec(),
            address_family: ObservationAddressFamily::Ipv4 as i32,
            policy_version: 1,
            policy_hash: vec![5; 32],
            policy_expires_at_ms: NOW + 30_000,
            challenge_hash: vec![ordinal; 32],
            reserved_up_mbps: 8,
            reserved_down_mbps: 12,
        };
        let scope = verified_scope(scope, &session_key, ordinal);
        ExitNativeReadyPath {
            scope,
            binding: EndpointTraversalBinding {
                path_id: u32::from(ordinal),
                role: WireguardRole::Exit,
                observer_id: node_id,
                observer_peer_id: peer_id,
            },
            endpoint: WireguardEndpoint {
                public_key: vec![ordinal; 32],
                underlay_ip: if local {
                    vec![192, 168, 7, 2]
                } else {
                    vec![44, 160, 1, 2]
                },
                listen_port: 41_000 + u32::from(ordinal),
                underlay_scope: if local {
                    UnderlayScope::DirectLocalLan
                } else {
                    UnderlayScope::PublicInternet
                } as i32,
            },
            deadline_ms: NOW + 5_000,
        }
    }

    fn verified_scope(
        scope: NativeProbePathScope,
        session_key: &SigningKey,
        ordinal: u8,
    ) -> NativeProbePathScope {
        let expires = scope.attempt_expires_at_ms;
        let request = NativeProbePermitRequest {
            scope: Some(scope.clone()),
            created_at_ms: NOW,
            expires_at_ms: expires,
            nonce: vec![ordinal; 32],
        };
        let signed_request = sign_control_message(
            &request,
            session_key,
            NOW,
            expires,
            [ordinal; 32],
            TimePolicy::default(),
        )
        .unwrap();
        let permit = NativeProbePermit {
            request_hash: native_probe_permit_request_hash(&signed_request)
                .unwrap()
                .to_vec(),
            scope: Some(scope),
            issued_at_ms: NOW,
            expires_at_ms: expires,
            nonce: vec![ordinal + 20; 32],
            exit_control_address: format!(
                "/ip4/46.162.3.2/udp/41000/quic-v1/p2p/{}",
                Libp2pPeerId::from_bytes(&actor(4).peer_id).unwrap(),
            ),
        };
        let signed_permit = sign_control_message(
            &permit,
            &SigningKey::from_bytes(&[4; 32]),
            NOW,
            expires,
            [ordinal + 20; 32],
            TimePolicy::default(),
        )
        .unwrap();
        verify_native_probe_permit(
            signed_request,
            signed_permit,
            NOW,
            &mut ReplayCache::new(2).unwrap(),
        )
        .expect("each path retains its independently signed exact session/Permit binding")
        .scope()
        .clone()
    }

    fn hint(path: &ExitNativeReadyPath) -> TraversalEndpointHint {
        let local = path.endpoint.underlay_scope == UnderlayScope::DirectLocalLan as i32;
        TraversalEndpointHint {
            path_id: path.binding.path_id,
            role: WireguardRole::Exit as i32,
            observer_id: path.binding.observer_id.to_vec(),
            observer_peer_id: path.binding.observer_peer_id.to_bytes(),
            observed_address: if local {
                Vec::new()
            } else {
                vec![45, 161, 2, 1]
            },
            on_link: local.then(|| volparossa_routing::OnLinkUnderlayHint {
                local_address: vec![192, 168, 7, 1],
                peer_address: path.endpoint.underlay_ip.clone(),
            }),
        }
    }

    #[test]
    fn native_ready_collector_mixed_out_of_order_requires_complete_exact_plan() {
        let public = path(1, false);
        let local = path(2, true);
        let hints = vec![hint(&local), hint(&public)];
        let mut plan = ExitNativeReadyPlan::default();
        assert_eq!(plan.insert(local, NOW), Ok(false));
        assert!(
            plan.prepare(hints.clone(), NOW).is_none(),
            "partial sets cannot prepare a helper"
        );
        assert_eq!(plan.insert(public, NOW), Ok(true));
        let prepare = plan
            .prepare(hints, NOW)
            .expect("one complete mixed-underlay batch");
        volparossa_routing::encode_request(&volparossa_routing::HelperRequest {
            protocol_version: volparossa_routing::HELPER_PROTOCOL_VERSION,
            request_id: vec![3; 16],
            operation: Some(
                volparossa_routing::helper_request::Operation::PrepareLeaseBatch(prepare.clone()),
            ),
        })
        .expect("the complete mixed plan passes real typed helper wire validation");
        assert_eq!(
            prepare
                .leases
                .iter()
                .map(|lease| lease.path_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(prepare.traversal_hints[0].path_id, 1);
        assert!(prepare.traversal_hints[0].on_link.is_none());
        assert_eq!(prepare.traversal_hints[1].path_id, 2);
        assert_eq!(
            prepare.traversal_hints[1]
                .on_link
                .as_ref()
                .unwrap()
                .peer_address,
            vec![192, 168, 7, 2]
        );
    }

    #[test]
    fn native_ready_collector_accepts_distinct_signed_path_sessions_only_with_shared_attempt() {
        let first = path(1, false);
        let second = path(2, false);
        assert_ne!(
            first.scope.client_session_id,
            second.scope.client_session_id
        );
        assert_ne!(
            first.scope.client_session_public_key,
            second.scope.client_session_public_key,
        );
        assert!(same_attempt(&first.scope, &second.scope));
        let mut changed = second.scope.clone();
        changed.attempt_id[0] ^= 1;
        assert!(!same_attempt(&first.scope, &changed));
        changed = second.scope.clone();
        changed.policy_hash[0] ^= 1;
        assert!(!same_attempt(&first.scope, &changed));
        changed = second.scope.clone();
        changed.reserved_up_mbps += 1;
        assert!(!same_attempt(&first.scope, &changed));
        changed = second.scope.clone();
        changed.control.as_mut().unwrap().advertisement_sequence += 1;
        assert!(!same_attempt(&first.scope, &changed));
        let mut plan = ExitNativeReadyPlan::default();
        assert_eq!(plan.insert(first, NOW), Ok(false));
        assert_eq!(plan.insert(second, NOW), Ok(true));
        assert_eq!(plan.prepare(Vec::new(), NOW).unwrap().leases.len(), 2);
    }

    #[test]
    fn native_ready_collector_missing_or_substituted_local_evidence_fails_closed() {
        let public = path(1, false);
        let local = path(2, true);
        let public_hint = hint(&public);
        let local_hint = hint(&local);
        let mut plan = ExitNativeReadyPlan::default();
        plan.insert(public, NOW).unwrap();
        plan.insert(local, NOW).unwrap();
        assert!(plan.prepare(vec![public_hint.clone()], NOW).is_none());
        let mut wrong = local_hint.clone();
        wrong.on_link.as_mut().unwrap().peer_address[3] = 3;
        assert!(
            plan.prepare(vec![public_hint.clone(), wrong], NOW)
                .is_none()
        );
        let mut wrong_actor = local_hint.clone();
        wrong_actor.observer_id[0] ^= 1;
        assert!(plan.prepare(vec![public_hint, wrong_actor], NOW).is_none());
        // A directly assigned public source can still be discovered by the helper. The exact
        // LAN pair cannot be omitted even when another path has a usable Internet default.
        assert!(plan.prepare(vec![local_hint], NOW).is_some());
    }

    #[test]
    fn native_ready_collector_expiry_and_conflicting_scope_never_prepare() {
        let mut first = path(1, false);
        let mut second = path(2, true);
        let hints = vec![hint(&first), hint(&second)];
        first.deadline_ms = NOW + 2_000;
        second.deadline_ms = NOW + 4_000;
        let mut plan = ExitNativeReadyPlan::default();
        plan.insert(first, NOW).unwrap();
        let mut changed = path(2, true);
        changed.scope.candidate_set_hash[0] ^= 1;
        assert_eq!(plan.insert(changed, NOW), Err(()));
        assert_eq!(plan.insert(path(1, false), NOW), Err(()));
        assert_eq!(plan.insert(second, NOW), Ok(true));
        assert_eq!(plan.expires_at_ms(), NOW + 2_000);
        assert!(plan.prepare(hints.clone(), NOW + 2_000).is_none());
        assert!(
            plan.prepare(hints, u64::MAX).is_none(),
            "shutdown expires all held plans"
        );
    }
}
