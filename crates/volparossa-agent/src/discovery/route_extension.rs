//! Fresh signed path additions reach an existing Exit only through its original control relay.

mod evidence;
pub(super) use evidence::ExtensionEvidenceBinding;

use volparossa_exit::AcceptedRouteExtension;
use volparossa_protocol::{RouteExtensionPhase, RouteExtensionRequest, RouteExtensionScope};
use volparossa_wireguard::ExitEndpointLease;

use super::{
    ConnectionId, DiscoveryRuntime, ExactNativeExitEvidenceVerifier, ExitForwardOperation,
    ExitForwardRequest, ExitForwardResponse, ExitReservationConfirmation, FORWARD_ID_BYTES,
    LeaseActivation, LeaseCommit, Libp2pPeerId, MAX_FORWARDING_FRAME_BYTES,
    MptcpSessionStartRequest, ReplayCache, TimePolicy, UpstreamExitForwardResponse, WireguardRole,
    decode_canonical, decoded_signed_payload, fixed_bytes, inner_forward_scope_matches,
    public_udp_endpoint, request_response, unix_millis, verify_control_message,
};
use crate::endpoint_leases::bind_prepared_exit_path_extension;
use std::time::Duration;
use tokio::time::Instant;

const MAX_DEFERRED_EXTENSION_BYTES: usize = 512 * 1024;
type ExtensionChannel = request_response::ResponseChannel<UpstreamExitForwardResponse>;

struct DeferredExitCommit {
    request: ExitForwardRequest,
    control_peer: Libp2pPeerId,
    replies: Vec<(ConnectionId, ExtensionChannel)>,
    deadline: Instant,
}

enum ExtensionResult {
    Ready(Vec<Vec<u8>>),
    AwaitBudget,
}

pub(super) struct PreselectionRestriction {
    pub(super) exit_node: [u8; 32],
    pub(super) exit_peer: Libp2pPeerId,
    pub(super) control_node: [u8; 32],
    pub(super) control_peer: Libp2pPeerId,
    pub(super) data_relays: Vec<([u8; 32], Libp2pPeerId)>,
}

impl PreselectionRestriction {
    pub(super) fn is_valid(&self) -> bool {
        !(self.exit_node == [0; 32]
            || self.control_node == [0; 32]
            || self.exit_node == self.control_node
            || self.exit_peer == self.control_peer
            || self.data_relays.len() != 2
            || self.data_relays[0].0 == self.data_relays[1].0
            || self.data_relays[0].1 == self.data_relays[1].1
            || self.data_relays.iter().any(|(node, peer)| {
                *node == [0; 32]
                    || *node == self.exit_node
                    || *peer == self.exit_peer
                    || *node == self.control_node
                    || *peer == self.control_peer
            }))
    }

    /// Select only from an already revalidated, ambiguity-checked Exit lineage group.
    /// The caller constructs affine subjects after this projection, never before it.
    pub(super) fn control_index(
        &self,
        candidates: &[super::ForwardedExitCandidateSnapshot],
    ) -> Option<usize> {
        candidates.iter().position(|candidate| {
            let cap = candidate.capability();
            cap.exit_node_id == self.exit_node
                && cap.exit_peer_id == self.exit_peer
                && cap.control_relay_node_id == self.control_node
                && cap.control_relay_peer_id == self.control_peer
        })
    }

    pub(super) fn retain_direct_relays(
        &self,
        candidates: &mut Vec<super::DirectRelayCandidateSnapshot>,
    ) {
        candidates.retain(|candidate| {
            let cap = candidate.capability();
            (cap.node_id == self.control_node && cap.peer_id == self.control_peer)
                || self.data_relays.contains(&(cap.node_id, cap.peer_id))
        });
    }
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "independent affine helper and wire acknowledgements survive partial setup for cleanup"
)]
pub(super) struct LiveExtension {
    scope: RouteExtensionScope,
    prepare_attempted: bool,
    lease: Option<ExitEndpointLease>,
    authorization: Option<Vec<u8>>,
    activated: bool,
    committed: bool,
    installed: bool,
    aborted: bool,
    pending: Option<DeferredExitCommit>,
}

pub(super) fn forward_scope_matches(request: &ExitForwardRequest, now: u64) -> bool {
    let Ok(mut replay) = ReplayCache::new(1) else {
        return false;
    };
    let Ok(verified) = verify_control_message::<RouteExtensionRequest>(
        request.canonical_request(),
        now,
        TimePolicy::default(),
        &mut replay,
    ) else {
        return false;
    };
    let Some(scope) = verified.message().scope.as_ref() else {
        return false;
    };
    let Ok(parent) = scope.parent() else {
        return false;
    };
    inner_forward_scope_matches(
        request,
        verified.nonce(),
        verified.expires_at_ms(),
        &parent.control_relay_node_id,
        &parent.control_relay_peer_id,
        &parent.exit_node_id,
        &parent.exit_peer_id,
    )
}

impl DiscoveryRuntime {
    /// Own the exact reply channels while a new sender queue waits for receiver credit.
    /// No helper operation remains in flight across this deferred actor boundary.
    pub(super) async fn begin_route_extension_forward(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: ExitForwardRequest,
        channel: ExtensionChannel,
    ) {
        let mut replies = vec![(connection, channel)];
        let key = extension_key(&request);
        let live_connection = self
            .service
            .bind_native_probe_control_connection(peer, connection)
            .is_ok();
        let Some((context, id)) = key.filter(|_| live_connection) else {
            self.finish_extension_forward(peer, &request, replies, None);
            return;
        };
        if let Some(pending) = self
            .active_production_mptcp_exit_routes
            .get_mut(&context)
            .and_then(|route| route.extensions.get_mut(&id))
            .and_then(|extension| extension.pending.as_mut())
        {
            if pending.control_peer == peer
                && pending.request == request
                && pending.replies.len() < super::MAX_COALESCED_WAITERS
            {
                pending.replies.append(&mut replies);
            } else {
                self.finish_extension_forward(peer, &request, replies, None);
            }
            return;
        }
        let pending = self
            .active_production_mptcp_exit_routes
            .values()
            .flat_map(|route| route.extensions.values())
            .filter_map(|extension| extension.pending.as_ref())
            .collect::<Vec<_>>();
        let pending_bytes: usize = pending
            .iter()
            .map(|pending| pending.request.canonical_request().len())
            .sum();
        let is_commit =
            decoded_signed_payload::<RouteExtensionRequest>(request.canonical_request())
                .is_some_and(|message| message.phase == RouteExtensionPhase::Commit as i32);
        if is_commit
            && (pending.len() >= super::MAX_CONCURRENT_FORWARDING_STREAMS
                || pending_bytes.saturating_add(request.canonical_request().len())
                    > MAX_DEFERRED_EXTENSION_BYTES)
        {
            self.finish_extension_forward(peer, &request, replies, None);
            return;
        }
        let now = unix_millis();
        let deadline =
            Instant::now() + Duration::from_millis(request.deadline_unix_ms().saturating_sub(now));
        let result = self.continue_route_extension(&request, peer, now).await;
        if matches!(result, Some(ExtensionResult::AwaitBudget)) {
            if let Some(extension) = self
                .active_production_mptcp_exit_routes
                .get_mut(&context)
                .and_then(|route| route.extensions.get_mut(&id))
            {
                extension.pending = Some(DeferredExitCommit {
                    request,
                    control_peer: peer,
                    replies,
                    deadline,
                });
                return;
            }
        }
        self.finish_extension_forward(peer, &request, replies, result.and_then(ready_response));
    }

    async fn continue_route_extension(
        &mut self,
        request: &ExitForwardRequest,
        peer: Libp2pPeerId,
        now: u64,
    ) -> Option<ExtensionResult> {
        if !self.exit_authority_enabled()
            || self.retired_exit_forward(request)
            || request.validate().is_err()
            || !forward_scope_matches(request, now)
            || request.control_relay_peer_id() != peer.to_bytes()
            || request.exit_node_id() != self.local_node_id
            || request.exit_peer_id() != self.service.local_peer_id().to_bytes()
        {
            return None;
        }
        self.extend_production_mptcp_route(
            request,
            fixed_bytes(request.control_relay_node_id())?,
            peer,
            now,
        )
        .await
    }

    pub(super) async fn resume_exit_extension_commits(&mut self) {
        let keys = self
            .active_production_mptcp_exit_routes
            .iter()
            .flat_map(|(context, route)| {
                route.extensions.iter().filter_map(move |(id, extension)| {
                    extension.pending.as_ref().map(|_| (*context, *id))
                })
            })
            .collect::<Vec<_>>();
        for (context, id) in keys {
            let now = unix_millis();
            let Some(mut pending) = self
                .active_production_mptcp_exit_routes
                .get_mut(&context)
                .and_then(|route| route.extensions.get_mut(&id))
                .and_then(|extension| extension.pending.take())
            else {
                continue;
            };
            pending.replies.retain(|(connection, _)| {
                self.service
                    .bind_native_probe_control_connection(pending.control_peer, *connection)
                    .is_ok()
            });
            if pending.replies.is_empty() {
                continue;
            }
            if Instant::now() >= pending.deadline || pending.request.deadline_unix_ms() <= now {
                self.finish_extension_forward(
                    pending.control_peer,
                    &pending.request,
                    pending.replies,
                    None,
                );
                continue;
            }
            let result = self
                .continue_route_extension(&pending.request, pending.control_peer, now)
                .await;
            if matches!(result, Some(ExtensionResult::AwaitBudget)) {
                if let Some(extension) = self
                    .active_production_mptcp_exit_routes
                    .get_mut(&context)
                    .and_then(|route| route.extensions.get_mut(&id))
                {
                    extension.pending = Some(pending);
                    continue;
                }
            }
            self.finish_extension_forward(
                pending.control_peer,
                &pending.request,
                pending.replies,
                result.and_then(ready_response),
            );
        }
    }

    fn finish_extension_forward(
        &mut self,
        peer: Libp2pPeerId,
        request: &ExitForwardRequest,
        replies: Vec<(ConnectionId, ExtensionChannel)>,
        response: Option<Vec<Vec<u8>>>,
    ) {
        let response = response
            .filter(|_| request.deadline_unix_ms() > unix_millis())
            .and_then(|messages| {
                ExitForwardResponse::granted(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::ExtendRoute,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                    messages,
                )
                .ok()
            })
            .or_else(|| {
                ExitForwardResponse::unavailable(
                    request.forward_id().to_vec(),
                    ExitForwardOperation::ExtendRoute,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                )
                .ok()
            });
        let Some(response) = response else {
            return;
        };
        for (connection, channel) in replies {
            if self
                .service
                .bind_native_probe_control_connection(peer, connection)
                .is_ok()
            {
                let _ = self
                    .service
                    .send_exit_forward_upstream_response(channel, response.clone().into());
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exact signed transaction preserves all phase and affine cleanup ownership"
    )]
    async fn extend_production_mptcp_route(
        &mut self,
        forwarded: &ExitForwardRequest,
        control_node: [u8; 32],
        control_peer: Libp2pPeerId,
        now: u64,
    ) -> Option<ExtensionResult> {
        // The outer dispatcher has already checked the signature, forwarding nonce, session
        // identity and exact authenticated control-relay lineage before entering this method.
        let request =
            decoded_signed_payload::<RouteExtensionRequest>(forwarded.canonical_request())?;
        let scope = request.scope.as_ref()?;
        let parent = scope.parent().ok()?;
        let context = fixed_bytes::<FORWARD_ID_BYTES>(&parent.route_context_id)?;
        let id = fixed_bytes::<FORWARD_ID_BYTES>(&scope.extension_id)?;
        let phase = RouteExtensionPhase::try_from(request.phase).ok()?;
        let active = self.active_production_mptcp_exit_routes.get(&context)?;
        let start: MptcpSessionStartRequest = decode_canonical(
            &active.canonical_start,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
        )
        .ok()?;
        if !active.runtime_started
            || active.expires_at_ms <= now
            || active.expires_at_ms != parent.expires_at_ms
            || start.signed_exit_reservation() != scope.signed_exit_reservation
        {
            return None;
        }
        let control = active.path_control.as_ref()?.clone();
        if phase != RouteExtensionPhase::Probe {
            let extension = active.extensions.get(&id)?;
            if extension.scope != *scope {
                return None;
            }
        }
        if phase == RouteExtensionPhase::Authorize {
            let extension = self
                .active_production_mptcp_exit_routes
                .get_mut(&context)?
                .extensions
                .get_mut(&id)?;
            if extension.aborted {
                return None;
            }
            if !extension.prepare_attempted {
                // Ownership is recorded before awaiting the helper. The caller can always Abort
                // this exact ID after an ambiguous response, while original-context teardown owns
                // every extension even if this control RPC is interrupted.
                extension.prepare_attempted = true;
                let setup = forwarded.deadline_unix_ms() / 1000;
                let prepared = control
                    .prepare(id, scope.path_id, setup, Vec::new())
                    .await
                    .ok()?;
                let lease =
                    bind_prepared_exit_path_extension(context, id, scope.path_id, prepared).ok()?;
                self.active_production_mptcp_exit_routes
                    .get_mut(&context)?
                    .extensions
                    .get_mut(&id)?
                    .lease = Some(lease);
            }
        }
        let endpoint = self
            .active_production_mptcp_exit_routes
            .get(&context)?
            .extensions
            .get(&id)
            .and_then(|extension| extension.lease);
        self.recent_native_exit_evidence
            .retain(|evidence| evidence.expires_at_ms > now);
        let verifier = if phase == RouteExtensionPhase::Authorize {
            ExactNativeExitEvidenceVerifier::for_extension(
                &self.recent_native_exit_evidence,
                now,
                &request,
            )?
        } else {
            ExactNativeExitEvidenceVerifier::new(&self.recent_native_exit_evidence, now)
        };
        let identity = &self.identity;
        let accepted = self
            .exit_service
            .as_mut()?
            .extend_route_with(
                forwarded.canonical_request(),
                &control_node,
                &control_peer.to_bytes(),
                unix_millis(),
                self.local_public_key,
                &verifier,
                |path| endpoint.filter(|lease| lease.path_id() == path),
                |message| identity.sign(message).ok(),
            )
            .ok()?;
        let consumed = verifier.consumed();
        self.recent_native_exit_evidence
            .retain(|evidence| !consumed.contains(&evidence.evidence_id));
        match phase {
            RouteExtensionPhase::Probe => {
                let extensions = &mut self
                    .active_production_mptcp_exit_routes
                    .get_mut(&context)?
                    .extensions;
                if extensions.len() >= 8 && !extensions.contains_key(&id) {
                    return None;
                }
                extensions.entry(id).or_insert_with(|| LiveExtension {
                    scope: scope.clone(),
                    prepare_attempted: false,
                    lease: None,
                    authorization: None,
                    activated: false,
                    committed: false,
                    installed: false,
                    aborted: false,
                    pending: None,
                });
            }
            RouteExtensionPhase::Authorize => {
                self.active_production_mptcp_exit_routes
                    .get_mut(&context)?
                    .extensions
                    .get_mut(&id)?
                    .authorization = Some(accepted.encoded().to_vec());
            }
            RouteExtensionPhase::Abort => {
                let extension = self
                    .active_production_mptcp_exit_routes
                    .get_mut(&context)?
                    .extensions
                    .get_mut(&id)?;
                if extension.prepare_attempted && !extension.aborted {
                    control.abort(id).await.ok()?;
                }
                extension.aborted = true;
                self.retire_extension_send_leg(context, scope.path_id);
            }
            RouteExtensionPhase::Commit => {
                if !self
                    .commit_live_extension(context, id, &request, &accepted)
                    .await?
                {
                    return Some(ExtensionResult::AwaitBudget);
                }
            }
        }
        Some(ExtensionResult::Ready(vec![accepted.encoded().to_vec()]))
    }

    async fn commit_live_extension(
        &mut self,
        context: [u8; 16],
        id: [u8; 16],
        request: &RouteExtensionRequest,
        accepted: &AcceptedRouteExtension,
    ) -> Option<bool> {
        let confirmed = accepted.confirmed_path()?;
        let confirmation: ExitReservationConfirmation =
            decoded_signed_payload(&request.signed_confirmation)?;
        let active = self.active_production_mptcp_exit_routes.get_mut(&context)?;
        let control = active.path_control.as_ref()?.clone();
        let extension = active.extensions.get_mut(&id)?;
        let lease = extension.lease?;
        if confirmed.path_id() != lease.path_id()
            || confirmed.reservation_id() != &active.reservation_id
            || confirmed.exit_public_key() != lease.public_endpoint().public_key()
            || extension.aborted
        {
            return None;
        }
        if !extension.activated {
            let relay_endpoint = confirmed.relay_exit_endpoint();
            control
                .activate(
                    id,
                    LeaseActivation {
                        lease_handle: lease.lease_handle().as_bytes().to_vec(),
                        path_id: lease.path_id(),
                        role: WireguardRole::Exit as i32,
                        peer_public_key: relay_endpoint.public_key().as_bytes().to_vec(),
                        peer_endpoint: Some(public_udp_endpoint(relay_endpoint)),
                        maximum_up_mbps: 0,
                        maximum_down_mbps: 0,
                        signed_relay_reservation: confirmation.relay_reservation.clone(),
                        signed_client_relay_request: Vec::new(),
                    },
                    extension.authorization.as_ref()?.clone(),
                )
                .await
                .ok()?;
            extension.activated = true;
        }
        let requires_budget =
            decoded_signed_payload::<super::RelayReservation>(&confirmation.relay_reservation)?
                .receive_budget_required;
        if !extension.committed && requires_budget {
            let target = control.downlink_budget_target(id).await.ok()?;
            if !self.register_extension_send_leg(
                context,
                lease.path_id(),
                target,
                &confirmation.relay_reservation,
            ) {
                return None;
            }
            if !self.extension_send_budget_ready(context, lease.path_id()) {
                return Some(false);
            }
        }
        let extension = self
            .active_production_mptcp_exit_routes
            .get_mut(&context)?
            .extensions
            .get_mut(&id)?;
        if !extension.committed {
            control
                .commit(
                    id,
                    LeaseCommit {
                        lease_handle: lease.lease_handle().as_bytes().to_vec(),
                        path_id: lease.path_id(),
                        role: WireguardRole::Exit as i32,
                    },
                )
                .await
                .ok()?;
            extension.committed = true;
        }
        if !extension.installed {
            control
                .install(
                    accepted.encoded().to_vec(),
                    confirmation.relay_reservation,
                    accepted.signed_capability().to_vec(),
                )
                .await
                .ok()?;
            extension.installed = true;
        }
        Some(true)
    }
}

fn extension_key(request: &ExitForwardRequest) -> Option<([u8; 16], [u8; 16])> {
    let message = decoded_signed_payload::<RouteExtensionRequest>(request.canonical_request())?;
    let scope = message.scope.as_ref()?;
    Some((
        fixed_bytes(&scope.parent().ok()?.route_context_id)?,
        fixed_bytes(&scope.extension_id)?,
    ))
}

fn ready_response(result: ExtensionResult) -> Option<Vec<Vec<u8>>> {
    match result {
        ExtensionResult::Ready(response) => Some(response),
        ExtensionResult::AwaitBudget => None,
    }
}
