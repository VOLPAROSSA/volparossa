//! Destruction-only, session-signed retirement over retained adjacent peer relationships.

#[cfg(test)]
mod tests;

use super::{
    ConnectionId, DatapathRelayOperation, DatapathRelayRequest, DatapathRelayResponse,
    DiscoveryCommand, DiscoveryControlHandle, DiscoveryRuntime, ExitForwardOperation,
    ExitForwardRequest, ExitForwardResponse, ExitReservation, ExitReservationFinalizeRequest,
    FORWARD_ID_BYTES, ForwardStatus, HashMap, Libp2pPeerId, OutboundReservationError,
    RelayReservationRequest, ReplayCache, TimePolicy, UpstreamExitForwardResponse,
    decoded_signed_payload, fixed_bytes, generate_nonce, node_id_from_public_key, oneshot,
    request_response, sign_control_message_with, signed_envelope_matches_peer, unix_millis,
};
use std::{collections::BTreeSet, time::Duration};
use volparossa_protocol::{
    ClientSessionCapability, MAX_ROUTE_RETIRE_BYTES, RetirementReceipt, RouteRetire,
    VerifiedControlMessage, route_retire_request_hash, verify_control_message,
};

type ContextId = [u8; FORWARD_ID_BYTES];
type RequestId = request_response::OutboundRequestId;
const MAX_SCOPES: usize = 1024;
const MAX_PENDING: usize = 64;

#[derive(Default)]
pub(super) struct RouteRetireBridge {
    relay: HashMap<ContextId, RelayScope>,
    exit: HashMap<ContextId, ExitScope>,
    clients: HashMap<RequestId, PendingClient>,
    upstream: HashMap<RequestId, PendingUpstream>,
}

#[derive(Clone)]
struct RelayScope {
    request: RouteRetire,
    client_peer: Libp2pPeerId,
    exit_peer: Libp2pPeerId,
    exit_node: [u8; 32],
    expires_at_ms: u64,
    retiring: bool,
    complete: bool,
}

struct ExitScope {
    request: RouteRetire,
    relays: BTreeSet<Libp2pPeerId>,
    expires_at_ms: u64,
    retiring: bool,
    complete: bool,
}

struct PendingClient {
    relay: Libp2pPeerId,
    exit: Libp2pPeerId,
    signed: Vec<u8>,
    reply: oneshot::Sender<Result<(), OutboundReservationError>>,
}

struct PendingUpstream {
    context: ContextId,
    exit: Libp2pPeerId,
    signed: Vec<u8>,
    request_id: Vec<u8>,
    channel: request_response::ResponseChannel<DatapathRelayResponse>,
}

pub(super) struct RetireCommand {
    relay: Libp2pPeerId,
    exit: Libp2pPeerId,
    signed: Vec<u8>,
    reply: oneshot::Sender<Result<(), OutboundReservationError>>,
}

impl RetireCommand {
    pub(super) fn reject(self) {
        let _ = self.reply.send(Err(OutboundReservationError::Shutdown));
    }
}

impl DiscoveryControlHandle {
    /// Retire through one exact previously selected Relay; never directly contact the Exit.
    pub(crate) async fn retire_route(
        &self,
        relay_peer_id: Libp2pPeerId,
        expected_exit_peer_id: Libp2pPeerId,
        signed_request: Vec<u8>,
    ) -> Result<(), OutboundReservationError> {
        let (reply, response) = oneshot::channel();
        self.send_rpc(DiscoveryCommand::RetireRoute(RetireCommand {
            relay: relay_peer_id,
            exit: expected_exit_peer_id,
            signed: signed_request,
            reply,
        }))
        .await?;
        Self::await_rpc(response, Duration::from_secs(10)).await
    }
}

fn checked_request(bytes: &[u8]) -> Option<VerifiedControlMessage<RouteRetire>> {
    if bytes.len() > MAX_ROUTE_RETIRE_BYTES {
        return None;
    }
    // Destruction is idempotent for the exact retained scope. A repeated fresh envelope can
    // observe pending/completed cleanup, but cannot create an owner or authorize another tuple.
    verify_control_message::<RouteRetire>(
        bytes,
        unix_millis(),
        TimePolicy::default(),
        &mut ReplayCache::new(1).ok()?,
    )
    .ok()
}

fn peer_node(peer: Libp2pPeerId) -> Option<[u8; 32]> {
    let key = libp2p::identity::PublicKey::try_decode_protobuf(peer.as_ref().digest()).ok()?;
    if key.to_peer_id() != peer {
        return None;
    }
    Some(node_id_from_public_key(
        &key.try_into_ed25519().ok()?.to_bytes(),
    ))
}

fn exit_request(grant: &ExitReservation) -> RouteRetire {
    RouteRetire {
        route_context_id: grant.route_context_id.clone(),
        reservation_id: grant.reservation_id.clone(),
        policy_hash: grant.policy_hash.clone(),
        client_session_id: grant.client_session_id.clone(),
        client_session_public_key: grant.client_session_public_key.clone(),
    }
}

fn finalize_scope(
    request: &ExitForwardRequest,
) -> Option<(ExitReservationFinalizeRequest, ClientSessionCapability)> {
    let mut replay = ReplayCache::new(2).ok()?;
    let finalize = verify_control_message::<ExitReservationFinalizeRequest>(
        request.canonical_request(),
        unix_millis(),
        TimePolicy::default(),
        &mut replay,
    )
    .ok()?;
    let capability = verify_control_message::<ClientSessionCapability>(
        &finalize.message().client_session_capability,
        unix_millis(),
        TimePolicy::default(),
        &mut replay,
    )
    .ok()?;
    let grant = capability.message();
    let message = finalize.message();
    let exit = Libp2pPeerId::from_bytes(request.exit_peer_id()).ok()?;
    if !signed_envelope_matches_peer(&message.client_session_capability, &exit)
        || message.route_context_id != grant.route_context_id
        || message.reservation_id != grant.reservation_id
        || message.client_session_id != grant.client_session_id
        || finalize.sender_public_key().as_slice() != grant.client_session_public_key
        || message.exit_node_id != grant.exit_node_id
        || message.exit_peer_id != grant.exit_peer_id
        || message.control_relay_peer_id != grant.control_relay_peer_id
        || message.control_relay_node_id != grant.control_relay_node_id
    {
        return None;
    }
    Some((message.clone(), grant.clone()))
}

fn capability_request(grant: &ClientSessionCapability) -> RouteRetire {
    RouteRetire {
        route_context_id: grant.route_context_id.clone(),
        reservation_id: grant.reservation_id.clone(),
        policy_hash: grant.policy_hash.clone(),
        client_session_id: grant.client_session_id.clone(),
        client_session_public_key: grant.client_session_public_key.clone(),
    }
}

impl DiscoveryRuntime {
    pub(super) fn retired_relay_datapath(&self, request: &DatapathRelayRequest) -> bool {
        let context = match request.validated_operation() {
            Ok(DatapathRelayOperation::ReservePath) => {
                decoded_signed_payload::<RelayReservationRequest>(request.client_signed_request())
                    .and_then(|r| decoded_signed_payload::<ExitReservation>(&r.exit_reservation))
                    .and_then(|r| fixed_bytes(&r.route_context_id))
            }
            Ok(DatapathRelayOperation::UdpSessionStart) => super::verified_udp_session_start_scope(
                request.client_signed_request(),
                unix_millis(),
            )
            .and_then(|s| fixed_bytes(&s.exit.route_context_id)),
            Ok(DatapathRelayOperation::MptcpSessionStart) => {
                super::verified_mptcp_session_start_scope(
                    request.client_signed_request(),
                    unix_millis(),
                )
                .and_then(|s| fixed_bytes(&s.exit.route_context_id))
            }
            Ok(DatapathRelayOperation::MpquicSessionStart) => {
                super::verified_mpquic_session_start_scope(
                    request.client_signed_request(),
                    unix_millis(),
                )
                .and_then(|s| fixed_bytes(&s.exit.route_context_id))
            }
            _ => None,
        };
        context.is_some_and(|id| {
            self.route_retire
                .relay
                .get(&id)
                .is_some_and(|scope| scope.retiring)
        })
    }

    pub(super) fn retired_exit_forward(&self, request: &ExitForwardRequest) -> bool {
        let context = match request.validated_operation() {
            Ok(ExitForwardOperation::FinalizeReservation) => {
                decoded_signed_payload::<ExitReservationFinalizeRequest>(
                    request.canonical_request(),
                )
                .and_then(|r| fixed_bytes(&r.route_context_id))
            }
            Ok(ExitForwardOperation::ConfirmRelay) => decoded_signed_payload::<
                super::ExitReservationConfirmation,
            >(request.canonical_request())
            .and_then(|r| fixed_bytes(&r.route_context_id)),
            Ok(ExitForwardOperation::UdpSessionStart) => {
                super::verified_udp_session_start_scope(request.canonical_request(), unix_millis())
                    .and_then(|s| fixed_bytes(&s.exit.route_context_id))
            }
            Ok(ExitForwardOperation::MptcpSessionStart) => {
                super::verified_mptcp_session_start_scope(
                    request.canonical_request(),
                    unix_millis(),
                )
                .and_then(|s| fixed_bytes(&s.exit.route_context_id))
            }
            Ok(ExitForwardOperation::MpquicSessionStart) => {
                super::verified_mpquic_session_start_scope(
                    request.canonical_request(),
                    unix_millis(),
                )
                .and_then(|s| fixed_bytes(&s.exit.route_context_id))
            }
            _ => None,
        };
        context.is_some_and(|id| {
            self.route_retire
                .exit
                .get(&id)
                .is_some_and(|scope| scope.retiring)
        })
    }

    fn detach_retiring_relay_sessions(&mut self, context: ContextId) {
        let ids: Vec<_> = self
            .pending_relay_forwards
            .iter()
            .filter_map(|(id, pending)| {
                (pending
                    .udp_session
                    .as_ref()
                    .is_some_and(|s| s.route_context_id == context)
                    || pending
                        .mptcp_session
                        .as_ref()
                        .is_some_and(|s| s.route_context_id == context)
                    || pending
                        .mpquic_session
                        .as_ref()
                        .is_some_and(|s| s.route_context_id == context))
                .then_some(*id)
            })
            .collect();
        for id in ids {
            let mut pending = self
                .pending_relay_forwards
                .remove(&id)
                .expect("selected pending owner");
            self.relay_forward_index.remove(&pending.key);
            let selected = if let Some(session) = pending.udp_session.take() {
                Some((
                    session.route,
                    session.channels,
                    session.datapath_request_id,
                    DatapathRelayOperation::UdpSessionStart,
                ))
            } else if let Some(session) = pending.mptcp_session.take() {
                Some((
                    session.route,
                    session.channels,
                    session.datapath_request_id,
                    DatapathRelayOperation::MptcpSessionStart,
                ))
            } else {
                pending.mpquic_session.take().map(|session| {
                    (
                        session.route,
                        session.channels,
                        session.datapath_request_id,
                        DatapathRelayOperation::MpquicSessionStart,
                    )
                })
            };
            if let Some((mut route, channels, request_id, operation)) = selected {
                route.usable = false;
                let previous = self.prepared_production_relay_routes.insert(context, route);
                assert!(previous.is_none(), "one affine pending Relay owner");
                if let Ok(response) = DatapathRelayResponse::unavailable(
                    request_id.to_vec(),
                    operation,
                    self.local_node_id.to_vec(),
                    self.service.local_peer_id().to_bytes(),
                ) {
                    for channel in channels {
                        let _ = self
                            .service
                            .send_datapath_relay_response(channel, response.clone());
                    }
                }
            }
        }
    }

    pub(super) fn maintain_route_retirement(&mut self, _now: u64) {
        // The Exit cannot infer that every downstream Relay received its ACK. Keep bounded
        // scopes/tombstones until actor shutdown, including after original expiry; never evict
        // authentication to make room. At the hard capacity, new admission fails closed.
        let clients: Vec<_> = self
            .route_retire
            .clients
            .iter()
            .filter_map(|(id, pending)| checked_request(&pending.signed).is_none().then_some(*id))
            .collect();
        for id in clients {
            self.fail_route_retire_client(id);
        }
        let upstream: Vec<_> = self
            .route_retire
            .upstream
            .iter()
            .filter_map(|(id, pending)| checked_request(&pending.signed).is_none().then_some(*id))
            .collect();
        for id in upstream {
            self.fail_route_retire_upstream(id);
        }
    }

    pub(super) fn shutdown_route_retirement(&mut self) {
        for (_, pending) in self.route_retire.clients.drain() {
            let _ = pending.reply.send(Err(OutboundReservationError::Shutdown));
        }
        self.route_retire.upstream.clear();
    }

    pub(super) fn begin_route_retire(&mut self, command: RetireCommand) {
        let Some(verified) = checked_request(&command.signed) else {
            let _ = command
                .reply
                .send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        if command.relay == command.exit
            || command.relay == *self.service.local_peer_id()
            || self.route_retire.clients.len() >= MAX_PENDING
        {
            let _ = command.reply.send(Err(OutboundReservationError::Capacity));
            return;
        }
        let Some(node) = peer_node(command.relay) else {
            let _ = command
                .reply
                .send(Err(OutboundReservationError::InvalidRequest));
            return;
        };
        let request = DatapathRelayRequest::new(
            verified.nonce()[..FORWARD_ID_BYTES].to_vec(),
            node.to_vec(),
            command.relay.to_bytes(),
            verified.expires_at_ms(),
            DatapathRelayOperation::RouteRetire,
            command.signed.clone(),
            Vec::new(),
        );
        let dispatched = request.ok().and_then(|request| {
            self.service
                .request_datapath_relay(&command.relay, request)
                .ok()
        });
        let Some(id) = dispatched else {
            let _ = command
                .reply
                .send(Err(OutboundReservationError::SendFailed));
            return;
        };
        self.route_retire.clients.insert(
            id,
            PendingClient {
                relay: command.relay,
                exit: command.exit,
                signed: command.signed,
                reply: command.reply,
            },
        );
    }

    pub(super) fn retain_control_retirement(
        &mut self,
        client: Libp2pPeerId,
        request: &ExitForwardRequest,
    ) -> bool {
        if request.validated_operation() != Ok(ExitForwardOperation::FinalizeReservation) {
            return true;
        }
        let Some((_, grant)) = finalize_scope(request) else {
            return false;
        };
        let Some(context) = fixed_bytes(&grant.route_context_id) else {
            return false;
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&grant.exit_peer_id) else {
            return false;
        };
        let Some(exit_node) = fixed_bytes(&grant.exit_node_id) else {
            return false;
        };
        self.insert_relay_retirement(
            context,
            RelayScope {
                request: capability_request(&grant),
                client_peer: client,
                exit_peer,
                exit_node,
                expires_at_ms: grant.expires_at_ms,
                retiring: false,
                complete: false,
            },
        )
    }

    pub(super) fn retain_relay_retirement(
        &mut self,
        client: Libp2pPeerId,
        request: &RelayReservationRequest,
    ) -> bool {
        let Some(grant) = decoded_signed_payload::<ExitReservation>(&request.exit_reservation)
        else {
            return false;
        };
        let Some(context) = fixed_bytes(&grant.route_context_id) else {
            return false;
        };
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&grant.exit_peer_id) else {
            return false;
        };
        let Some(exit_node) = fixed_bytes(&grant.exit_node_id) else {
            return false;
        };
        self.insert_relay_retirement(
            context,
            RelayScope {
                request: exit_request(&grant),
                client_peer: client,
                exit_peer,
                exit_node,
                expires_at_ms: grant.expires_at_ms,
                retiring: false,
                complete: false,
            },
        )
    }

    fn insert_relay_retirement(&mut self, context: ContextId, scope: RelayScope) -> bool {
        if let Some(existing) = self.route_retire.relay.get(&context) {
            return !existing.retiring
                && !existing.complete
                && existing.request == scope.request
                && existing.client_peer == scope.client_peer
                && existing.exit_peer == scope.exit_peer
                && existing.expires_at_ms == scope.expires_at_ms;
        }
        if self.route_retire.relay.len() >= MAX_SCOPES {
            return false;
        }
        self.route_retire.relay.insert(context, scope);
        true
    }

    pub(super) fn retain_exit_retirement(&mut self, request: &ExitForwardRequest) -> Option<()> {
        let (finalize, grant) = finalize_scope(request)?;
        if grant.exit_node_id != self.local_node_id
            || grant.exit_peer_id != self.service.local_peer_id().to_bytes()
        {
            return None;
        }
        let context = fixed_bytes(&grant.route_context_id)?;
        let scope = capability_request(&grant);
        let mut relays = finalize
            .relay_paths
            .iter()
            .map(|path| Libp2pPeerId::from_bytes(&path.relay_peer_id).ok())
            .collect::<Option<BTreeSet<_>>>()?;
        relays.insert(Libp2pPeerId::from_bytes(&grant.control_relay_peer_id).ok()?);
        if let Some(existing) = self.route_retire.exit.get(&context) {
            return (!existing.retiring
                && !existing.complete
                && existing.request == scope
                && existing.relays == relays
                && existing.expires_at_ms == grant.expires_at_ms)
                .then_some(());
        }
        if self.route_retire.exit.len() >= MAX_SCOPES {
            return None;
        }
        self.route_retire.exit.insert(
            context,
            ExitScope {
                request: scope,
                relays,
                expires_at_ms: grant.expires_at_ms,
                retiring: false,
                complete: false,
            },
        );
        Some(())
    }

    pub(super) fn answer_route_retire(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
    ) {
        let admitted = self.admit_relay_retire(peer, connection, request);
        let Some((context, exit, upstream)) = admitted else {
            tracing::warn!("ROUTE_RETIRE_RELAY_SCOPE_REJECTED");
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::RouteRetire,
                channel,
            );
            return;
        };
        self.retire_receive_budget_context(context);
        // Stop a late upstream Start response from installing a new usable local owner.
        self.detach_retiring_relay_sessions(context);
        let Ok(id) = self
            .service
            .request_exit_forward_upstream(&exit, upstream.into())
        else {
            tracing::warn!("ROUTE_RETIRE_UPSTREAM_UNAVAILABLE");
            self.send_native_datapath_unavailable(
                request,
                DatapathRelayOperation::RouteRetire,
                channel,
            );
            return;
        };
        tracing::info!("ROUTE_RETIRE_UPSTREAM_DISPATCHED");
        self.route_retire.upstream.insert(
            id,
            PendingUpstream {
                context,
                exit,
                signed: request.client_signed_request().to_vec(),
                request_id: request.request_id().to_vec(),
                channel,
            },
        );
    }

    fn admit_relay_retire(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: &DatapathRelayRequest,
    ) -> Option<(ContextId, Libp2pPeerId, ExitForwardRequest)> {
        let verified = checked_request(request.client_signed_request())?;
        let context = fixed_bytes(&verified.message().route_context_id)?;
        if let Some(route) = self.prepared_production_relay_routes.get(&context) {
            let grant =
                decoded_signed_payload::<super::RelayReservation>(route.accepted.encoded())?;
            if route.authenticated_client_peer != peer
                || grant.reservation_id != verified.message().reservation_id
                || grant.route_context_id != verified.message().route_context_id
                || grant.client_session_id != verified.message().client_session_id
                || grant.client_session_public_key != verified.message().client_session_public_key
                || grant.policy_hash != verified.message().policy_hash
            {
                return None;
            }
        }
        let scope = self.route_retire.relay.get_mut(&context)?;
        if request.validate().is_err()
            || scope.request != *verified.message()
            || scope.client_peer != peer
            || request.relay_node_id() != self.local_node_id
            || request.relay_peer_id() != self.service.local_peer_id().to_bytes()
            || request.request_id() != &verified.nonce()[..FORWARD_ID_BYTES]
            || !self
                .service
                .route_retirement_connection_live(peer, connection)
            || self.route_retire.upstream.len() >= MAX_PENDING
        {
            return None;
        }
        scope.retiring = true;
        let upstream = ExitForwardRequest::new(
            request.request_id().to_vec(),
            self.local_node_id.to_vec(),
            self.service.local_peer_id().to_bytes(),
            self.local_public_key.to_vec(),
            scope.exit_peer.to_bytes(),
            scope.exit_node.to_vec(),
            request.deadline_unix_ms(),
            ExitForwardOperation::RouteRetire,
            request.client_signed_request().to_vec(),
        )
        .ok()?;
        Some((context, scope.exit_peer, upstream))
    }

    pub(super) async fn answer_exit_route_retire(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        let receipt = self
            .perform_exit_route_retire(peer, connection, request)
            .await;
        if receipt.is_none() {
            tracing::warn!("ROUTE_RETIRE_EXIT_UNCONFIRMED");
        }
        let response = match receipt {
            Some(receipt) => ExitForwardResponse::granted(
                request.forward_id().to_vec(),
                ExitForwardOperation::RouteRetire,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                vec![receipt],
            ),
            None => ExitForwardResponse::unavailable(
                request.forward_id().to_vec(),
                ExitForwardOperation::RouteRetire,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ),
        };
        if let Ok(response) = response {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
        }
    }

    async fn perform_exit_route_retire(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: &ExitForwardRequest,
    ) -> Option<Vec<u8>> {
        let verified = checked_request(request.canonical_request())?;
        let context = fixed_bytes(&verified.message().route_context_id)?;
        if let Some(route) = self.prepared_production_exit_routes.get(&context) {
            let grant =
                decoded_signed_payload::<ExitReservation>(route.bundle.signed_exit_reservation())?;
            if exit_request(&grant) != *verified.message() {
                return None;
            }
        }
        if let Some(route) = self.active_production_mptcp_exit_routes.get(&context) {
            let start = super::decode_canonical::<super::MptcpSessionStartRequest>(
                &route.canonical_start,
                usize::try_from(super::MAX_FORWARDING_FRAME_BYTES).ok()?,
            )
            .ok()?;
            let grant = decoded_signed_payload::<ExitReservation>(start.signed_exit_reservation())?;
            if exit_request(&grant) != *verified.message() {
                return None;
            }
        }
        let scope = self.route_retire.exit.get_mut(&context)?;
        if request.validate().is_err()
            || scope.request != *verified.message()
            || !scope.relays.contains(&peer)
            || request.control_relay_peer_id() != peer.to_bytes()
            || request.control_relay_node_id() != peer_node(peer)?
            || request.exit_node_id() != self.local_node_id
            || request.exit_peer_id() != self.service.local_peer_id().to_bytes()
            || request.forward_id() != &verified.nonce()[..FORWARD_ID_BYTES]
            || !self
                .service
                .route_retirement_connection_live(peer, connection)
        {
            return None;
        }
        if let Some(runtime) = self.exit_runtime_retirements.get(&context) {
            let grant =
                decoded_signed_payload::<ExitReservation>(&runtime.signed_exit_reservation)?;
            if exit_request(&grant) != scope.request {
                return None;
            }
        }
        scope.retiring = true;
        if !self.retire_exact_exit_owners(context).await {
            tracing::info!("ROUTE_RETIRE_EXIT_CLEANUP_PENDING");
            return None;
        }
        self.route_retire.exit.get_mut(&context)?.complete = true;
        let _ = self.exit_service.as_mut().and_then(|service| {
            service
                .release(&fixed_bytes::<FORWARD_ID_BYTES>(
                    &verified.message().reservation_id,
                )?)
                .ok()
        });
        tracing::info!("ROUTE_RETIRE_EXIT_COMPLETE");
        self.retirement_receipt(request.canonical_request(), Vec::new())
    }

    async fn retire_exact_exit_owners(&mut self, context: ContextId) -> bool {
        if let Some(pending) = self.pending_mptcp_exit_sessions.remove(&context) {
            self.finish_mptcp_exit_session_unavailable(context, pending)
                .await;
        }
        if let Some(pending) = self.pending_mpquic_exit_sessions.remove(&context) {
            self.finish_mpquic_exit_session_unavailable(context, pending)
                .await;
        }
        if let Some(runtime) = self.exit_runtime_retirements.get_mut(&context) {
            let _ = runtime.shutdown.send(true);
            if self
                .active_production_mptcp_exit_routes
                .get(&context)
                .is_some_and(|r| r.runtime_started)
            {
                return false; // The actor must consume the real runtime completion first.
            }
            if runtime.cleanup_not_before_ms > unix_millis()
                || matches!(
                    runtime.completed.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                )
            {
                return false;
            }
            if self
                .helper
                .destroy_context_after_join(&runtime.cleanup)
                .await
                .is_err()
            {
                runtime.cleanup_not_before_ms =
                    unix_millis().saturating_add(super::HELPER_CLEANUP_RETRY_BACKOFF_MS);
                return false;
            }
            self.exit_runtime_retirements.remove(&context);
        }
        if self
            .prepared_production_exit_routes
            .get(&context)
            .is_some_and(|route| route.cleanup_not_before_ms > unix_millis())
            || self
                .active_production_mptcp_exit_routes
                .get(&context)
                .is_some_and(|route| route.cleanup_not_before_ms > unix_millis())
        {
            return false;
        }
        if let Some(route) = self.prepared_production_exit_routes.remove(&context) {
            if !self.retire_production_exit_route(context, route).await {
                return false;
            }
        }
        if let Some(route) = self.active_production_mptcp_exit_routes.remove(&context) {
            if !self.retire_active_mptcp_exit_route(context, route).await {
                return false;
            }
        }
        true
    }

    fn retirement_receipt(&self, signed: &[u8], signed_exit_receipt: Vec<u8>) -> Option<Vec<u8>> {
        let verified = checked_request(signed)?;
        let request = verified.message();
        let receipt = RetirementReceipt {
            route_context_id: request.route_context_id.clone(),
            reservation_id: request.reservation_id.clone(),
            request_hash: route_retire_request_hash(signed).ok()?.to_vec(),
            provider_node_id: self.local_node_id.to_vec(),
            confirmed_destroyed: true,
            signed_exit_receipt,
        };
        sign_control_message_with(
            &receipt,
            self.local_public_key,
            unix_millis(),
            verified.expires_at_ms(),
            generate_nonce(),
            TimePolicy::default(),
            |bytes| self.identity.sign(bytes).ok(),
        )
        .ok()
    }

    pub(super) async fn complete_route_retire_upstream(
        &mut self,
        id: RequestId,
        peer: Libp2pPeerId,
        response: &UpstreamExitForwardResponse,
    ) -> bool {
        let Some(pending) = self.route_retire.upstream.get(&id) else {
            return false;
        };
        if pending.exit != peer {
            return true;
        }
        let response = response.as_forward_response();
        let receipt = response
            .signed_responses()
            .first()
            .filter(|signed| {
                response.validate().is_ok()
                    && response.validated_operation() == Ok(ExitForwardOperation::RouteRetire)
                    && response.validated_status() == Ok(ForwardStatus::Granted)
                    && response.forward_id() == pending.request_id
                    && response.exit_peer_id() == peer.to_bytes()
                    && verified_receipt(signed, peer, &pending.signed)
                        .is_some_and(|r| r.signed_exit_receipt.is_empty())
            })
            .cloned();
        let pending = self
            .route_retire
            .upstream
            .remove(&id)
            .expect("checked pending retirement");
        let receipt = if let Some(exit_receipt) = receipt {
            let cleanup_due = self
                .prepared_production_relay_routes
                .get(&pending.context)
                .is_none_or(|route| route.cleanup_not_before_ms <= unix_millis());
            let destroyed = if cleanup_due {
                match self
                    .prepared_production_relay_routes
                    .remove(&pending.context)
                {
                    Some(route) => {
                        self.retire_production_relay_route(pending.context, route)
                            .await
                    }
                    None => true,
                }
            } else {
                false
            };
            if destroyed {
                if let Some(scope) = self.route_retire.relay.get_mut(&pending.context) {
                    scope.complete = true;
                }
                self.retirement_receipt(&pending.signed, exit_receipt)
            } else {
                tracing::info!("ROUTE_RETIRE_RELAY_CLEANUP_PENDING");
                None
            }
        } else {
            tracing::warn!("ROUTE_RETIRE_UPSTREAM_UNCONFIRMED");
            None
        };
        if receipt.is_some() {
            tracing::info!("ROUTE_RETIRE_RELAY_COMPLETE");
        }
        self.send_relay_retirement_response(pending, receipt);
        true
    }

    fn send_relay_retirement_response(
        &mut self,
        pending: PendingUpstream,
        receipt: Option<Vec<u8>>,
    ) {
        let response = match receipt {
            Some(receipt) => DatapathRelayResponse::granted(
                pending.request_id,
                DatapathRelayOperation::RouteRetire,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                receipt,
            ),
            None => DatapathRelayResponse::unavailable(
                pending.request_id,
                DatapathRelayOperation::RouteRetire,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            ),
        };
        if let Ok(response) = response {
            let _ = self
                .service
                .send_datapath_relay_response(pending.channel, response);
        }
    }

    pub(super) fn fail_route_retire_upstream(&mut self, id: RequestId) -> bool {
        let Some(pending) = self.route_retire.upstream.remove(&id) else {
            return false;
        };
        tracing::warn!("ROUTE_RETIRE_UPSTREAM_FAILED");
        self.send_relay_retirement_response(pending, None);
        true
    }

    pub(super) fn complete_route_retire_client(
        &mut self,
        id: RequestId,
        peer: Libp2pPeerId,
        response: &DatapathRelayResponse,
    ) -> bool {
        let Some(pending) = self.route_retire.clients.get(&id) else {
            return false;
        };
        if pending.relay != peer {
            return true;
        }
        let accepted = verified_receipt(response.signed_response(), peer, &pending.signed)
            .and_then(|receipt| {
                verified_receipt(&receipt.signed_exit_receipt, pending.exit, &pending.signed)
            })
            .is_some_and(|receipt| receipt.signed_exit_receipt.is_empty())
            && response.validate().is_ok()
            && response.validated_operation() == Ok(DatapathRelayOperation::RouteRetire)
            && response.validated_status() == Ok(ForwardStatus::Granted)
            && checked_request(&pending.signed)
                .is_some_and(|r| response.request_id() == &r.nonce()[..FORWARD_ID_BYTES]);
        let pending = self
            .route_retire
            .clients
            .remove(&id)
            .expect("checked pending retirement");
        let _ = pending.reply.send(if accepted {
            Ok(())
        } else {
            Err(OutboundReservationError::SendFailed)
        });
        true
    }

    pub(super) fn fail_route_retire_client(&mut self, id: RequestId) -> bool {
        let Some(pending) = self.route_retire.clients.remove(&id) else {
            return false;
        };
        let _ = pending
            .reply
            .send(Err(OutboundReservationError::AmbiguousAfterDispatch));
        true
    }
}

fn verified_receipt(bytes: &[u8], peer: Libp2pPeerId, request: &[u8]) -> Option<RetirementReceipt> {
    let original = checked_request(request)?;
    if bytes.len() > MAX_ROUTE_RETIRE_BYTES || !signed_envelope_matches_peer(bytes, &peer) {
        return None;
    }
    let verified = verify_control_message::<RetirementReceipt>(
        bytes,
        unix_millis(),
        TimePolicy::default(),
        &mut ReplayCache::new(1).ok()?,
    )
    .ok()?;
    let receipt = verified.message();
    (receipt.route_context_id == original.message().route_context_id
        && receipt.reservation_id == original.message().reservation_id
        && receipt.request_hash == route_retire_request_hash(request).ok()?
        && receipt.provider_node_id == peer_node(peer)?
        && receipt.confirmed_destroyed)
        .then(|| receipt.clone())
}
