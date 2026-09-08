//! Affine, adjacent Relay-to-Exit receive-budget continuations.
//!
//! These messages update an existing signed reservation, never select a route or grant egress.

use super::{
    AgentState, Arc, BTreeSet, ConnectionId, DatapathRelayOperation, DatapathRelayRequest,
    DatapathRelayResponse, Digest, DiscoveryRuntime, ExitForwardOperation, ExitForwardRequest,
    ExitForwardResponse, FORWARD_ID_BYTES, ForwardStatus, HashMap, Libp2pPeerId, LogLevel, OsRng,
    RelayReservation, ReplayCache, RngCore, RwLock, Sha256, TimePolicy,
    UpstreamExitForwardResponse, decoded_signed_payload, fixed_bytes, generate_nonce,
    request_response, sign_control_message_with, unix_millis, verified_mpquic_session_start_scope,
    verified_mptcp_session_start_scope, verified_udp_session_start_scope,
};
use crate::downlink_sharing::{
    DownlinkSharingRuntime, ReceiveBudgetWindow, allocate_receive_budget,
};
use crate::helper::{HelperClientError, RuntimeBoundDownlinkBudgetTarget};
use std::collections::BTreeMap;
use volparossa_protocol::{
    AdjacentReceiveBudget, AdjacentReceiveBudgetReceipt, AdjacentReceiveLeg,
    MAX_ADJACENT_RECEIVE_BUDGET_LIFETIME_MS, verify_adjacent_receive_budget,
    verify_adjacent_receive_budget_receipt,
};

const MAX_LEGS: usize = 128;
const MAX_DEFERRED_BYTES: usize = 512 * 1024;
type LegKey = ([u8; FORWARD_ID_BYTES], u32);

pub(super) struct DownlinkBridge {
    runtime: Option<DownlinkSharingRuntime>,
    outgoing: BTreeMap<LegKey, ReceiveLeg>,
    targets: BTreeMap<LegKey, SendLeg>,
    pending: HashMap<request_response::OutboundRequestId, PendingBudget>,
    deferred: BTreeMap<LegKey, DeferredStart>,
    replay: ReplayCache,
    sample_failure: Option<HelperClientError>,
}

impl Default for DownlinkBridge {
    fn default() -> Self {
        Self {
            runtime: None,
            outgoing: BTreeMap::new(),
            targets: BTreeMap::new(),
            pending: HashMap::new(),
            deferred: BTreeMap::new(),
            // At most 128 legs, two requests/second and five live seconds, in each direction.
            replay: ReplayCache::new(4_096).expect("nonzero bounded replay capacity"),
            sample_failure: None,
        }
    }
}

struct ReceiveLeg {
    signed_grant: Vec<u8>,
    grant: RelayReservation,
    exit_peer: Libp2pPeerId,
    sequence: u64,
    positive_until_ms: u64,
    credit: BudgetCredit,
    retired: bool,
}

/// A lost reply cannot free rate which the peer may already have installed. A signed newer
/// receipt supersedes earlier sequences; without it the highest live sent rate expires closed.
#[derive(Default)]
struct BudgetCredit {
    rate: u64,
    expires_at_ms: u64,
}

impl BudgetCredit {
    const fn live(&self, now_ms: u64) -> u64 {
        if self.expires_at_ms > now_ms {
            self.rate
        } else {
            0
        }
    }

    fn sent(&mut self, rate: u64, expires_at_ms: u64, now_ms: u64) {
        self.rate = self.live(now_ms).max(rate);
        self.expires_at_ms = self.expires_at_ms.max(expires_at_ms);
    }

    fn acknowledged(&mut self, rate: u64, expires_at_ms: u64) {
        self.rate = rate;
        self.expires_at_ms = expires_at_ms;
    }
}

struct SendLeg {
    target: RuntimeBoundDownlinkBudgetTarget,
    signed_grant: Vec<u8>,
    relay_peer: Libp2pPeerId,
    expires_at_ms: u64,
    sequence: u64,
}

struct PendingBudget {
    key: LegKey,
    exit_peer: Libp2pPeerId,
    request: ExitForwardRequest,
    signed_budget: Vec<u8>,
    deadline_ms: u64,
}

struct DeferredStart {
    peer: Libp2pPeerId,
    request: DatapathRelayRequest,
    channel: request_response::ResponseChannel<DatapathRelayResponse>,
}

impl DiscoveryRuntime {
    /// Transfer the single receiver accounting owner before starting this actor.
    pub(crate) fn set_download_sharing(&mut self, runtime: Option<DownlinkSharingRuntime>) {
        assert!(
            self.downlink.runtime.is_none(),
            "one receiver accounting owner"
        );
        self.downlink.runtime = runtime;
    }

    pub(super) async fn maintain_downlink(
        &mut self,
        state: &Arc<RwLock<AgentState>>,
    ) -> Result<(), HelperClientError> {
        if let Some(error) = self.downlink.sample_failure.take() {
            return Err(error);
        }
        let now = unix_millis();
        self.downlink.outgoing.retain(|_, leg| {
            leg.grant.expires_at_ms > now && (!leg.retired || leg.credit.live(now) > 0)
        });
        self.downlink.targets.retain(|(context, _), leg| {
            leg.expires_at_ms > now
                && (self.prepared_production_exit_routes.contains_key(context)
                    || self.exit_runtime_retirements.contains_key(context)
                    || self
                        .active_production_mptcp_exit_routes
                        .contains_key(context))
        });
        // Keep even expired request IDs until the transport returns Response/OutboundFailure.
        // Dropping our entry early would permit a second still-in-flight stream for this leg.
        let controlled = self.controlled_receive_keys();
        if let Some(runtime) = self.downlink.runtime.as_mut() {
            let window = runtime.sample(&controlled).await?;
            self.dispatch_downlink_window(&window);
        }
        Box::pin(self.resume_downlink_starts(state)).await;
        Ok(())
    }

    pub(super) async fn shutdown_downlink(&mut self, state: &Arc<RwLock<AgentState>>) {
        self.downlink.pending.clear();
        self.downlink.outgoing.clear();
        self.downlink.targets.clear();
        self.downlink.deferred.clear();
        if let Some(runtime) = self.downlink.runtime.take() {
            if runtime.shutdown().await.is_err() {
                state.write().await.log(
                    LogLevel::Error,
                    "DOWNLINK_ACCOUNTING_CLEANUP_PENDING",
                    unix_millis(),
                );
            }
        }
    }

    /// Called only after this Relay's exact pair of helper leases has activated.
    pub(super) fn register_receive_leg(&mut self, context: [u8; FORWARD_ID_BYTES]) -> bool {
        let Some(route) = self.prepared_production_relay_routes.get(&context) else {
            return false;
        };
        let Some(grant) = decoded_signed_payload::<RelayReservation>(route.accepted.encoded())
        else {
            return false;
        };
        if !grant.receive_budget_required {
            return true;
        }
        let key = (context, grant.path_id);
        if self.downlink.runtime.is_none()
            || self.downlink.outgoing.len() >= MAX_LEGS
            || self.downlink.outgoing.contains_key(&key)
        {
            return false;
        }
        let Ok(exit_peer) = Libp2pPeerId::from_bytes(&grant.exit_peer_id) else {
            return false;
        };
        self.downlink.outgoing.insert(
            key,
            ReceiveLeg {
                signed_grant: route.accepted.encoded().to_vec(),
                grant,
                exit_peer,
                sequence: 0,
                positive_until_ms: 0,
                credit: BudgetCredit::default(),
                retired: false,
            },
        );
        true
    }

    pub(super) async fn prime_receive_budget(&mut self) {
        let controlled = self.controlled_receive_keys();
        if let Some(runtime) = self.downlink.runtime.as_mut() {
            match runtime.sample(&controlled).await {
                Ok(window) => self.dispatch_downlink_window(&window),
                Err(error) => self.downlink.sample_failure = Some(error),
            }
        }
    }

    fn controlled_receive_keys(&self) -> BTreeSet<(Vec<u8>, u32)> {
        self.downlink
            .outgoing
            .iter()
            .filter_map(|(key, leg)| {
                (!leg.retired && leg.grant.expires_at_ms > unix_millis())
                    .then_some((key.0.to_vec(), key.1))
            })
            .collect()
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one signed-grant dispatch atomically reserves bounded aggregate credit and its sole RPC continuation"
    )]
    fn dispatch_downlink_window(&mut self, window: &ReceiveBudgetWindow) {
        let now = unix_millis();
        let keys = self
            .downlink
            .outgoing
            .iter()
            .filter_map(|(key, leg)| {
                (!leg.retired
                    && leg.grant.expires_at_ms > now
                    && window.paths.contains(&(key.0.to_vec(), key.1)))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        let caps = keys
            .iter()
            .map(|key| self.downlink.outgoing[key].grant.maximum_down_mbps * 125_000)
            .collect::<Vec<_>>();
        let reserved = self
            .downlink
            .outgoing
            .values()
            .map(|leg| leg.credit.live(now))
            .sum::<u64>();
        let mut free = window.available_bytes_per_second.saturating_sub(reserved);
        for (key, (desired_rate, burst)) in keys.into_iter().zip(allocate_receive_budget(
            window.available_bytes_per_second,
            &caps,
        )) {
            if self.downlink.pending.len() >= MAX_LEGS {
                break;
            }
            if self
                .downlink
                .pending
                .values()
                .any(|pending| pending.key == key)
            {
                continue;
            }
            let Some(leg) = self.downlink.outgoing.get_mut(&key) else {
                continue;
            };
            let previous = leg.credit.live(now);
            let rate = desired_rate.min(previous.saturating_add(free));
            let Some(sequence) = leg.sequence.checked_add(1) else {
                continue;
            };
            let nonce = generate_nonce();
            let expiry = now
                .saturating_add(MAX_ADJACENT_RECEIVE_BUDGET_LIFETIME_MS)
                .min(leg.grant.expires_at_ms);
            let budget = AdjacentReceiveBudget {
                reservation_id: leg.grant.reservation_id.clone(),
                route_context_id: key.0.to_vec(),
                path_id: key.1,
                receiver_relay_node_id: self.local_node_id.to_vec(),
                sender_exit_node_id: leg.grant.exit_node_id.clone(),
                relay_reservation_sha256: Sha256::digest(&leg.signed_grant).to_vec(),
                leg: AdjacentReceiveLeg::ExitToRelay as i32,
                sequence,
                rate_bytes_per_second: rate,
                burst_bytes: burst,
                created_at_ms: now,
                expires_at_ms: expiry,
                nonce: nonce.to_vec(),
            };
            let Ok(signed_budget) = sign_control_message_with(
                &budget,
                self.local_public_key,
                now,
                expiry,
                nonce,
                TimePolicy::default(),
                |bytes| self.identity.sign(bytes).ok(),
            ) else {
                continue;
            };
            leg.sequence = sequence;
            let mut forward_id = [0_u8; FORWARD_ID_BYTES];
            OsRng.fill_bytes(&mut forward_id);
            let Ok(request) = ExitForwardRequest::new(
                forward_id.to_vec(),
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                self.local_public_key.to_vec(),
                leg.exit_peer.to_bytes(),
                leg.grant.exit_node_id.clone(),
                expiry,
                ExitForwardOperation::AdjacentReceiveBudget,
                signed_budget.clone(),
            ) else {
                continue;
            };
            let Ok(id) = self
                .service
                .request_exit_forward_upstream(&leg.exit_peer, request.clone().into())
            else {
                continue;
            };
            free = free.saturating_sub(rate.saturating_sub(previous));
            leg.credit.sent(rate, expiry, now);
            if rate == 0 {
                leg.positive_until_ms = 0;
            }
            self.downlink.pending.insert(
                id,
                PendingBudget {
                    key,
                    exit_peer: leg.exit_peer,
                    request,
                    signed_budget,
                    deadline_ms: expiry,
                },
            );
        }
    }

    pub(super) fn fail_downlink_budget(&mut self, id: request_response::OutboundRequestId) -> bool {
        self.downlink.pending.remove(&id).is_some()
    }

    pub(super) fn retire_receive_budget_context(&mut self, context: [u8; FORWARD_ID_BYTES]) {
        for (key, leg) in &mut self.downlink.outgoing {
            if key.0 == context {
                leg.retired = true;
                leg.positive_until_ms = 0;
            }
        }
        self.downlink.deferred.retain(|key, _| key.0 != context);
    }

    pub(super) fn complete_downlink_budget(
        &mut self,
        id: request_response::OutboundRequestId,
        peer: Libp2pPeerId,
        response: &UpstreamExitForwardResponse,
    ) -> bool {
        let Some(pending) = self.downlink.pending.remove(&id) else {
            return false;
        };
        let Some(leg) = self.downlink.outgoing.get_mut(&pending.key) else {
            return true;
        };
        leg.accept_receipt(
            &pending,
            peer,
            response.as_forward_response(),
            unix_millis(),
            &mut self.downlink.replay,
        );
        true
    }

    /// Derive update-only handles while the affine Exit owner is still held here.
    pub(super) fn register_send_legs(&mut self, context: [u8; FORWARD_ID_BYTES]) -> bool {
        let Some(route) = self.prepared_production_exit_routes.get(&context) else {
            return false;
        };
        let mut entries = Vec::new();
        for activation in route.pending_activations.values() {
            let Some(grant) =
                decoded_signed_payload::<RelayReservation>(&activation.signed_relay_reservation)
            else {
                return false;
            };
            if !grant.receive_budget_required {
                continue;
            }
            let key = (context, activation.path_id);
            if self.downlink.targets.contains_key(&key) {
                continue;
            }
            let Ok(target) = route
                .helper_owner
                .downlink_budget_target(activation.path_id)
            else {
                return false;
            };
            let Ok(relay_peer) = Libp2pPeerId::from_bytes(&grant.relay_peer_id) else {
                return false;
            };
            entries.push((
                key,
                SendLeg {
                    target,
                    relay_peer,
                    signed_grant: activation.signed_relay_reservation.clone(),
                    expires_at_ms: grant.expires_at_ms,
                    sequence: 0,
                },
            ));
        }
        if entries.len().saturating_add(self.downlink.targets.len()) > MAX_LEGS {
            return false;
        }
        self.downlink.targets.extend(entries);
        true
    }

    pub(super) async fn answer_downlink_budget(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: &ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        let signed_receipt = self.apply_received_budget(peer, connection, request).await;
        let response = if let Some(receipt) = signed_receipt {
            ExitForwardResponse::granted(
                request.forward_id().to_vec(),
                ExitForwardOperation::AdjacentReceiveBudget,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                vec![receipt],
            )
        } else {
            ExitForwardResponse::unavailable(
                request.forward_id().to_vec(),
                ExitForwardOperation::AdjacentReceiveBudget,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            )
        };
        if let Ok(response) = response {
            let _ = self
                .service
                .send_exit_forward_upstream_response(channel, response.into());
        }
    }

    async fn apply_received_budget(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: &ExitForwardRequest,
    ) -> Option<Vec<u8>> {
        let now = unix_millis();
        if request.validate().is_err()
            || !self.exit_authority_enabled()
            || self.exit_service.is_none()
            || request.deadline_unix_ms() <= now
            || request.control_relay_peer_id() != peer.to_bytes()
            || request.exit_node_id() != self.local_node_id
            || request.exit_peer_id() != self.service.local_peer_id().to_bytes()
        {
            return None;
        }
        // This operation revalidates the same authenticated connection before and after helper
        // I/O; its response channel is retained in this actor, not exported as native authority.
        drop(
            self.service
                .bind_native_probe_data_relay_connection(peer, connection)
                .ok()?,
        );
        let budget = decoded_signed_payload::<AdjacentReceiveBudget>(request.canonical_request())?;
        let context = fixed_bytes::<FORWARD_ID_BYTES>(&budget.route_context_id)?;
        if !self.budget_exit_context_live(&context, now) {
            return None;
        }
        let leg = self.downlink.targets.get_mut(&(context, budget.path_id))?;
        if leg.relay_peer != peer || leg.expires_at_ms <= now {
            return None;
        }
        let verified = verify_adjacent_receive_budget(
            request.canonical_request(),
            &leg.signed_grant,
            now,
            leg.sequence,
            &mut self.downlink.replay,
        )
        .ok()?;
        let budget = verified.message();
        let applied = self
            .helper
            .apply_downlink_budget(&leg.target, request.canonical_request().to_vec())
            .await
            .ok()?;
        if applied.route_context_id != budget.route_context_id
            || applied.sequence != budget.sequence
            || applied.rate_bytes_per_second != budget.rate_bytes_per_second
            || applied.burst_bytes != budget.burst_bytes
            || applied.expires_at_ms != budget.expires_at_ms
        {
            return None;
        }
        leg.sequence = budget.sequence;
        drop(
            self.service
                .bind_native_probe_data_relay_connection(peer, connection)
                .ok()?,
        );
        let now = unix_millis();
        if now >= budget.expires_at_ms {
            return None;
        }
        let nonce = generate_nonce();
        let receipt = AdjacentReceiveBudgetReceipt {
            receiver_relay_node_id: budget.receiver_relay_node_id.clone(),
            sender_exit_node_id: self.local_node_id.to_vec(),
            signed_budget_sha256: Sha256::digest(request.canonical_request()).to_vec(),
            sequence: budget.sequence,
            rate_bytes_per_second: budget.rate_bytes_per_second,
            burst_bytes: budget.burst_bytes,
            created_at_ms: now,
            expires_at_ms: budget.expires_at_ms,
            nonce: nonce.to_vec(),
        };
        sign_control_message_with(
            &receipt,
            self.local_public_key,
            now,
            receipt.expires_at_ms,
            nonce,
            TimePolicy::default(),
            |bytes| self.identity.sign(bytes).ok(),
        )
        .ok()
    }

    fn budget_exit_context_live(&self, context: &[u8; FORWARD_ID_BYTES], now_ms: u64) -> bool {
        self.prepared_production_exit_routes
            .get(context)
            .is_some_and(|route| route.commit.is_some() && route.expires_at_ms > now_ms)
            || self
                .exit_runtime_retirements
                .get(context)
                .is_some_and(|runtime| !*runtime.shutdown.borrow())
            || self
                .active_production_mptcp_exit_routes
                .get(context)
                .is_some_and(|route| route.expires_at_ms > now_ms)
    }

    /// Keep the original request/channel, not an activation owner, while the first allowance is
    /// absent. The normal signed request and packet-counter checks run unchanged on continuation.
    pub(super) fn defer_downlink_start_request(
        &mut self,
        peer: Libp2pPeerId,
        request: &DatapathRelayRequest,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
    ) -> Option<request_response::ResponseChannel<DatapathRelayResponse>> {
        if self.downlink.outgoing.is_empty() {
            return Some(channel);
        }
        let Some(context) = session_context(request) else {
            return Some(channel);
        };
        let Some((key, leg)) = self
            .downlink
            .outgoing
            .iter()
            .find(|(key, leg)| key.0 == context && !leg.retired)
        else {
            return Some(channel);
        };
        if leg.ready(unix_millis()) {
            return Some(channel);
        }
        let key = *key;
        let bytes = self
            .downlink
            .deferred
            .values()
            .map(|pending| pending.request.client_signed_request().len())
            .sum::<usize>();
        if self.downlink.deferred.len() >= MAX_LEGS
            || self.downlink.deferred.contains_key(&key)
            || bytes.saturating_add(request.client_signed_request().len()) > MAX_DEFERRED_BYTES
            || self
                .prepared_production_relay_routes
                .get(&context)
                .is_none_or(|route| route.authenticated_client_peer != peer)
        {
            if let Ok(operation) = request.validated_operation() {
                self.send_native_datapath_unavailable(request, operation, channel);
            }
            return None;
        }
        self.downlink.deferred.insert(
            key,
            DeferredStart {
                peer,
                request: request.clone(),
                channel,
            },
        );
        None
    }

    async fn resume_downlink_starts(&mut self, state: &Arc<RwLock<AgentState>>) {
        let now = unix_millis();
        let ready = self
            .downlink
            .deferred
            .iter()
            .filter_map(|(key, pending)| {
                (pending.request.deadline_unix_ms() <= now
                    || self
                        .downlink
                        .outgoing
                        .get(key)
                        .is_none_or(|leg| leg.retired)
                    || self.downlink.outgoing[key].ready(now))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in ready {
            let Some(pending) = self.downlink.deferred.remove(&key) else {
                continue;
            };
            let Ok(operation) = pending.request.validated_operation() else {
                continue;
            };
            if pending.request.deadline_unix_ms() <= unix_millis()
                || self
                    .downlink
                    .outgoing
                    .get(&key)
                    .is_none_or(|leg| leg.retired)
            {
                self.send_native_datapath_unavailable(&pending.request, operation, pending.channel);
                continue;
            }
            match operation {
                DatapathRelayOperation::UdpSessionStart => {
                    Box::pin(self.begin_udp_session_start(
                        pending.peer,
                        &pending.request,
                        pending.channel,
                        state,
                    ))
                    .await;
                }
                DatapathRelayOperation::MptcpSessionStart => {
                    Box::pin(self.begin_mptcp_session_start(
                        pending.peer,
                        &pending.request,
                        pending.channel,
                        state,
                    ))
                    .await;
                }
                DatapathRelayOperation::MpquicSessionStart => {
                    Box::pin(self.begin_mpquic_session_start(
                        pending.peer,
                        &pending.request,
                        pending.channel,
                        state,
                    ))
                    .await;
                }
                _ => self.send_native_datapath_unavailable(
                    &pending.request,
                    operation,
                    pending.channel,
                ),
            }
        }
    }
}

impl ReceiveLeg {
    fn ready(&self, now_ms: u64) -> bool {
        !self.retired && self.positive_until_ms > now_ms.saturating_add(500)
    }
    fn accept_receipt(
        &mut self,
        pending: &PendingBudget,
        peer: Libp2pPeerId,
        response: &ExitForwardResponse,
        now_ms: u64,
        replay: &mut ReplayCache,
    ) -> bool {
        if peer != pending.exit_peer
            || pending.deadline_ms <= now_ms
            || response.validate().is_err()
            || response.forward_id() != pending.request.forward_id()
            || response.exit_peer_id() != peer.to_bytes()
            || response.exit_node_id() != self.grant.exit_node_id
            || response.validated_operation() != Ok(ExitForwardOperation::AdjacentReceiveBudget)
            || response.validated_status() != Ok(ForwardStatus::Granted)
        {
            return false;
        }
        let [encoded] = response.signed_responses() else {
            return false;
        };
        let Ok(receipt) = verify_adjacent_receive_budget_receipt(
            encoded,
            &pending.signed_budget,
            &self.signed_grant,
            now_ms,
            replay,
        ) else {
            return false;
        };
        let receipt = receipt.message();
        if receipt.sequence != self.sequence {
            return false;
        }
        self.credit
            .acknowledged(receipt.rate_bytes_per_second, receipt.expires_at_ms);
        self.positive_until_ms = if !self.retired && receipt.rate_bytes_per_second > 0 {
            receipt.expires_at_ms
        } else {
            0
        };
        true
    }
}

fn session_context(request: &DatapathRelayRequest) -> Option<[u8; FORWARD_ID_BYTES]> {
    let now = unix_millis();
    let context = match request.validated_operation().ok()? {
        DatapathRelayOperation::UdpSessionStart => {
            verified_udp_session_start_scope(request.client_signed_request(), now)?
                .exit
                .route_context_id
        }
        DatapathRelayOperation::MptcpSessionStart => {
            verified_mptcp_session_start_scope(request.client_signed_request(), now)?
                .exit
                .route_context_id
        }
        DatapathRelayOperation::MpquicSessionStart => {
            verified_mpquic_session_start_scope(request.client_signed_request(), now)?
                .exit
                .route_context_id
        }
        _ => return None,
    };
    fixed_bytes(&context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_discovery::UpstreamExitForwardRequest;
    use volparossa_identity::Identity;
    use volparossa_protocol::{Transport, sign_control_message};
    use volparossa_test_support::SignedRouteFixture;

    const NOW: u64 = 1_800_000_000_000;

    #[allow(
        clippy::too_many_lines,
        reason = "one real nested Relay/Exit signed grant and its exact signed budget/receipt"
    )]
    fn signed_exchange(rate: u64) -> (ReceiveLeg, PendingBudget, ExitForwardResponse) {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW).unwrap();
        let relay_key = fixture.relay_key(0).unwrap();
        let mut grant =
            decoded_signed_payload::<RelayReservation>(&fixture.relay_reservations()[0]).unwrap();
        grant.receive_budget_required = true;
        let signed_grant = sign_control_message(
            &grant,
            relay_key,
            grant.created_at_ms,
            grant.expires_at_ms,
            grant.nonce.as_slice().try_into().unwrap(),
            TimePolicy::default(),
        )
        .unwrap();
        let exit_peer = Libp2pPeerId::from_bytes(fixture.exit_peer_id()).unwrap();
        let nonce = generate_nonce();
        let budget = AdjacentReceiveBudget {
            reservation_id: grant.reservation_id.clone(),
            route_context_id: grant.route_context_id.clone(),
            path_id: 1,
            receiver_relay_node_id: grant.relay_node_id.clone(),
            sender_exit_node_id: grant.exit_node_id.clone(),
            relay_reservation_sha256: Sha256::digest(&signed_grant).to_vec(),
            leg: AdjacentReceiveLeg::ExitToRelay as i32,
            sequence: 1,
            rate_bytes_per_second: rate,
            burst_bytes: 2048,
            created_at_ms: NOW,
            expires_at_ms: NOW + 5000,
            nonce: nonce.to_vec(),
        };
        let signed_budget = sign_control_message(
            &budget,
            relay_key,
            NOW,
            budget.expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let request = ExitForwardRequest::new(
            vec![9; 16],
            grant.relay_node_id.clone(),
            grant.relay_peer_id.clone(),
            relay_key.verifying_key().to_bytes().to_vec(),
            grant.exit_peer_id.clone(),
            grant.exit_node_id.clone(),
            budget.expires_at_ms,
            ExitForwardOperation::AdjacentReceiveBudget,
            signed_budget.clone(),
        )
        .unwrap();
        // Exercise canonical request and envelope validation before the actor's response join.
        UpstreamExitForwardRequest::from(request.clone())
            .validate()
            .unwrap();
        let nonce = generate_nonce();
        let receipt = AdjacentReceiveBudgetReceipt {
            receiver_relay_node_id: grant.relay_node_id.clone(),
            sender_exit_node_id: grant.exit_node_id.clone(),
            signed_budget_sha256: Sha256::digest(&signed_budget).to_vec(),
            sequence: budget.sequence,
            rate_bytes_per_second: rate,
            burst_bytes: budget.burst_bytes,
            created_at_ms: NOW,
            expires_at_ms: budget.expires_at_ms,
            nonce: nonce.to_vec(),
        };
        let signed_receipt = sign_control_message(
            &receipt,
            fixture.exit_key(),
            NOW,
            receipt.expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .unwrap();
        let response = ExitForwardResponse::granted(
            request.forward_id().to_vec(),
            ExitForwardOperation::AdjacentReceiveBudget,
            grant.exit_node_id.clone(),
            grant.exit_peer_id.clone(),
            vec![signed_receipt],
        )
        .unwrap();
        let key = (*fixture.route_context_id(), 1);
        (
            ReceiveLeg {
                signed_grant,
                grant,
                exit_peer,
                sequence: 1,
                positive_until_ms: 0,
                credit: BudgetCredit {
                    rate,
                    expires_at_ms: NOW + 5000,
                },
                retired: false,
            },
            PendingBudget {
                key,
                exit_peer,
                request,
                signed_budget,
                deadline_ms: NOW + 1000,
            },
            response,
        )
    }

    #[test]
    fn downlink_start_requires_fresh_positive_exact_signed_receipt() {
        for rate in [0, 1_000_000] {
            let (mut leg, pending, response) = signed_exchange(rate);
            let mut replay = ReplayCache::new(16).unwrap();
            assert!(!leg.ready(NOW));
            assert!(!leg.accept_receipt(
                &pending,
                *Identity::generate().peer_id(),
                &response,
                NOW,
                &mut replay
            ));
            assert!(!leg.ready(NOW));
            assert!(leg.accept_receipt(&pending, pending.exit_peer, &response, NOW, &mut replay));
            assert_eq!(leg.ready(NOW), rate > 0);
            assert!(!leg.accept_receipt(&pending, pending.exit_peer, &response, NOW, &mut replay));
            assert!(!leg.ready(NOW + 4500));
            leg.retired = true;
            assert!(!leg.ready(NOW));
        }
    }

    #[test]
    fn downlink_receipt_cannot_join_other_budget_or_expired_request() {
        let (mut leg, pending, response) = signed_exchange(1_000_000);
        let (_, other, _) = signed_exchange(1_000_000);
        assert!(!leg.accept_receipt(
            &other,
            other.exit_peer,
            &response,
            NOW,
            &mut ReplayCache::new(16).unwrap()
        ));
        assert!(!leg.accept_receipt(
            &pending,
            pending.exit_peer,
            &response,
            pending.deadline_ms,
            &mut ReplayCache::new(16).unwrap()
        ));
        assert!(!leg.ready(NOW));
    }

    #[test]
    fn downlink_aggregate_credit_waits_for_shrink_receipt_or_kernel_expiry() {
        let mut old = BudgetCredit::default();
        old.sent(100, NOW + 5000, NOW);
        old.sent(50, NOW + 5100, NOW + 100);
        // An unacknowledged reduction cannot finance a second leg, including after local retire.
        assert_eq!(100_u64.saturating_sub(old.live(NOW + 200)), 0);
        old.acknowledged(50, NOW + 5100);
        assert_eq!(100_u64.saturating_sub(old.live(NOW + 200)), 50);
        old.sent(100, NOW + 5200, NOW + 200);
        old.sent(0, NOW + 5300, NOW + 300);
        assert_eq!(old.live(NOW + 400), 100);
        assert_eq!(old.live(NOW + 5300), 0);
    }
}
