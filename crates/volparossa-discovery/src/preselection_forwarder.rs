//! Affine control-Relay forwarding for one exact Exit preselection observation.
//!
//! The owner retains the original client response channel while the unchanged canonical request
//! crosses the private Relay-to-Exit protocol. A response can return only through that channel
//! after its Exit signature, replay state, request binding, current Relay authority, and exact
//! upstream connection lineage have all been checked. The resulting wrapper is control-plane
//! evidence only: it grants no readiness, freshness, reservation, route, or datapath authority.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{
    PeerId, identity,
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::ConnectionId,
};
use thiserror::Error;
use tokio::time::Instant;
use volparossa_protocol::{
    ForwardedPreselectionAttestation, ObservationAddressFamily, PreselectionObservationReceipt,
    PreselectionObservationRequest, PreselectionObservationRole, ReplayCache, TimePolicy,
    decode_canonical, preselection_observation_receipt_hash, preselection_observation_request_hash,
    sign_control_message_with, verify_control_message,
};

use crate::{
    ClientPreselectionObservationRequest, ClientPreselectionObservationResponse, DiscoveryService,
    MAX_PRESELECTION_REQUEST_SIZE, PRESELECTION_OBSERVATION_REQUEST_TIMEOUT,
    UpstreamPreselectionObservationRequest, UpstreamPreselectionObservationResponse,
    UpstreamPreselectionTransaction,
    preselection_responder::{LocalPreselectionPolicy, TombstoneError, mint_response_nonce},
    preselection_transaction::consume_bound_upstream_for_forwarded_attestation,
};

const MAX_EXIT_RECEIPT_REPLAYS: usize = 1_024;

/// Detail-free internal rejection at the affine Relay forwarding boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ForwardedPreselectionError {
    #[error("invalid forwarded preselection request")]
    Request,
    #[error("forwarded preselection Relay authority is unavailable")]
    Authority,
    #[error("forwarded preselection transaction is unavailable")]
    Transaction,
    #[error("forwarded preselection response proof is invalid")]
    Proof,
    #[error("forwarded preselection request replay")]
    Replay,
    #[error("forwarded preselection resource limit reached")]
    ResourceLimit,
    #[error("forwarded preselection time is unavailable")]
    Time,
    #[error("forwarded preselection signing failed")]
    Signing,
    #[error("forwarded preselection response channel closed")]
    ResponseChannel,
}

struct ForwardingContext {
    canonical_request: Vec<u8>,
    request: PreselectionObservationRequest,
    downstream_channel: ResponseChannel<ClientPreselectionObservationResponse>,
    authenticated_client: PeerId,
    downstream_connection: ConnectionId,
}

struct PendingForwardedPreselection {
    transaction: UpstreamPreselectionTransaction<ForwardingContext>,
    deadline: Instant,
    policy: LocalPreselectionPolicy,
    signer_public_key: [u8; 32],
    relay_binding: volparossa_protocol::PreselectionActorBinding,
    scope: volparossa_protocol::PreselectionObservationScope,
    downstream_peer: PeerId,
    downstream_connection: ConnectionId,
    downstream_request_id: InboundRequestId,
}

struct ForwardingCompletion {
    deadline: Instant,
    policy: LocalPreselectionPolicy,
    signer_public_key: [u8; 32],
    relay_binding: volparossa_protocol::PreselectionActorBinding,
    downstream_peer: PeerId,
    downstream_connection: ConnectionId,
}

pub(super) struct PreselectionForwarderState {
    pending: Option<PendingForwardedPreselection>,
    exit_receipt_replay: ReplayCache,
}

impl PreselectionForwarderState {
    pub(super) fn new() -> Result<Self, volparossa_protocol::ProtocolError> {
        Ok(Self {
            pending: None,
            exit_receipt_replay: ReplayCache::new(MAX_EXIT_RECEIPT_REPLAYS)?,
        })
    }
}

pub(super) fn client_request_is_forwarded_exit(
    request: &ClientPreselectionObservationRequest,
) -> bool {
    let Ok(request) = decode_canonical::<PreselectionObservationRequest>(
        request.as_encoded(),
        MAX_PRESELECTION_REQUEST_SIZE,
    ) else {
        return false;
    };
    request.validate().is_ok()
        && request.forwarded_control.is_some()
        && request.scope.as_ref().is_some_and(|scope| {
            PreselectionObservationRole::try_from(scope.role)
                == Ok(PreselectionObservationRole::Exit)
        })
}

impl DiscoveryService {
    pub(super) fn forwarded_preselection_pending_deadline(&self) -> Option<Instant> {
        self.preselection_forwarder
            .pending
            .as_ref()
            .map(|pending| pending.deadline)
    }

    pub(super) fn cancel_forwarded_preselection_at_deadline(&mut self, now: Instant) {
        if self
            .preselection_forwarder
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.deadline)
        {
            self.cancel_pending_forwarded_preselection();
        }
    }

    /// Cancel the one service-owned forwarded control request, if present.
    ///
    /// This idempotent lifecycle seam returns no request material, transport proof, identifier, or
    /// response authority. It is used when the role-gated responder pump is disabled or replaced,
    /// so policy revocation cannot retain a downstream channel or occupy the upstream slot.
    pub fn cancel_preselection_forwarding(&mut self) {
        self.cancel_pending_forwarded_preselection();
    }

    pub(super) fn cancel_forwarded_preselection_if_context_changed(
        &mut self,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
    ) {
        let should_cancel = self
            .preselection_forwarder
            .pending
            .as_ref()
            .is_some_and(|pending| {
                if pending.policy != policy || pending.signer_public_key != signer_public_key {
                    return true;
                }
                let Ok(now_ms) = system_unix_millis() else {
                    return true;
                };
                match self.local_relay_authority(policy, signer_public_key, &pending.scope, now_ms)
                {
                    Ok(authority) => authority.actor != pending.relay_binding,
                    Err(_) => true,
                }
            });
        if should_cancel {
            self.cancel_pending_forwarded_preselection();
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one synchronous admission boundary retains every exact downstream and authority input"
    )]
    pub(super) fn begin_forwarded_preselection_event(
        &mut self,
        event: request_response::Event<
            ClientPreselectionObservationRequest,
            ClientPreselectionObservationResponse,
        >,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
    ) -> Result<(), ForwardedPreselectionError> {
        let request_response::Event::Message {
            peer,
            connection_id,
            message:
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                },
        } = event
        else {
            return Err(ForwardedPreselectionError::Request);
        };
        if self.preselection_forwarder.pending.is_some() || !self.protocol_roles().relay() {
            return Err(ForwardedPreselectionError::ResourceLimit);
        }

        let canonical_request = request.as_encoded().to_vec();
        let typed: PreselectionObservationRequest =
            decode_canonical(&canonical_request, MAX_PRESELECTION_REQUEST_SIZE)
                .map_err(|_| ForwardedPreselectionError::Request)?;
        typed
            .validate()
            .map_err(|_| ForwardedPreselectionError::Request)?;
        let scope = typed
            .scope
            .clone()
            .ok_or(ForwardedPreselectionError::Request)?;
        let role = PreselectionObservationRole::try_from(scope.role)
            .map_err(|_| ForwardedPreselectionError::Request)?;
        let control = typed
            .forwarded_control
            .as_ref()
            .ok_or(ForwardedPreselectionError::Request)?;
        let exit = typed
            .actor
            .as_ref()
            .ok_or(ForwardedPreselectionError::Request)?;
        let exit_peer =
            PeerId::from_bytes(&exit.peer_id).map_err(|_| ForwardedPreselectionError::Request)?;
        let now_ms = system_unix_millis()?;
        if role != PreselectionObservationRole::Exit
            || typed.created_at_ms > now_ms
            || now_ms >= typed.expires_at_ms
            || peer == *self.local_peer_id()
            || exit_peer == peer
            || exit_peer == *self.local_peer_id()
            || peer_id_for_actor(exit) != Some(exit_peer)
        {
            return Err(ForwardedPreselectionError::Request);
        }
        let authority = self
            .local_relay_authority(policy, signer_public_key, &scope, now_ms)
            .map_err(|_| ForwardedPreselectionError::Authority)?;
        if control != &authority.actor
            || scope.policy_version != policy.version
            || scope.policy_hash.as_slice() != policy.hash
            || scope.policy_expires_at_ms != policy.expires_at_ms
        {
            return Err(ForwardedPreselectionError::Authority);
        }

        let now_mono = Instant::now();
        let remaining = Duration::from_millis(
            typed
                .expires_at_ms
                .checked_sub(now_ms)
                .ok_or(ForwardedPreselectionError::Time)?,
        );
        let deadline = now_mono
            .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
            .ok_or(ForwardedPreselectionError::Time)?
            .min(
                now_mono
                    .checked_add(remaining)
                    .ok_or(ForwardedPreselectionError::Time)?,
            );
        if deadline <= now_mono {
            return Err(ForwardedPreselectionError::Time);
        }

        let upstream =
            UpstreamPreselectionObservationRequest::from_canonical(canonical_request.clone())
                .map_err(|_| ForwardedPreselectionError::Request)?;
        self.preflight_preselection_observation_upstream(&upstream)
            .map_err(|_| ForwardedPreselectionError::Transaction)?;
        let request_hash = preselection_observation_request_hash(&canonical_request)
            .map_err(|_| ForwardedPreselectionError::Request)?;
        // Spend shared replay capacity only after read-only request, role, target, family, slot,
        // and unique authenticated Exit-provenance admission. The synchronous dispatch below
        // repeats all checks and mints a fresh immediate pre-send witness.
        let replay_reservation = self
            .preselection_responder
            .reserve_tentative(request_hash, peer, now_mono)
            .map_err(forwarded_tombstone_error)?;
        let context = ForwardingContext {
            canonical_request,
            request: typed,
            downstream_channel: channel,
            authenticated_client: peer,
            downstream_connection: connection_id,
        };
        let transaction = if let Ok(transaction) = self
            .dispatch_preselection_observation_upstream_with_context(upstream, deadline, context)
        {
            replay_reservation.commit();
            transaction
        } else {
            let rolled_back = self
                .preselection_responder
                .rollback_tentative(replay_reservation);
            debug_assert!(
                rolled_back,
                "synchronous pre-send failure must own its exact tentative tombstone"
            );
            return Err(ForwardedPreselectionError::Transaction);
        };
        self.preselection_forwarder.pending = Some(PendingForwardedPreselection {
            transaction,
            deadline,
            policy,
            signer_public_key,
            relay_binding: authority.actor,
            scope,
            downstream_peer: peer,
            downstream_connection: connection_id,
            downstream_request_id: request_id,
        });
        Ok(())
    }

    pub(super) fn handle_forwarded_preselection_upstream_response<F>(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        response: UpstreamPreselectionObservationResponse,
        signer: F,
    ) -> bool
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        if !self.forwarded_preselection_owns_upstream_event(peer, request_id) {
            return false;
        }
        let Ok(arrival) =
            self.seal_upstream_preselection_response(peer, connection_id, request_id, response)
        else {
            self.cancel_pending_forwarded_preselection();
            return true;
        };
        let Some(pending) = self.preselection_forwarder.pending.take() else {
            return true;
        };
        let PendingForwardedPreselection {
            transaction,
            deadline,
            policy,
            signer_public_key,
            relay_binding,
            scope: _,
            downstream_peer,
            downstream_connection,
            downstream_request_id: _,
        } = pending;
        let Ok((context, transport, response)) =
            self.bind_preselection_observation_upstream_response_with_context(transaction, arrival)
        else {
            return true;
        };
        let completion = ForwardingCompletion {
            deadline,
            policy,
            signer_public_key,
            relay_binding,
            downstream_peer,
            downstream_connection,
        };
        let _ =
            self.finish_forwarded_preselection(completion, context, transport, response, signer);
        true
    }

    pub(super) fn handle_forwarded_preselection_upstream_failure(
        &mut self,
        peer: PeerId,
        request_id: OutboundRequestId,
    ) -> bool {
        let owns = self.forwarded_preselection_owns_upstream_event(peer, request_id);
        if owns {
            self.cancel_pending_forwarded_preselection();
        }
        owns
    }

    pub(super) fn handle_forwarded_preselection_downstream_failure(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
    ) -> bool {
        let owns =
            self.forwarded_preselection_owns_downstream_event(peer, connection_id, request_id);
        if owns {
            self.cancel_pending_forwarded_preselection();
        }
        owns
    }

    pub(super) fn forwarded_preselection_owns_upstream_event(
        &self,
        peer: PeerId,
        request_id: OutboundRequestId,
    ) -> bool {
        self.preselection_forwarder
            .pending
            .as_ref()
            .is_some_and(|pending| {
                self.upstream_transaction_owns_event(&pending.transaction, peer, request_id)
            })
    }

    pub(super) fn forwarded_preselection_owns_downstream_event(
        &self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
    ) -> bool {
        self.preselection_forwarder
            .pending
            .as_ref()
            .is_some_and(|pending| {
                pending.downstream_request_id == request_id
                    && pending.downstream_peer == peer
                    && pending.downstream_connection == connection_id
            })
    }

    fn cancel_pending_forwarded_preselection(&mut self) {
        if let Some(pending) = self.preselection_forwarder.pending.take() {
            let _ = self.cancel_preselection_observation_upstream_transaction(pending.transaction);
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one exact downstream owner, upstream proof, authority snapshot, and signer remain atomic"
    )]
    fn finish_forwarded_preselection<F>(
        &mut self,
        completion: ForwardingCompletion,
        context: ForwardingContext,
        transport: crate::BoundUpstreamPreselectionTransport,
        response: UpstreamPreselectionObservationResponse,
        signer: F,
    ) -> Result<(), ForwardedPreselectionError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        let ForwardingCompletion {
            deadline,
            policy,
            signer_public_key,
            relay_binding,
            downstream_peer,
            downstream_connection,
        } = completion;
        let now_mono = Instant::now();
        if now_mono >= deadline {
            return Err(ForwardedPreselectionError::Time);
        }
        let now_ms = system_unix_millis()?;
        let scope = context
            .request
            .scope
            .as_ref()
            .ok_or(ForwardedPreselectionError::Request)?;
        if context.request.created_at_ms > now_ms || now_ms >= context.request.expires_at_ms {
            return Err(ForwardedPreselectionError::Time);
        }
        let authority = self
            .local_relay_authority(policy, signer_public_key, scope, now_ms)
            .map_err(|_| ForwardedPreselectionError::Authority)?;
        if authority.actor != relay_binding
            || context.request.forwarded_control.as_ref() != Some(&authority.actor)
            || context.authenticated_client == *self.local_peer_id()
            || context.authenticated_client != downstream_peer
            || context.downstream_connection != downstream_connection
        {
            return Err(ForwardedPreselectionError::Authority);
        }
        let request_hash = preselection_observation_request_hash(&context.canonical_request)
            .map_err(|_| ForwardedPreselectionError::Request)?;
        let prefix =
            consume_bound_upstream_for_forwarded_attestation(transport, request_hash, now_mono)
                .map_err(|_| ForwardedPreselectionError::Proof)?;
        if prefix.address_family != scope.address_family
            || ObservationAddressFamily::try_from(prefix.address_family)
                == Ok(ObservationAddressFamily::Unspecified)
        {
            return Err(ForwardedPreselectionError::Proof);
        }

        let encoded_receipt = response.into_encoded();
        let receipt = verify_exit_receipt_for_request(
            &mut self.preselection_forwarder.exit_receipt_replay,
            &encoded_receipt,
            &context.request,
            request_hash,
            now_ms,
        )?;
        let exit_receipt_hash = preselection_observation_receipt_hash(&encoded_receipt)
            .map_err(|_| ForwardedPreselectionError::Proof)?;
        let control = context
            .request
            .forwarded_control
            .as_ref()
            .ok_or(ForwardedPreselectionError::Request)?;
        let exit = context
            .request
            .actor
            .as_ref()
            .ok_or(ForwardedPreselectionError::Request)?;
        let valid_until_ms = context
            .request
            .expires_at_ms
            .min(receipt.valid_until_ms)
            .min(authority.advertisement.expires_at_ms)
            .min(control.advertisement_expires_at_ms)
            .min(control.capability_expires_at_ms)
            .min(exit.advertisement_expires_at_ms)
            .min(exit.capability_expires_at_ms)
            .min(scope.policy_expires_at_ms)
            .min(policy.expires_at_ms);
        if valid_until_ms <= now_ms {
            return Err(ForwardedPreselectionError::Time);
        }
        let nonce = mint_response_nonce().ok_or(ForwardedPreselectionError::Signing)?;
        let attestation = ForwardedPreselectionAttestation {
            request_hash: request_hash.to_vec(),
            challenge: context.request.challenge.clone(),
            signed_exit_receipt: encoded_receipt,
            exit_receipt_hash: exit_receipt_hash.to_vec(),
            control: Some(control.clone()),
            exit: Some(exit.clone()),
            scope: Some(scope.clone()),
            upstream_network_prefix: Some(prefix),
            observed_at_ms: now_ms,
            valid_until_ms,
            nonce: nonce.to_vec(),
        };
        let encoded_attestation = sign_control_message_with(
            &attestation,
            signer_public_key,
            now_ms,
            valid_until_ms,
            nonce,
            TimePolicy::default(),
            signer,
        )
        .map_err(|_| ForwardedPreselectionError::Signing)?;
        let response = ClientPreselectionObservationResponse::from_canonical(encoded_attestation)
            .map_err(|_| ForwardedPreselectionError::Signing)?;

        self.swarm
            .behaviour_mut()
            .preselection_observation
            .send_response(context.downstream_channel, response)
            .map_err(|_| ForwardedPreselectionError::ResponseChannel)
    }
}

fn verify_exit_receipt_for_request(
    replay: &mut ReplayCache,
    encoded_receipt: &[u8],
    request: &PreselectionObservationRequest,
    request_hash: [u8; 32],
    now_ms: u64,
) -> Result<PreselectionObservationReceipt, ForwardedPreselectionError> {
    let verified = verify_control_message::<PreselectionObservationReceipt>(
        encoded_receipt,
        now_ms,
        TimePolicy::default(),
        replay,
    )
    .map_err(|_| ForwardedPreselectionError::Proof)?;
    let sender = *verified.sender_id();
    let sender_public_key = *verified.sender_public_key();
    let nonce = *verified.nonce();
    let receipt = verified.into_message();
    let matches = request.actor.as_ref().is_some_and(|exit| {
        exit.node_id.as_slice() == sender && exit.public_key.as_slice() == sender_public_key
    }) && request
        .scope
        .as_ref()
        .is_some_and(|scope| scope.role == PreselectionObservationRole::Exit as i32)
        && request.forwarded_control.is_some()
        && receipt.request_hash.as_slice() == request_hash
        && receipt.challenge == request.challenge
        && receipt.actor == request.actor
        && receipt.scope == request.scope
        && receipt.observed_at_ms < receipt.valid_until_ms;
    if matches {
        return Ok(receipt);
    }
    if !replay.rollback(&sender, &nonce) {
        return Err(ForwardedPreselectionError::Proof);
    }
    Err(ForwardedPreselectionError::Proof)
}

fn peer_id_for_actor(actor: &volparossa_protocol::PreselectionActorBinding) -> Option<PeerId> {
    let public_key: [u8; 32] = actor.public_key.as_slice().try_into().ok()?;
    let public_key = identity::ed25519::PublicKey::try_from_bytes(&public_key).ok()?;
    Some(identity::PublicKey::from(public_key).to_peer_id())
}

fn forwarded_tombstone_error(error: TombstoneError) -> ForwardedPreselectionError {
    match error {
        TombstoneError::Replay => ForwardedPreselectionError::Replay,
        TombstoneError::ResourceLimit => ForwardedPreselectionError::ResourceLimit,
        TombstoneError::Time => ForwardedPreselectionError::Time,
    }
}

fn system_unix_millis() -> Result<u64, ForwardedPreselectionError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForwardedPreselectionError::Time)?;
    u64::try_from(duration.as_millis()).map_err(|_| ForwardedPreselectionError::Time)
}

#[cfg(test)]
mod tests {
    use libp2p::identity;
    use volparossa_protocol::{
        PROTOCOL_VERSION, PreselectionActorBinding, PreselectionObservationScope, Transport,
        node_id_from_public_key,
    };

    use super::*;

    const NOW_MS: u64 = 1_000_000;
    const POLICY_EXPIRY_MS: u64 = NOW_MS + 60_000;
    const ADVERTISEMENT_EXPIRY_MS: u64 = NOW_MS + 30_000;

    impl DiscoveryService {
        pub(crate) fn test_forwarded_downstream_identity(
            &self,
        ) -> Option<(PeerId, ConnectionId, InboundRequestId)> {
            self.preselection_forwarder.pending.as_ref().map(|pending| {
                (
                    pending.downstream_peer,
                    pending.downstream_connection,
                    pending.downstream_request_id,
                )
            })
        }
    }

    fn raw_public_key(key: &identity::Keypair) -> [u8; 32] {
        key.public()
            .try_into_ed25519()
            .expect("Ed25519 test key")
            .to_bytes()
    }

    fn sign_with_key(key: &identity::Keypair, message: &[u8]) -> Option<[u8; 64]> {
        key.sign(message).ok()?.try_into().ok()
    }

    fn actor(key: &identity::Keypair, marker: u8) -> PreselectionActorBinding {
        let public_key = raw_public_key(key);
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: key.public().to_peer_id().to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: u64::from(marker),
            advertisement_expires_at_ms: ADVERTISEMENT_EXPIRY_MS,
            advertisement_payload_hash: vec![marker; 32],
            capability_expires_at_ms: ADVERTISEMENT_EXPIRY_MS,
        }
    }

    fn forwarded_request(
        exit: PreselectionActorBinding,
        control: PreselectionActorBinding,
        challenge: u8,
    ) -> PreselectionObservationRequest {
        PreselectionObservationRequest {
            protocol_version: PROTOCOL_VERSION,
            challenge: vec![challenge; 32],
            actor: Some(exit),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Exit as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: 7,
                policy_hash: vec![71; 32],
                policy_expires_at_ms: POLICY_EXPIRY_MS,
            }),
            forwarded_control: Some(control),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 4_000,
        }
    }

    fn signed_receipt(
        exit_key: &identity::Keypair,
        request: &PreselectionObservationRequest,
        request_hash: [u8; 32],
        nonce: u8,
    ) -> Vec<u8> {
        let public_key = raw_public_key(exit_key);
        let receipt = PreselectionObservationReceipt {
            request_hash: request_hash.to_vec(),
            challenge: request.challenge.clone(),
            actor: request.actor.clone(),
            scope: request.scope.clone(),
            observed_at_ms: NOW_MS + 100,
            valid_until_ms: NOW_MS + 4_000,
            nonce: vec![nonce; 32],
        };
        sign_control_message_with(
            &receipt,
            public_key,
            NOW_MS + 100,
            NOW_MS + 4_000,
            [nonce; 32],
            TimePolicy::default(),
            |message| sign_with_key(exit_key, message),
        )
        .expect("signed Exit receipt")
    }

    #[test]
    fn exit_receipt_signature_exact_binding_and_replay_are_atomic() {
        let exit_key = identity::Keypair::generate_ed25519();
        let control_key = identity::Keypair::generate_ed25519();
        let request = forwarded_request(actor(&exit_key, 1), actor(&control_key, 2), 3);
        let canonical =
            volparossa_protocol::encode_canonical(&request, MAX_PRESELECTION_REQUEST_SIZE)
                .expect("canonical request");
        let request_hash = preselection_observation_request_hash(&canonical).expect("request hash");
        let receipt = signed_receipt(&exit_key, &request, request_hash, 4);
        let mut replay = ReplayCache::new(2).expect("replay cache");

        let verified = verify_exit_receipt_for_request(
            &mut replay,
            &receipt,
            &request,
            request_hash,
            NOW_MS + 200,
        )
        .expect("exact Exit receipt");
        assert_eq!(verified.request_hash, request_hash);
        assert_eq!(replay.len(), 1);
        assert_eq!(
            verify_exit_receipt_for_request(
                &mut replay,
                &receipt,
                &request,
                request_hash,
                NOW_MS + 200,
            ),
            Err(ForwardedPreselectionError::Proof)
        );
        assert_eq!(replay.len(), 1);
    }

    #[test]
    fn cross_request_failure_rolls_back_only_its_new_exit_replay_entry() {
        let exit_key = identity::Keypair::generate_ed25519();
        let control_key = identity::Keypair::generate_ed25519();
        let request = forwarded_request(actor(&exit_key, 5), actor(&control_key, 6), 7);
        let canonical =
            volparossa_protocol::encode_canonical(&request, MAX_PRESELECTION_REQUEST_SIZE)
                .expect("canonical request");
        let request_hash = preselection_observation_request_hash(&canonical).expect("request hash");
        let receipt = signed_receipt(&exit_key, &request, request_hash, 8);
        let mut substituted = request.clone();
        substituted.challenge = vec![9; 32];
        let substituted_canonical =
            volparossa_protocol::encode_canonical(&substituted, MAX_PRESELECTION_REQUEST_SIZE)
                .expect("substituted request");
        let substituted_hash = preselection_observation_request_hash(&substituted_canonical)
            .expect("substituted request hash");
        let mut replay = ReplayCache::new(1).expect("replay cache");

        assert_eq!(
            verify_exit_receipt_for_request(
                &mut replay,
                &receipt,
                &substituted,
                substituted_hash,
                NOW_MS + 200,
            ),
            Err(ForwardedPreselectionError::Proof)
        );
        assert!(replay.is_empty(), "failed cross-binding must roll back");
        verify_exit_receipt_for_request(
            &mut replay,
            &receipt,
            &request,
            request_hash,
            NOW_MS + 200,
        )
        .expect("same receipt remains admissible for its exact request");
        assert_eq!(replay.len(), 1);
    }

    #[test]
    fn exit_actor_peer_id_must_derive_from_the_signing_identity() {
        let exit_key = identity::Keypair::generate_ed25519();
        let mut exit = actor(&exit_key, 10);
        assert_eq!(
            peer_id_for_actor(&exit),
            Some(exit_key.public().to_peer_id())
        );
        exit.peer_id = identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_bytes();
        assert_ne!(
            peer_id_for_actor(&exit),
            PeerId::from_bytes(&exit.peer_id).ok()
        );
    }

    #[test]
    fn production_surface_is_purpose_specific_bounded_and_claim_free() {
        let source = include_str!("preselection_forwarder.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [
            "FreshEvidence",
            "CandidateEvidence",
            "ready: true",
            "datapath_ready",
            "direct_exit",
            "pub fn upstream_prefix",
            "pub fn network_prefix",
            "unimplemented!",
            "TODO",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden forwarding authority surface: {forbidden}"
            );
        }
        assert!(production.contains("MAX_EXIT_RECEIPT_REPLAYS: usize = 1_024"));
        assert!(production.contains("verify_control_message::<PreselectionObservationReceipt>"));
        assert!(production.contains("consume_bound_upstream_for_forwarded_attestation"));
        assert!(production.contains("send_response(context.downstream_channel, response)"));
        assert!(production.contains("pub fn cancel_preselection_forwarding"));
        assert!(production.contains("cancel_forwarded_preselection_at_deadline"));
        assert!(production.contains("handle_forwarded_preselection_upstream_failure"));
        assert!(production.contains("handle_forwarded_preselection_downstream_failure"));
        assert!(
            production
                .find("preflight_preselection_observation_upstream(&upstream)")
                .expect("read-only provenance preflight")
                < production
                    .find(".reserve_tentative(request_hash, peer, now_mono)")
                    .expect("shared replay reservation")
        );
        assert!(production.contains(".rollback_tentative(replay_reservation)"));
        assert!(production.contains("replay_reservation.commit()"));
        assert_eq!(production.matches("mint_response_nonce()").count(), 1);
    }
}
