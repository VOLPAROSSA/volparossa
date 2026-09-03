//! Authenticated, role-gated Relay and Exit responders for one exact preselection request.
//!
//! This module signs no measurement and mints no selection, reservation, route, or session
//! authority. It only proves that the current advertised Relay or Exit identity received one
//! exact, short-lived request over the event's still-current authenticated connection lineage.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use libp2p::{PeerId, identity, request_response, swarm::ConnectionId};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::time::Instant;
use volparossa_core::IpFamily;
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, NodeAdvertisement, ObservationAddressFamily,
    PreselectionActorBinding, PreselectionObservationReceipt, PreselectionObservationRequest,
    PreselectionObservationRole, PreselectionObservationScope, ReplayCache, SignedEnvelope,
    TimePolicy, Transport, decode_canonical, node_id_from_public_key,
    preselection_observation_request_hash, sign_control_message_with, verify_control_message,
};

use crate::{
    ClientPreselectionObservationRequest, ClientPreselectionObservationResponse, DiscoveryService,
    MAX_PRESELECTION_REQUEST_SIZE, PreselectionProvenanceReject, PreselectionResponderReject,
    UpstreamPreselectionObservationRequest, UpstreamPreselectionObservationResponse,
    connection_provenance::BoundConnectionObservation,
};

const REQUEST_TOMBSTONE_LIFETIME: Duration = Duration::from_secs(120);
const MAX_REQUEST_TOMBSTONES: usize = 1_024;
const MAX_REQUEST_TOMBSTONES_PER_PEER: usize = 16;
// A live advertisement can legitimately remain selected while the local node
// publishes several capacity refreshes.  Cover the measured alpha refresh
// window while retaining an explicit bound on locally served authorities.
const MAX_LOCAL_ADVERTISEMENT_LINEAGE: usize = 32;

/// Exact active-policy snapshot required before a Relay or Exit may sign an observation receipt.
///
/// Construction alone grants no authority. The responder additionally requires an exact current
/// locally served advertisement, its valid signature, the local libp2p identity, an enabled relay
/// protocol direction, a current authenticated connection, and an exact request binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalPreselectionPolicy {
    pub(super) version: u64,
    pub(super) hash: [u8; 32],
    pub(super) expires_at_ms: u64,
}

impl LocalPreselectionPolicy {
    /// Construct a non-empty active-policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns a policy error for a zero version, zero hash, or zero expiry. Current liveness is
    /// checked atomically by the responder.
    pub fn new(
        version: u64,
        hash: [u8; 32],
        expires_at_ms: u64,
    ) -> Result<Self, DirectPreselectionResponderError> {
        if version == 0 || hash == [0; 32] || expires_at_ms == 0 {
            return Err(DirectPreselectionResponderError::Authority);
        }
        Ok(Self {
            version,
            hash,
            expires_at_ms,
        })
    }
}

/// Detail-free fail-closed rejection at the direct-relay responder boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DirectPreselectionResponderError {
    /// The immutable discovery role does not admit direct-relay responses.
    #[error("direct preselection responder role is disabled")]
    Role,
    /// The request event, canonical bytes, target, scope, or lifetime is invalid.
    #[error("invalid direct preselection observation request")]
    Request,
    /// The exact current local advertisement, policy, or signing identity is unavailable.
    #[error("direct preselection responder authority is unavailable")]
    Authority,
    /// No exact current authenticated event connection proves the request's native family.
    #[error("direct preselection responder provenance is unavailable")]
    Provenance(PreselectionProvenanceReject),
    /// The exact request was already admitted inside the retained tombstone window.
    #[error("direct preselection observation request replay")]
    Replay,
    /// The global or per-peer fixed live-tombstone bound is exhausted.
    #[error("direct preselection responder resource limit reached")]
    ResourceLimit,
    /// Wall or monotonic time is unavailable or cannot represent the fixed window.
    #[error("direct preselection responder time is unavailable")]
    Time,
    /// The external permanent identity refused or emitted an invalid Ed25519 signature.
    #[error("direct preselection observation signing failed")]
    Signing,
    /// The exact response channel closed before the bound response was handed to libp2p.
    #[error("direct preselection observation response channel closed")]
    ResponseChannel,
}

/// Detail-free fail-closed rejection at the upstream Exit responder boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum UpstreamPreselectionResponderError {
    /// The immutable discovery role does not admit upstream Exit responses.
    #[error("upstream preselection responder role is disabled")]
    Role,
    /// The request event, canonical bytes, target, scope, or lifetime is invalid.
    #[error("invalid upstream preselection observation request")]
    Request,
    /// The exact current local advertisement, policy, or signing identity is unavailable.
    #[error("upstream preselection responder authority is unavailable")]
    Authority,
    /// The authenticated Relay or its exact current connection lineage is unavailable.
    #[error("upstream preselection responder provenance is unavailable")]
    Provenance(PreselectionProvenanceReject),
    /// The exact request was already admitted inside the retained tombstone window.
    #[error("upstream preselection observation request replay")]
    Replay,
    /// The global or per-peer fixed live-tombstone bound is exhausted.
    #[error("upstream preselection responder resource limit reached")]
    ResourceLimit,
    /// Wall or monotonic time is unavailable or cannot represent the fixed window.
    #[error("upstream preselection responder time is unavailable")]
    Time,
    /// The external permanent identity refused or emitted an invalid Ed25519 signature.
    #[error("upstream preselection observation signing failed")]
    Signing,
    /// The exact response channel closed before the bound response was handed to libp2p.
    #[error("upstream preselection observation response channel closed")]
    ResponseChannel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TombstoneError {
    Replay,
    ResourceLimit,
    Time,
}

struct RequestTombstone {
    authenticated_peer: PeerId,
    expires_at: Instant,
}

/// Exact newly inserted replay record that has not crossed its no-failure send boundary yet.
#[must_use = "a tentative request tombstone must be committed or rolled back"]
pub(super) struct TentativeRequestTombstone {
    request_hash: [u8; 32],
    authenticated_peer: PeerId,
    expires_at: Instant,
}

impl TentativeRequestTombstone {
    pub(super) fn commit(self) {
        let Self {
            request_hash: _,
            authenticated_peer: _,
            expires_at: _,
        } = self;
    }
}

pub(super) struct PreselectionResponderState {
    requests: HashMap<[u8; 32], RequestTombstone>,
    local_advertisement_lineage: VecDeque<Vec<u8>>,
}

impl PreselectionResponderState {
    pub(super) fn new() -> Self {
        Self {
            requests: HashMap::with_capacity(MAX_REQUEST_TOMBSTONES.min(256)),
            local_advertisement_lineage: VecDeque::with_capacity(MAX_LOCAL_ADVERTISEMENT_LINEAGE),
        }
    }

    pub(super) fn install_local_advertisement(
        &mut self,
        current: &mut Option<Vec<u8>>,
        replacement: Vec<u8>,
    ) {
        if current.as_ref() == Some(&replacement) {
            return;
        }
        if let Some(previous) = current.replace(replacement) {
            self.local_advertisement_lineage
                .retain(|encoded| encoded != &previous);
            self.local_advertisement_lineage.push_back(previous);
            while self.local_advertisement_lineage.len() > MAX_LOCAL_ADVERTISEMENT_LINEAGE {
                self.local_advertisement_lineage.pop_front();
            }
        }
    }

    pub(super) fn clear_local_advertisements(&mut self, current: &mut Option<Vec<u8>>) {
        *current = None;
        self.local_advertisement_lineage.clear();
    }

    pub(super) fn local_advertisement_lineage(&self) -> impl DoubleEndedIterator<Item = &[u8]> {
        self.local_advertisement_lineage.iter().map(Vec::as_slice)
    }

    pub(super) fn reserve(
        &mut self,
        request_hash: [u8; 32],
        authenticated_peer: PeerId,
        now: Instant,
    ) -> Result<(), TombstoneError> {
        self.requests.retain(|_, entry| entry.expires_at > now);
        if self.requests.contains_key(&request_hash) {
            return Err(TombstoneError::Replay);
        }
        if self.requests.len() >= MAX_REQUEST_TOMBSTONES
            || self
                .requests
                .values()
                .filter(|entry| entry.authenticated_peer == authenticated_peer)
                .count()
                >= MAX_REQUEST_TOMBSTONES_PER_PEER
        {
            return Err(TombstoneError::ResourceLimit);
        }
        let expires_at = now
            .checked_add(REQUEST_TOMBSTONE_LIFETIME)
            .ok_or(TombstoneError::Time)?;
        self.requests.insert(
            request_hash,
            RequestTombstone {
                authenticated_peer,
                expires_at,
            },
        );
        Ok(())
    }

    pub(super) fn reserve_tentative(
        &mut self,
        request_hash: [u8; 32],
        authenticated_peer: PeerId,
        now: Instant,
    ) -> Result<TentativeRequestTombstone, TombstoneError> {
        let expires_at = now
            .checked_add(REQUEST_TOMBSTONE_LIFETIME)
            .ok_or(TombstoneError::Time)?;
        self.reserve(request_hash, authenticated_peer, now)?;
        Ok(TentativeRequestTombstone {
            request_hash,
            authenticated_peer,
            expires_at,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "consuming the non-Clone tentative token prevents a second rollback attempt"
    )]
    pub(super) fn rollback_tentative(&mut self, reservation: TentativeRequestTombstone) -> bool {
        let TentativeRequestTombstone {
            request_hash,
            authenticated_peer,
            expires_at,
        } = reservation;
        let matches = self.requests.get(&request_hash).is_some_and(|entry| {
            entry.authenticated_peer == authenticated_peer && entry.expires_at == expires_at
        });
        if matches {
            self.requests.remove(&request_hash);
        }
        matches
    }
}

struct PreparedDirectPreselectionResponse {
    transport_proof: BoundConnectionObservation,
    response: ClientPreselectionObservationResponse,
}

struct PreparedUpstreamPreselectionResponse {
    transport_proof: BoundConnectionObservation,
    response: UpstreamPreselectionObservationResponse,
}

pub(super) struct LocalPreselectionAuthority {
    pub(super) actor: PreselectionActorBinding,
    pub(super) advertisement: NodeAdvertisement,
}

#[derive(Clone, Copy)]
enum LocalResponderRole {
    Relay,
    Exit,
}

impl DiscoveryService {
    /// Advance discovery while internally handling direct-Relay and upstream-Exit requests.
    ///
    /// A request event never crosses the caller boundary: this method obtains it directly from
    /// this service's swarm and immediately passes it to the private responder. Consequently a
    /// libp2p response channel, whose request and connection identifiers are only behaviour-local,
    /// cannot be transplanted between `DiscoveryService` instances. Rejected requests are dropped
    /// without a response and polling continues until another discovery event is available.
    ///
    /// The supplied signing closure should delegate to the same permanent Ed25519 identity used
    /// to build this discovery service. The agent discovery actor calls this seam only while an
    /// immutable Relay or Exit role and a currently active threshold-verified policy snapshot are
    /// present. Each responder independently requires its exact current locally served role
    /// advertisement before it can emit a response. An upstream Exit emits only its signed
    /// receipt; on the Relay, the same private pump may verify that receipt and mint the bounded
    /// forwarded control wrapper. Neither result is usable evidence, readiness, or datapath state.
    #[allow(
        clippy::too_many_lines,
        reason = "one private event owner routes three exact preselection directions and cleanup events"
    )]
    pub async fn next_event_with_preselection_responders<F>(
        &mut self,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        signer: &mut F,
    ) -> crate::DiscoveryEvent
    where
        F: FnMut(&[u8]) -> Option<[u8; 64]>,
    {
        loop {
            self.cancel_forwarded_preselection_if_context_changed(policy, signer_public_key);
            self.cancel_forwarded_preselection_at_deadline(Instant::now());
            let event = if let Some(deadline) = self.forwarded_preselection_pending_deadline() {
                tokio::select! {
                    event = self.next_internal_event() => Some(event),
                    () = tokio::time::sleep_until(deadline) => None,
                }
            } else {
                Some(self.next_internal_event().await)
            };
            let Some(event) = event else {
                self.cancel_forwarded_preselection_at_deadline(Instant::now());
                continue;
            };
            match event {
                libp2p::swarm::SwarmEvent::Behaviour(
                    crate::BehaviourEvent::PreselectionObservation(
                        event @ request_response::Event::Message {
                            message: request_response::Message::Request { .. },
                            ..
                        },
                    ),
                ) => {
                    if matches!(
                        &event,
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, .. },
                            ..
                        } if crate::preselection_forwarder::client_request_is_forwarded_exit(request)
                    ) {
                        if let Err(error) = self.begin_forwarded_preselection_event(
                            event,
                            policy,
                            signer_public_key,
                        ) {
                            return crate::DiscoveryEvent::PreselectionResponderRejected(
                                Self::forwarded_reject(error),
                            );
                        }
                    } else if let Err(error) = self.respond_direct_preselection_observation_event(
                        event,
                        policy,
                        signer_public_key,
                        |message| signer(message),
                    ) {
                        return crate::DiscoveryEvent::PreselectionResponderRejected(
                            Self::direct_reject(error),
                        );
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(
                    crate::BehaviourEvent::PreselectionObservationUpstream(
                        event @ request_response::Event::Message {
                            message: request_response::Message::Request { .. },
                            ..
                        },
                    ),
                ) => {
                    if let Err(error) = self.respond_upstream_preselection_observation_event(
                        event,
                        policy,
                        signer_public_key,
                        |message| signer(message),
                    ) {
                        return crate::DiscoveryEvent::PreselectionResponderRejected(
                            Self::upstream_reject(error),
                        );
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(
                    crate::BehaviourEvent::PreselectionObservationUpstream(
                        request_response::Event::Message {
                            peer,
                            connection_id,
                            message:
                                request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                        },
                    ),
                ) if self.forwarded_preselection_owns_upstream_event(peer, request_id) => {
                    if let Err(error) = self.handle_forwarded_preselection_upstream_response(
                        peer,
                        connection_id,
                        request_id,
                        response,
                        |message| signer(message),
                    ) {
                        return crate::DiscoveryEvent::PreselectionResponderRejected(
                            Self::forwarded_reject(error),
                        );
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(
                    crate::BehaviourEvent::PreselectionObservationUpstream(
                        event @ request_response::Event::OutboundFailure {
                            peer, request_id, ..
                        },
                    ),
                ) if self.forwarded_preselection_owns_upstream_event(peer, request_id) => {
                    let _ = self.handle_forwarded_preselection_upstream_failure(peer, request_id);
                    drop(event);
                    return crate::DiscoveryEvent::PreselectionResponderRejected(
                        PreselectionResponderReject::ForwardedUpstreamTransport,
                    );
                }
                libp2p::swarm::SwarmEvent::Behaviour(
                    crate::BehaviourEvent::PreselectionObservation(
                        event @ request_response::Event::InboundFailure {
                            peer,
                            connection_id,
                            request_id,
                            ..
                        },
                    ),
                ) if self.forwarded_preselection_owns_downstream_event(
                    peer,
                    connection_id,
                    request_id,
                ) =>
                {
                    let _ = self.handle_forwarded_preselection_downstream_failure(
                        peer,
                        connection_id,
                        request_id,
                    );
                    drop(event);
                }
                event => {
                    if let Some(event) = self.sanitize_public_event(event) {
                        return event;
                    }
                }
            }
        }
    }

    fn direct_reject(error: DirectPreselectionResponderError) -> PreselectionResponderReject {
        match error {
            DirectPreselectionResponderError::Role => PreselectionResponderReject::DirectRole,
            DirectPreselectionResponderError::Request => PreselectionResponderReject::DirectRequest,
            DirectPreselectionResponderError::Authority => {
                PreselectionResponderReject::DirectAuthority
            }
            DirectPreselectionResponderError::Provenance(reason) => {
                PreselectionResponderReject::DirectProvenance(reason)
            }
            DirectPreselectionResponderError::Replay => PreselectionResponderReject::DirectReplay,
            DirectPreselectionResponderError::ResourceLimit => {
                PreselectionResponderReject::DirectResourceLimit
            }
            DirectPreselectionResponderError::Time => PreselectionResponderReject::DirectTime,
            DirectPreselectionResponderError::Signing => PreselectionResponderReject::DirectSigning,
            DirectPreselectionResponderError::ResponseChannel => {
                PreselectionResponderReject::DirectResponseChannel
            }
        }
    }

    fn upstream_reject(error: UpstreamPreselectionResponderError) -> PreselectionResponderReject {
        match error {
            UpstreamPreselectionResponderError::Role => PreselectionResponderReject::UpstreamRole,
            UpstreamPreselectionResponderError::Request => {
                PreselectionResponderReject::UpstreamRequest
            }
            UpstreamPreselectionResponderError::Authority => {
                PreselectionResponderReject::UpstreamAuthority
            }
            UpstreamPreselectionResponderError::Provenance(reason) => {
                PreselectionResponderReject::UpstreamProvenance(reason)
            }
            UpstreamPreselectionResponderError::Replay => {
                PreselectionResponderReject::UpstreamReplay
            }
            UpstreamPreselectionResponderError::ResourceLimit => {
                PreselectionResponderReject::UpstreamResourceLimit
            }
            UpstreamPreselectionResponderError::Time => PreselectionResponderReject::UpstreamTime,
            UpstreamPreselectionResponderError::Signing => {
                PreselectionResponderReject::UpstreamSigning
            }
            UpstreamPreselectionResponderError::ResponseChannel => {
                PreselectionResponderReject::UpstreamResponseChannel
            }
        }
    }

    fn forwarded_reject(
        error: crate::preselection_forwarder::ForwardedPreselectionError,
    ) -> PreselectionResponderReject {
        use crate::preselection_forwarder::ForwardedPreselectionError;

        match error {
            ForwardedPreselectionError::Request => PreselectionResponderReject::ForwardedRequest,
            ForwardedPreselectionError::Authority => {
                PreselectionResponderReject::ForwardedAuthority
            }
            ForwardedPreselectionError::Transaction => {
                PreselectionResponderReject::ForwardedTransaction
            }
            ForwardedPreselectionError::Proof => PreselectionResponderReject::ForwardedProof,
            ForwardedPreselectionError::Replay => PreselectionResponderReject::ForwardedReplay,
            ForwardedPreselectionError::ResourceLimit => {
                PreselectionResponderReject::ForwardedResourceLimit
            }
            ForwardedPreselectionError::Time => PreselectionResponderReject::ForwardedTime,
            ForwardedPreselectionError::Signing => PreselectionResponderReject::ForwardedSigning,
            ForwardedPreselectionError::ResponseChannel => {
                PreselectionResponderReject::ForwardedResponseChannel
            }
        }
    }

    /// Validate, connection-bind, replay-admit, sign, and send one direct-relay observation reply.
    ///
    /// This remains private so the raw behaviour-local event and response channel can only arrive
    /// through `next_event_with_preselection_responders`. The responder verifies the
    /// returned signature and binds it to the exact currently served signed advertisement before
    /// emitting canonical bytes. There is no suspension point between the connection-lineage check
    /// and response handoff.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for a non-request event, disabled role, malformed or stale
    /// request, local authority mismatch, stale exact connection lineage, replay or bounded
    /// resource exhaustion, invalid signature, unavailable time, or a closed response channel.
    fn respond_direct_preselection_observation_event<F>(
        &mut self,
        event: request_response::Event<
            ClientPreselectionObservationRequest,
            ClientPreselectionObservationResponse,
        >,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        signer: F,
    ) -> Result<(), DirectPreselectionResponderError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        let request_response::Event::Message {
            peer,
            connection_id,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
        } = event
        else {
            return Err(DirectPreselectionResponderError::Request);
        };
        let now_ms = system_unix_millis()?;
        let prepared = self.prepare_direct_preselection_response_at(
            peer,
            connection_id,
            &request,
            policy,
            signer_public_key,
            signer,
            now_ms,
            Instant::now(),
        )?;
        let PreparedDirectPreselectionResponse {
            transport_proof,
            response,
        } = prepared;
        let sent = self
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_response(channel, response)
            .map_err(|_| DirectPreselectionResponderError::ResponseChannel);
        drop(transport_proof);
        sent
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one exact event, policy, signer, and dual-clock transaction boundary"
    )]
    fn prepare_direct_preselection_response_at<F>(
        &mut self,
        authenticated_peer: PeerId,
        connection_id: ConnectionId,
        request: &ClientPreselectionObservationRequest,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        signer: F,
        now_ms: u64,
        now_mono: Instant,
    ) -> Result<PreparedDirectPreselectionResponse, DirectPreselectionResponderError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        if !self.protocol_roles.relay() {
            return Err(DirectPreselectionResponderError::Role);
        }
        let canonical_request = request.as_encoded();
        let typed: PreselectionObservationRequest =
            decode_canonical(canonical_request, MAX_PRESELECTION_REQUEST_SIZE)
                .map_err(|_| DirectPreselectionResponderError::Request)?;
        typed
            .validate()
            .map_err(|_| DirectPreselectionResponderError::Request)?;
        let scope = typed
            .scope
            .as_ref()
            .ok_or(DirectPreselectionResponderError::Request)?;
        let role = PreselectionObservationRole::try_from(scope.role)
            .map_err(|_| DirectPreselectionResponderError::Request)?;
        let family = observation_family(scope)?;
        if role != PreselectionObservationRole::Relay
            || typed.forwarded_control.is_some()
            || typed.created_at_ms > now_ms
            || now_ms >= typed.expires_at_ms
            || authenticated_peer == *self.local_peer_id()
        {
            return Err(DirectPreselectionResponderError::Request);
        }
        let actor = typed
            .actor
            .as_ref()
            .ok_or(DirectPreselectionResponderError::Request)?;
        let authority =
            self.local_relay_authority_for_actor(policy, signer_public_key, scope, actor, now_ms)?;
        if actor != &authority.actor
            || scope.policy_version != policy.version
            || scope.policy_hash.as_slice() != policy.hash
            || scope.policy_expires_at_ms != policy.expires_at_ms
        {
            return Err(DirectPreselectionResponderError::Authority);
        }

        let provenance = &self.swarm.behaviour().connection_provenance;
        let witness = provenance
            .exact_witness(authenticated_peer, connection_id, family)
            .ok_or_else(|| {
                DirectPreselectionResponderError::Provenance(
                    provenance.diagnose_preselection_reject(
                        authenticated_peer,
                        family,
                        connection_id,
                    ),
                )
            })?;
        let transport = provenance
            .bind(witness, authenticated_peer, connection_id)
            .ok_or_else(|| {
                DirectPreselectionResponderError::Provenance(
                    provenance.diagnose_preselection_reject(
                        authenticated_peer,
                        family,
                        connection_id,
                    ),
                )
            })?;
        let request_hash = preselection_observation_request_hash(canonical_request)
            .map_err(|_| DirectPreselectionResponderError::Request)?;
        self.preselection_responder
            .reserve(request_hash, authenticated_peer, now_mono)
            .map_err(direct_tombstone_error)?;

        let valid_until_ms = typed
            .expires_at_ms
            .min(authority.advertisement.expires_at_ms)
            .min(policy.expires_at_ms);
        if valid_until_ms <= now_ms {
            return Err(DirectPreselectionResponderError::Time);
        }
        let nonce = mint_response_nonce().ok_or(DirectPreselectionResponderError::Signing)?;
        let receipt = PreselectionObservationReceipt {
            request_hash: request_hash.to_vec(),
            challenge: typed.challenge.clone(),
            actor: typed.actor.clone(),
            scope: typed.scope.clone(),
            observed_at_ms: now_ms,
            valid_until_ms,
            nonce: nonce.to_vec(),
        };
        let encoded_response = sign_control_message_with(
            &receipt,
            signer_public_key,
            now_ms,
            valid_until_ms,
            nonce,
            TimePolicy::default(),
            signer,
        )
        .map_err(|_| DirectPreselectionResponderError::Signing)?;
        let response = ClientPreselectionObservationResponse::from_canonical(encoded_response)
            .map_err(|_| DirectPreselectionResponderError::Signing)?;
        Ok(PreparedDirectPreselectionResponse {
            transport_proof: transport,
            response,
        })
    }

    /// Validate, connection-bind, replay-admit, sign, and send one upstream Exit reply.
    ///
    /// The raw event and response channel stay private to the service that observed them. The
    /// authenticated remote must be the exact Ed25519-derived `forwarded_control` Relay, while the
    /// challenged actor must be this service's exact active Exit advertisement. There is no
    /// suspension point between lineage binding and response handoff.
    fn respond_upstream_preselection_observation_event<F>(
        &mut self,
        event: request_response::Event<
            UpstreamPreselectionObservationRequest,
            UpstreamPreselectionObservationResponse,
        >,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        signer: F,
    ) -> Result<(), UpstreamPreselectionResponderError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        let request_response::Event::Message {
            peer,
            connection_id,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
        } = event
        else {
            return Err(UpstreamPreselectionResponderError::Request);
        };
        let now_ms = system_unix_millis().map_err(|_| UpstreamPreselectionResponderError::Time)?;
        let prepared = self.prepare_upstream_preselection_response_at(
            peer,
            connection_id,
            &request,
            policy,
            signer_public_key,
            signer,
            now_ms,
            Instant::now(),
        )?;
        let PreparedUpstreamPreselectionResponse {
            transport_proof,
            response,
        } = prepared;
        let sent = self
            .swarm
            .behaviour_mut()
            .preselection_observation_upstream
            .send_response(channel, response)
            .map_err(|_| UpstreamPreselectionResponderError::ResponseChannel);
        drop(transport_proof);
        sent
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one exact event, policy, signer, and dual-clock transaction boundary"
    )]
    fn prepare_upstream_preselection_response_at<F>(
        &mut self,
        authenticated_relay: PeerId,
        connection_id: ConnectionId,
        request: &UpstreamPreselectionObservationRequest,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        signer: F,
        now_ms: u64,
        now_mono: Instant,
    ) -> Result<PreparedUpstreamPreselectionResponse, UpstreamPreselectionResponderError>
    where
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        if !self.protocol_roles.exit() {
            return Err(UpstreamPreselectionResponderError::Role);
        }
        let canonical_request = request.as_encoded();
        let typed: PreselectionObservationRequest =
            decode_canonical(canonical_request, MAX_PRESELECTION_REQUEST_SIZE)
                .map_err(|_| UpstreamPreselectionResponderError::Request)?;
        typed
            .validate()
            .map_err(|_| UpstreamPreselectionResponderError::Request)?;
        let scope = typed
            .scope
            .as_ref()
            .ok_or(UpstreamPreselectionResponderError::Request)?;
        let role = PreselectionObservationRole::try_from(scope.role)
            .map_err(|_| UpstreamPreselectionResponderError::Request)?;
        let family = upstream_observation_family(scope)?;
        let control = typed
            .forwarded_control
            .as_ref()
            .ok_or(UpstreamPreselectionResponderError::Request)?;
        let exit = typed
            .actor
            .as_ref()
            .ok_or(UpstreamPreselectionResponderError::Request)?;
        if role != PreselectionObservationRole::Exit
            || typed.created_at_ms > now_ms
            || now_ms >= typed.expires_at_ms
            || authenticated_relay == *self.local_peer_id()
            || control.peer_id != authenticated_relay.to_bytes()
            || peer_id_for_actor(control) != Some(authenticated_relay)
        {
            return Err(UpstreamPreselectionResponderError::Request);
        }
        let authority = self.local_exit_authority_for_actor(
            policy,
            signer_public_key,
            scope,
            control.capability_expires_at_ms,
            exit,
            now_ms,
        )?;
        if exit != &authority.actor
            || scope.policy_version != policy.version
            || scope.policy_hash.as_slice() != policy.hash
            || scope.policy_expires_at_ms != policy.expires_at_ms
        {
            return Err(UpstreamPreselectionResponderError::Authority);
        }

        let provenance = &self.swarm.behaviour().connection_provenance;
        let witness = provenance
            .exact_witness(authenticated_relay, connection_id, family)
            .ok_or_else(|| {
                UpstreamPreselectionResponderError::Provenance(
                    provenance.diagnose_preselection_reject(
                        authenticated_relay,
                        family,
                        connection_id,
                    ),
                )
            })?;
        let transport = provenance
            .bind(witness, authenticated_relay, connection_id)
            .ok_or_else(|| {
                UpstreamPreselectionResponderError::Provenance(
                    provenance.diagnose_preselection_reject(
                        authenticated_relay,
                        family,
                        connection_id,
                    ),
                )
            })?;
        let request_hash = preselection_observation_request_hash(canonical_request)
            .map_err(|_| UpstreamPreselectionResponderError::Request)?;
        self.preselection_responder
            .reserve(request_hash, authenticated_relay, now_mono)
            .map_err(upstream_tombstone_error)?;

        let valid_until_ms = typed
            .expires_at_ms
            .min(authority.advertisement.expires_at_ms)
            .min(authority.actor.capability_expires_at_ms)
            .min(policy.expires_at_ms);
        if valid_until_ms <= now_ms {
            return Err(UpstreamPreselectionResponderError::Time);
        }
        let nonce = mint_response_nonce().ok_or(UpstreamPreselectionResponderError::Signing)?;
        let receipt = PreselectionObservationReceipt {
            request_hash: request_hash.to_vec(),
            challenge: typed.challenge.clone(),
            actor: typed.actor.clone(),
            scope: typed.scope.clone(),
            observed_at_ms: now_ms,
            valid_until_ms,
            nonce: nonce.to_vec(),
        };
        let encoded_response = sign_control_message_with(
            &receipt,
            signer_public_key,
            now_ms,
            valid_until_ms,
            nonce,
            TimePolicy::default(),
            signer,
        )
        .map_err(|_| UpstreamPreselectionResponderError::Signing)?;
        let response = UpstreamPreselectionObservationResponse::from_canonical(encoded_response)
            .map_err(|_| UpstreamPreselectionResponderError::Signing)?;
        Ok(PreparedUpstreamPreselectionResponse {
            transport_proof: transport,
            response,
        })
    }

    pub(super) fn local_relay_authority(
        &self,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        scope: &PreselectionObservationScope,
        now_ms: u64,
    ) -> Result<LocalPreselectionAuthority, DirectPreselectionResponderError> {
        self.local_preselection_authority(
            policy,
            signer_public_key,
            scope,
            now_ms,
            LocalResponderRole::Relay,
        )
        .ok_or(DirectPreselectionResponderError::Authority)
    }

    pub(super) fn local_relay_authority_for_actor(
        &self,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        scope: &PreselectionObservationScope,
        expected: &PreselectionActorBinding,
        now_ms: u64,
    ) -> Result<LocalPreselectionAuthority, DirectPreselectionResponderError> {
        if let Ok(authority) = self.local_relay_authority(policy, signer_public_key, scope, now_ms)
        {
            if &authority.actor == expected {
                return Ok(authority);
            }
        }
        self.preselection_responder
            .local_advertisement_lineage()
            .rev()
            .find_map(|encoded| {
                self.local_preselection_authority_from_encoded(
                    encoded,
                    policy,
                    signer_public_key,
                    scope,
                    now_ms,
                    LocalResponderRole::Relay,
                )
                .filter(|authority| &authority.actor == expected)
            })
            .ok_or(DirectPreselectionResponderError::Authority)
    }

    fn local_exit_authority_for_actor(
        &self,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        scope: &PreselectionObservationScope,
        control_capability_expires_at_ms: u64,
        expected: &PreselectionActorBinding,
        now_ms: u64,
    ) -> Result<LocalPreselectionAuthority, UpstreamPreselectionResponderError> {
        let constrain = |mut authority: LocalPreselectionAuthority| {
            authority.actor.capability_expires_at_ms = authority
                .actor
                .capability_expires_at_ms
                .min(control_capability_expires_at_ms);
            (authority.actor == *expected).then_some(authority)
        };
        self.local_preselection_authority(
            policy,
            signer_public_key,
            scope,
            now_ms,
            LocalResponderRole::Exit,
        )
        .and_then(constrain)
        .or_else(|| {
            self.preselection_responder
                .local_advertisement_lineage()
                .rev()
                .find_map(|encoded| {
                    self.local_preselection_authority_from_encoded(
                        encoded,
                        policy,
                        signer_public_key,
                        scope,
                        now_ms,
                        LocalResponderRole::Exit,
                    )
                    .and_then(constrain)
                })
        })
        .ok_or(UpstreamPreselectionResponderError::Authority)
    }

    fn local_preselection_authority(
        &self,
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        scope: &PreselectionObservationScope,
        now_ms: u64,
        required_role: LocalResponderRole,
    ) -> Option<LocalPreselectionAuthority> {
        let encoded = self.local_advertisement.as_deref()?;
        self.local_preselection_authority_from_encoded(
            encoded,
            policy,
            signer_public_key,
            scope,
            now_ms,
            required_role,
        )
    }

    fn local_preselection_authority_from_encoded(
        &self,
        encoded: &[u8],
        policy: LocalPreselectionPolicy,
        signer_public_key: [u8; 32],
        scope: &PreselectionObservationScope,
        now_ms: u64,
        required_role: LocalResponderRole,
    ) -> Option<LocalPreselectionAuthority> {
        let envelope: SignedEnvelope = decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE).ok()?;
        let mut replay = ReplayCache::new(1).ok()?;
        let verified = verify_control_message::<NodeAdvertisement>(
            encoded,
            now_ms,
            TimePolicy::default(),
            &mut replay,
        )
        .ok()?;
        let advertisement = verified.into_message();
        let local_peer = peer_id_for_ed25519(&signer_public_key)?;
        let roles = advertisement.roles.as_ref()?;
        let capabilities = advertisement.capabilities.as_ref()?;
        let advertised_policy = advertisement.policy.as_ref()?;
        let network = advertisement.network.as_ref()?;
        let payload_hash: [u8; 32] = envelope.payload_hash.as_slice().try_into().ok()?;
        let role_enabled = match required_role {
            LocalResponderRole::Relay => roles.relay,
            LocalResponderRole::Exit => roles.exit,
        };
        if *self.local_peer_id() != local_peer
            || verified_sender_mismatch(&envelope, &signer_public_key)
            || advertisement.node_id != node_id_from_public_key(&signer_public_key)
            || advertisement.peer_id != local_peer.to_bytes()
            || advertisement.sequence_number == 0
            || !role_enabled
            || network.asn == 0
            || payload_hash == [0; 32]
            || advertised_policy.whitelist_version != policy.version
            || advertised_policy.whitelist_hash.as_slice() != policy.hash
            || policy.expires_at_ms <= now_ms
            || advertisement.expires_at_ms > policy.expires_at_ms
            || !capability_supports_scope(capabilities, scope)
        {
            return None;
        }
        let actor = PreselectionActorBinding {
            node_id: advertisement.node_id.clone(),
            peer_id: advertisement.peer_id.clone(),
            public_key: signer_public_key.to_vec(),
            advertisement_sequence: advertisement.sequence_number,
            advertisement_expires_at_ms: advertisement.expires_at_ms,
            advertisement_payload_hash: payload_hash.to_vec(),
            capability_expires_at_ms: advertisement.expires_at_ms.min(policy.expires_at_ms),
        };
        Some(LocalPreselectionAuthority {
            actor,
            advertisement,
        })
    }
}

fn direct_tombstone_error(error: TombstoneError) -> DirectPreselectionResponderError {
    match error {
        TombstoneError::Replay => DirectPreselectionResponderError::Replay,
        TombstoneError::ResourceLimit => DirectPreselectionResponderError::ResourceLimit,
        TombstoneError::Time => DirectPreselectionResponderError::Time,
    }
}

fn upstream_tombstone_error(error: TombstoneError) -> UpstreamPreselectionResponderError {
    match error {
        TombstoneError::Replay => UpstreamPreselectionResponderError::Replay,
        TombstoneError::ResourceLimit => UpstreamPreselectionResponderError::ResourceLimit,
        TombstoneError::Time => UpstreamPreselectionResponderError::Time,
    }
}

fn verified_sender_mismatch(envelope: &SignedEnvelope, public_key: &[u8; 32]) -> bool {
    envelope.sender_public_key.as_slice() != public_key
        || envelope.sender_id != node_id_from_public_key(public_key)
}

fn peer_id_for_ed25519(public_key: &[u8; 32]) -> Option<PeerId> {
    let public_key = identity::ed25519::PublicKey::try_from_bytes(public_key).ok()?;
    Some(identity::PublicKey::from(public_key).to_peer_id())
}

fn peer_id_for_actor(actor: &PreselectionActorBinding) -> Option<PeerId> {
    let public_key: [u8; 32] = actor.public_key.as_slice().try_into().ok()?;
    peer_id_for_ed25519(&public_key)
}

fn observation_family(
    scope: &PreselectionObservationScope,
) -> Result<IpFamily, DirectPreselectionResponderError> {
    match ObservationAddressFamily::try_from(scope.address_family)
        .map_err(|_| DirectPreselectionResponderError::Request)?
    {
        ObservationAddressFamily::Ipv4 => Ok(IpFamily::Ipv4),
        ObservationAddressFamily::Ipv6 => Ok(IpFamily::Ipv6),
        ObservationAddressFamily::Unspecified => Err(DirectPreselectionResponderError::Request),
    }
}

fn upstream_observation_family(
    scope: &PreselectionObservationScope,
) -> Result<IpFamily, UpstreamPreselectionResponderError> {
    match ObservationAddressFamily::try_from(scope.address_family)
        .map_err(|_| UpstreamPreselectionResponderError::Request)?
    {
        ObservationAddressFamily::Ipv4 => Ok(IpFamily::Ipv4),
        ObservationAddressFamily::Ipv6 => Ok(IpFamily::Ipv6),
        ObservationAddressFamily::Unspecified => Err(UpstreamPreselectionResponderError::Request),
    }
}

fn capability_supports_scope(
    capabilities: &volparossa_protocol::AdvertisementCapabilities,
    scope: &PreselectionObservationScope,
) -> bool {
    let family_supported = match ObservationAddressFamily::try_from(scope.address_family) {
        Ok(ObservationAddressFamily::Ipv4) => capabilities.ipv4,
        Ok(ObservationAddressFamily::Ipv6) => capabilities.ipv6,
        Ok(ObservationAddressFamily::Unspecified) | Err(_) => false,
    };
    let transport_supported = match Transport::try_from(scope.transport) {
        Ok(Transport::TcpMptcp) => capabilities.tcp_mptcp,
        Ok(Transport::UdpSinglePath) => capabilities.udp_single_path,
        Ok(Transport::MultipathQuic) => capabilities.multipath_quic,
        Ok(Transport::Unspecified) | Err(_) => false,
    };
    family_supported && transport_supported
}

fn system_unix_millis() -> Result<u64, DirectPreselectionResponderError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DirectPreselectionResponderError::Time)?;
    u64::try_from(duration.as_millis()).map_err(|_| DirectPreselectionResponderError::Time)
}

pub(super) fn mint_response_nonce() -> Option<[u8; 32]> {
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce).ok()?;
    if nonce == [0; 32] {
        return None;
    }
    Some(nonce)
}

#[cfg(test)]
mod tests {
    use std::mem::size_of_val;

    use libp2p::{
        Multiaddr,
        core::{ConnectedPoint, Endpoint, transport::PortUse},
        swarm::{
            AddressChange, FromSwarm, NetworkBehaviour, SwarmEvent,
            behaviour::ConnectionEstablished,
        },
    };
    use volparossa_protocol::{
        AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork,
        AdvertisementPolicy, AdvertisementQuality, AdvertisementRoles, ControlPayload,
        ForwardedPreselectionAttestation, MAX_CONTROL_PAYLOAD_SIZE, encode_canonical,
        verify_direct_preselection_transcript, verify_forwarded_preselection_transcript,
    };

    use super::*;
    use crate::{BehaviourEvent, DiscoveryEvent, DiscoveryProtocolRoles};

    const NOW_MS: u64 = 1_000_000;
    const CONNECTION: usize = 41;
    const POLICY_VERSION: u64 = 7;
    const POLICY_HASH: [u8; 32] = [71; 32];
    const POLICY_EXPIRY_MS: u64 = NOW_MS + 60_000;
    const ADVERTISEMENT_EXPIRY_MS: u64 = NOW_MS + 30_000;
    const CONTROL_ADVERTISEMENT_EXPIRY_MS: u64 = ADVERTISEMENT_EXPIRY_MS - 1_000;

    async fn next_other(service: &mut DiscoveryService) -> SwarmEvent<BehaviourEvent> {
        loop {
            if let DiscoveryEvent::Other(event) = service.next_event().await {
                return event;
            }
        }
    }

    struct Fixture {
        service: DiscoveryService,
        relay_key: identity::Keypair,
        relay_public_key: [u8; 32],
        client_peer: PeerId,
        actor: PreselectionActorBinding,
        policy: LocalPreselectionPolicy,
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

    fn relay_advertisement(
        relay_key: &identity::Keypair,
        relay_public_key: [u8; 32],
    ) -> NodeAdvertisement {
        NodeAdvertisement {
            node_id: node_id_from_public_key(&relay_public_key).to_vec(),
            peer_id: relay_key.public().to_peer_id().to_bytes(),
            sequence_number: 12,
            roles: Some(AdvertisementRoles {
                client: true,
                relay: true,
                exit: false,
            }),
            capabilities: Some(AdvertisementCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: true,
                ipv6: true,
                udp_hole_punching: true,
            }),
            control_addresses: vec!["/ip4/8.8.4.4/udp/4001/quic-v1".to_owned()],
            capacity: Some(AdvertisementCapacity {
                operator_relay_limit_up_mbps: 100,
                operator_relay_limit_down_mbps: 100,
                operator_exit_limit_up_mbps: 0,
                operator_exit_limit_down_mbps: 0,
                currently_reserved_up_mbps: 0,
                currently_reserved_down_mbps: 0,
                estimated_free_up_mbps: 100,
                estimated_free_down_mbps: 100,
                active_relay_sessions: 0,
                active_exit_sessions: 0,
                free_relay_slots: 4,
                free_exit_slots: 0,
                sample_window_seconds: 15,
            }),
            network: Some(AdvertisementNetwork {
                region: "eu-west".to_owned(),
                country_code: "NL".to_owned(),
                asn: 64_496,
                ipv4_prefix_hint: "8.8.4.0/24".to_owned(),
                ipv6_prefix_hint: String::new(),
                operator_id: "operator-responder".to_owned(),
            }),
            quality: Some(AdvertisementQuality {
                local_uptime_seconds: 60,
                historical_uptime_ppm: 0,
                historical_delivery_ratio_p25_ppm: 0,
            }),
            policy: Some(AdvertisementPolicy {
                whitelist_version: POLICY_VERSION,
                whitelist_hash: POLICY_HASH.to_vec(),
            }),
            measured_at_ms: NOW_MS,
            expires_at_ms: ADVERTISEMENT_EXPIRY_MS,
        }
    }

    fn exit_advertisement(
        exit_key: &identity::Keypair,
        exit_public_key: [u8; 32],
    ) -> NodeAdvertisement {
        let mut advertisement = relay_advertisement(exit_key, exit_public_key);
        advertisement.roles = Some(AdvertisementRoles {
            client: false,
            relay: false,
            exit: true,
        });
        let capacity = advertisement
            .capacity
            .as_mut()
            .expect("advertisement capacity");
        capacity.operator_relay_limit_up_mbps = 0;
        capacity.operator_relay_limit_down_mbps = 0;
        capacity.operator_exit_limit_up_mbps = 100;
        capacity.operator_exit_limit_down_mbps = 100;
        capacity.free_relay_slots = 0;
        capacity.free_exit_slots = 4;
        advertisement
    }

    fn actor_for(
        key: &identity::Keypair,
        public_key: [u8; 32],
        sequence: u64,
        payload_hash: [u8; 32],
        expires_at_ms: u64,
    ) -> PreselectionActorBinding {
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: key.public().to_peer_id().to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: sequence,
            advertisement_expires_at_ms: expires_at_ms,
            advertisement_payload_hash: payload_hash.to_vec(),
            capability_expires_at_ms: expires_at_ms,
        }
    }

    fn listener(remote: &str) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/4001"
                .parse::<Multiaddr>()
                .expect("local multiaddr"),
            send_back_addr: remote.parse::<Multiaddr>().expect("remote multiaddr"),
        }
    }

    fn dialer(remote: &str) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: remote.parse::<Multiaddr>().expect("remote multiaddr"),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        }
    }

    fn establish(
        service: &mut DiscoveryService,
        peer: PeerId,
        connection: usize,
        endpoint: &ConnectedPoint,
        other_established: usize,
    ) {
        service
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: peer,
                connection_id: ConnectionId::new_unchecked(connection),
                endpoint,
                failed_addresses: &[],
                other_established,
            }));
    }

    async fn fixture() -> Fixture {
        tokio::task::yield_now().await;
        let relay_key = identity::Keypair::generate_ed25519();
        let relay_public_key = raw_public_key(&relay_key);
        let advertisement = relay_advertisement(&relay_key, relay_public_key);
        advertisement.validate().expect("valid advertisement");
        let signed = sign_control_message_with(
            &advertisement,
            relay_public_key,
            NOW_MS,
            ADVERTISEMENT_EXPIRY_MS,
            [19; 32],
            TimePolicy::default(),
            |message| sign_with_key(&relay_key, message),
        )
        .expect("signed local advertisement");
        let envelope: SignedEnvelope =
            decode_canonical(&signed, MAX_CONTROL_MESSAGE_SIZE).expect("signed envelope");
        let policy = LocalPreselectionPolicy::new(POLICY_VERSION, POLICY_HASH, POLICY_EXPIRY_MS)
            .expect("policy");
        let actor = PreselectionActorBinding {
            node_id: advertisement.node_id.clone(),
            peer_id: advertisement.peer_id.clone(),
            public_key: relay_public_key.to_vec(),
            advertisement_sequence: advertisement.sequence_number,
            advertisement_expires_at_ms: advertisement.expires_at_ms,
            advertisement_payload_hash: envelope.payload_hash,
            capability_expires_at_ms: ADVERTISEMENT_EXPIRY_MS,
        };
        let mut service = DiscoveryService::new_with_protocol_roles(
            relay_key.clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("relay discovery");
        service
            .set_local_advertisement(signed)
            .expect("serve local advertisement");
        let client_peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        establish(
            &mut service,
            client_peer,
            CONNECTION,
            &listener("/ip4/1.1.1.8/tcp/443"),
            0,
        );
        Fixture {
            service,
            relay_key,
            relay_public_key,
            client_peer,
            actor,
            policy,
        }
    }

    struct UpstreamFixture {
        service: DiscoveryService,
        exit_key: identity::Keypair,
        exit_public_key: [u8; 32],
        relay_peer: PeerId,
        exit_actor: PreselectionActorBinding,
        control_actor: PreselectionActorBinding,
        policy: LocalPreselectionPolicy,
    }

    async fn upstream_fixture() -> UpstreamFixture {
        tokio::task::yield_now().await;
        let exit_key = identity::Keypair::generate_ed25519();
        let exit_public_key = raw_public_key(&exit_key);
        let advertisement = exit_advertisement(&exit_key, exit_public_key);
        advertisement.validate().expect("valid Exit advertisement");
        let signed = sign_control_message_with(
            &advertisement,
            exit_public_key,
            NOW_MS,
            ADVERTISEMENT_EXPIRY_MS,
            [61; 32],
            TimePolicy::default(),
            |message| sign_with_key(&exit_key, message),
        )
        .expect("signed local Exit advertisement");
        let envelope: SignedEnvelope =
            decode_canonical(&signed, MAX_CONTROL_MESSAGE_SIZE).expect("signed envelope");
        let mut exit_actor = actor_for(
            &exit_key,
            exit_public_key,
            advertisement.sequence_number,
            envelope
                .payload_hash
                .as_slice()
                .try_into()
                .expect("payload hash"),
            ADVERTISEMENT_EXPIRY_MS,
        );
        exit_actor.capability_expires_at_ms = CONTROL_ADVERTISEMENT_EXPIRY_MS;
        let relay_key = identity::Keypair::generate_ed25519();
        let relay_public_key = raw_public_key(&relay_key);
        let relay_peer = relay_key.public().to_peer_id();
        let control_actor = actor_for(
            &relay_key,
            relay_public_key,
            13,
            [62; 32],
            CONTROL_ADVERTISEMENT_EXPIRY_MS,
        );
        let mut service = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("Exit discovery");
        service
            .set_local_advertisement(signed)
            .expect("serve local Exit advertisement");
        establish(
            &mut service,
            relay_peer,
            CONNECTION,
            &listener("/ip4/1.1.1.8/tcp/443"),
            0,
        );
        UpstreamFixture {
            service,
            exit_key,
            exit_public_key,
            relay_peer,
            exit_actor,
            control_actor,
            policy: LocalPreselectionPolicy::new(POLICY_VERSION, POLICY_HASH, POLICY_EXPIRY_MS)
                .expect("policy"),
        }
    }

    async fn connect_and_capture_listener_lineage(
        client: &mut DiscoveryService,
        relay: &mut DiscoveryService,
    ) -> (ConnectionId, ConnectedPoint) {
        relay
            .listen_on("/memory/0".parse::<Multiaddr>().expect("memory address"))
            .expect("memory listener");
        let address = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = next_other(relay).await {
                    break address;
                }
            }
        })
        .await
        .expect("listener address timeout");
        let relay_peer = *relay.local_peer_id();
        let client_peer = *client.local_peer_id();
        client
            .dial_peerlink(&crate::PeerLink::new(relay_peer, address).expect("memory peerlink"))
            .expect("memory dial");

        tokio::time::timeout(Duration::from_secs(5), async {
            let mut client_connected = false;
            let mut relay_lineage = None;
            while !client_connected || relay_lineage.is_none() {
                tokio::select! {
                    event = next_other(client) => {
                        if matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == relay_peer
                        ) {
                            client_connected = true;
                        }
                    }
                    event = next_other(relay) => {
                        if let SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            ..
                        } = event {
                            if peer_id == client_peer {
                                relay_lineage = Some((connection_id, endpoint));
                            }
                        }
                    }
                }
            }
            relay_lineage.expect("relay lineage")
        })
        .await
        .expect("memory connection timeout")
    }

    async fn connect_and_capture_both_lineages(
        dialling: &mut DiscoveryService,
        listening: &mut DiscoveryService,
    ) -> (
        (ConnectionId, ConnectedPoint),
        (ConnectionId, ConnectedPoint),
    ) {
        listening
            .listen_on("/memory/0".parse::<Multiaddr>().expect("memory address"))
            .expect("memory listener");
        let address = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = next_other(listening).await {
                    break address;
                }
            }
        })
        .await
        .expect("listener address timeout");
        let listening_peer = *listening.local_peer_id();
        let dialling_peer = *dialling.local_peer_id();
        dialling
            .dial_peerlink(&crate::PeerLink::new(listening_peer, address).expect("memory peerlink"))
            .expect("memory dial");

        tokio::time::timeout(Duration::from_secs(5), async {
            let mut dialling_lineage = None;
            let mut listening_lineage = None;
            while dialling_lineage.is_none() || listening_lineage.is_none() {
                tokio::select! {
                    event = next_other(dialling) => {
                        if let SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            ..
                        } = event
                        {
                            if peer_id == listening_peer {
                                dialling_lineage = Some((connection_id, endpoint));
                            }
                        }
                    }
                    event = next_other(listening) => {
                        if let SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            ..
                        } = event
                        {
                            if peer_id == dialling_peer {
                                listening_lineage = Some((connection_id, endpoint));
                            }
                        }
                    }
                }
            }
            (
                dialling_lineage.expect("dialling lineage"),
                listening_lineage.expect("listening lineage"),
            )
        })
        .await
        .expect("memory connection timeout")
    }

    fn send_forwarded_control_request(
        client: &mut DiscoveryService,
        relay_peer: PeerId,
        template: &PreselectionObservationRequest,
        challenge: u8,
    ) -> request_response::OutboundRequestId {
        let mut request = template.clone();
        let now_ms = system_unix_millis().expect("request wall time");
        request.challenge = vec![challenge; 32];
        request.created_at_ms = now_ms;
        request.expires_at_ms = now_ms + 4_000;
        let canonical = encode_canonical(&request, MAX_CONTROL_PAYLOAD_SIZE)
            .expect("canonical forwarded request");
        let wire = ClientPreselectionObservationRequest::from_canonical(canonical)
            .expect("forwarded request wrapper");
        client
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&relay_peer, wire)
    }

    async fn drive_client_relay_until_forwarding_pending(
        client: &mut DiscoveryService,
        relay: &mut DiscoveryService,
        policy: LocalPreselectionPolicy,
        relay_public_key: [u8; 32],
        relay_key: &identity::Keypair,
    ) {
        for _ in 0..32 {
            if relay.forwarded_preselection_pending_deadline().is_some() {
                return;
            }
            let mut signer = |message: &[u8]| sign_with_key(relay_key, message);
            let _ = tokio::time::timeout(Duration::from_millis(50), async {
                tokio::select! {
                    _ = client.next_internal_event() => {}
                    _ = relay.next_event_with_preselection_responders(
                        policy,
                        relay_public_key,
                        &mut signer,
                    ) => {}
                }
            })
            .await;
        }
        assert!(
            relay.forwarded_preselection_pending_deadline().is_some(),
            "Relay must retain the exact forwarded owner before the bounded test deadline"
        );
    }

    fn request(
        actor: PreselectionActorBinding,
        challenge: u8,
        family: ObservationAddressFamily,
    ) -> ClientPreselectionObservationRequest {
        let request = PreselectionObservationRequest {
            protocol_version: volparossa_protocol::PROTOCOL_VERSION,
            challenge: vec![challenge; 32],
            actor: Some(actor),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Relay as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: family as i32,
                policy_version: POLICY_VERSION,
                policy_hash: POLICY_HASH.to_vec(),
                policy_expires_at_ms: POLICY_EXPIRY_MS,
            }),
            forwarded_control: None,
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 4_000,
        };
        ClientPreselectionObservationRequest::from_canonical(
            encode_canonical(&request, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical request"),
        )
        .expect("wire request")
    }

    fn upstream_request(
        exit: PreselectionActorBinding,
        control: PreselectionActorBinding,
        challenge: u8,
        family: ObservationAddressFamily,
    ) -> UpstreamPreselectionObservationRequest {
        let request = PreselectionObservationRequest {
            protocol_version: volparossa_protocol::PROTOCOL_VERSION,
            challenge: vec![challenge; 32],
            actor: Some(exit),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Exit as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: family as i32,
                policy_version: POLICY_VERSION,
                policy_hash: POLICY_HASH.to_vec(),
                policy_expires_at_ms: POLICY_EXPIRY_MS,
            }),
            forwarded_control: Some(control),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 4_000,
        };
        UpstreamPreselectionObservationRequest::from_canonical(
            encode_canonical(&request, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical request"),
        )
        .expect("wire upstream request")
    }

    fn rejection(
        result: Result<PreparedDirectPreselectionResponse, DirectPreselectionResponderError>,
        context: &str,
    ) -> DirectPreselectionResponderError {
        result
            .err()
            .unwrap_or_else(|| panic!("unexpected prepared response: {context}"))
    }

    fn upstream_rejection(
        result: Result<PreparedUpstreamPreselectionResponse, UpstreamPreselectionResponderError>,
        context: &str,
    ) -> UpstreamPreselectionResponderError {
        result
            .err()
            .unwrap_or_else(|| panic!("unexpected prepared upstream response: {context}"))
    }

    #[tokio::test]
    async fn exact_current_direct_request_is_signed_and_cryptographically_verifiable() {
        let mut fixture = fixture().await;
        let request = request(fixture.actor.clone(), 21, ObservationAddressFamily::Ipv4);
        let canonical_request = request.as_encoded().to_vec();
        let prepared = fixture
            .service
            .prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request,
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            )
            .expect("prepared response");
        assert!(size_of_val(&prepared.transport_proof) > 0);
        let signed = prepared.response.as_encoded();
        let envelope: SignedEnvelope =
            decode_canonical(signed, MAX_CONTROL_MESSAGE_SIZE).expect("canonical response");
        assert_eq!(
            envelope.message_type,
            volparossa_protocol::ControlMessageType::PreselectionObservationReceipt as i32
        );
        assert_eq!(envelope.sender_public_key, fixture.relay_public_key);
        assert_eq!(envelope.timestamp_ms, NOW_MS + 100);
        assert_eq!(envelope.expires_at_ms, NOW_MS + 4_000);
        assert_ne!(envelope.payload_hash, vec![0; 32]);
        assert_ne!(envelope.nonce, vec![0; 32]);
        assert_eq!(envelope.signature.len(), 64);
        let mut replay = ReplayCache::new(2).expect("replay cache");
        verify_direct_preselection_transcript(
            signed,
            &canonical_request,
            NOW_MS + 200,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("complete direct transcript");
    }

    #[tokio::test]
    async fn exact_current_upstream_request_is_exit_signed_and_request_bound() {
        let mut fixture = upstream_fixture().await;
        assert!(
            fixture.control_actor.capability_expires_at_ms
                < fixture.exit_actor.advertisement_expires_at_ms
        );
        assert_eq!(
            fixture.exit_actor.capability_expires_at_ms,
            fixture.control_actor.capability_expires_at_ms
        );
        let request = upstream_request(
            fixture.exit_actor.clone(),
            fixture.control_actor.clone(),
            63,
            ObservationAddressFamily::Ipv4,
        );
        let canonical_request = request.as_encoded().to_vec();
        let prepared = fixture
            .service
            .prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request,
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            )
            .expect("prepared upstream response");
        assert!(size_of_val(&prepared.transport_proof) > 0);
        let signed = prepared.response.as_encoded();
        let envelope: SignedEnvelope =
            decode_canonical(signed, MAX_CONTROL_MESSAGE_SIZE).expect("canonical response");
        assert_eq!(
            envelope.message_type,
            volparossa_protocol::ControlMessageType::PreselectionObservationReceipt as i32
        );
        assert_eq!(envelope.sender_public_key, fixture.exit_public_key);
        assert_eq!(envelope.timestamp_ms, NOW_MS + 100);
        assert_eq!(envelope.expires_at_ms, NOW_MS + 4_000);
        let mut replay = ReplayCache::new(2).expect("replay cache");
        let receipt = verify_control_message::<PreselectionObservationReceipt>(
            signed,
            NOW_MS + 200,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("verified Exit receipt")
        .into_message();
        assert_eq!(
            receipt.request_hash,
            preselection_observation_request_hash(&canonical_request)
                .expect("request hash")
                .to_vec()
        );
        assert_eq!(receipt.challenge, vec![63; 32]);
        assert_eq!(receipt.actor, Some(fixture.exit_actor));
        assert_eq!(
            receipt.scope.expect("receipt scope").role,
            PreselectionObservationRole::Exit as i32
        );
    }

    #[tokio::test]
    async fn upstream_role_and_signing_failure_fail_closed_and_tombstone_exact_replay() {
        let mut fixture = upstream_fixture().await;
        let request = upstream_request(
            fixture.exit_actor.clone(),
            fixture.control_actor.clone(),
            73,
            ObservationAddressFamily::Ipv4,
        );
        let signing = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request,
                fixture.policy,
                fixture.exit_public_key,
                |_| None,
                NOW_MS + 100,
                Instant::now(),
            ),
            "upstream signer refusal",
        );
        assert_eq!(signing, UpstreamPreselectionResponderError::Signing);
        let replay = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request,
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 200,
                Instant::now(),
            ),
            "upstream replay after signer refusal",
        );
        assert_eq!(replay, UpstreamPreselectionResponderError::Replay);

        let mut relay_only = DiscoveryService::new_with_protocol_roles(
            fixture.exit_key.clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("Relay-only discovery");
        let role = upstream_rejection(
            relay_only.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request,
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 200,
                Instant::now(),
            ),
            "upstream responder disabled by immutable role",
        );
        assert_eq!(role, UpstreamPreselectionResponderError::Role);
    }

    #[tokio::test]
    async fn upstream_responder_enforces_the_shared_exact_per_relay_bound_without_eviction() {
        let mut fixture = upstream_fixture().await;
        let now_mono = Instant::now();
        for offset in 0..MAX_REQUEST_TOMBSTONES_PER_PEER {
            let challenge = u8::try_from(offset + 80).expect("bounded challenge");
            let prepared = fixture
                .service
                .prepare_upstream_preselection_response_at(
                    fixture.relay_peer,
                    ConnectionId::new_unchecked(CONNECTION),
                    &upstream_request(
                        fixture.exit_actor.clone(),
                        fixture.control_actor.clone(),
                        challenge,
                        ObservationAddressFamily::Ipv4,
                    ),
                    fixture.policy,
                    fixture.exit_public_key,
                    |message| sign_with_key(&fixture.exit_key, message),
                    NOW_MS + 100,
                    now_mono,
                )
                .expect("within exact per-Relay tombstone bound");
            drop(prepared);
        }
        let resource = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    fixture.exit_actor,
                    fixture.control_actor,
                    120,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                now_mono,
            ),
            "seventeenth live upstream request",
        );
        assert_eq!(resource, UpstreamPreselectionResponderError::ResourceLimit);
        assert_eq!(
            fixture.service.preselection_responder.requests.len(),
            MAX_REQUEST_TOMBSTONES_PER_PEER
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial matrix for authenticated Relay and exact Exit authority"
    )]
    async fn upstream_relay_identity_policy_exit_authority_and_lineage_are_exact() {
        let mut fixture = upstream_fixture().await;
        let wrong_relay = identity::Keypair::generate_ed25519();
        let wrong_relay_peer = wrong_relay.public().to_peer_id();
        let wrong_authenticated = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                wrong_relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    fixture.exit_actor.clone(),
                    fixture.control_actor.clone(),
                    64,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted authenticated Relay",
        );
        assert_eq!(
            wrong_authenticated,
            UpstreamPreselectionResponderError::Request
        );

        let mut peer_key_substitution = fixture.control_actor.clone();
        let substituted_public = raw_public_key(&wrong_relay);
        peer_key_substitution.public_key = substituted_public.to_vec();
        peer_key_substitution.node_id = node_id_from_public_key(&substituted_public).to_vec();
        let peer_key_substitution = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    fixture.exit_actor.clone(),
                    peer_key_substitution,
                    65,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "Relay public key does not derive authenticated Peer ID",
        );
        assert_eq!(
            peer_key_substitution,
            UpstreamPreselectionResponderError::Request
        );

        let mut substituted_exit = fixture.exit_actor.clone();
        substituted_exit.advertisement_payload_hash[0] ^= 1;
        let authority_substitution = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    substituted_exit,
                    fixture.control_actor.clone(),
                    66,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted Exit advertisement",
        );
        assert_eq!(
            authority_substitution,
            UpstreamPreselectionResponderError::Authority
        );

        let wrong_policy =
            LocalPreselectionPolicy::new(POLICY_VERSION + 1, POLICY_HASH, POLICY_EXPIRY_MS)
                .expect("shaped policy");
        let policy_substitution = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    fixture.exit_actor.clone(),
                    fixture.control_actor.clone(),
                    67,
                    ObservationAddressFamily::Ipv4,
                ),
                wrong_policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted active policy",
        );
        assert_eq!(
            policy_substitution,
            UpstreamPreselectionResponderError::Authority
        );

        let wrong_connection = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION + 1),
                &upstream_request(
                    fixture.exit_actor.clone(),
                    fixture.control_actor.clone(),
                    68,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted event connection",
        );
        assert_eq!(
            wrong_connection,
            UpstreamPreselectionResponderError::Provenance(
                PreselectionProvenanceReject::ExactConnectionMissing
            )
        );

        let wrong_family = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    fixture.exit_actor,
                    fixture.control_actor,
                    69,
                    ObservationAddressFamily::Ipv6,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted native family",
        );
        assert_eq!(
            wrong_family,
            UpstreamPreselectionResponderError::Provenance(
                PreselectionProvenanceReject::FamilyPrefix
            )
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one complete real two-swarm request, responder handoff, and signature transcript"
    )]
    async fn service_owned_poll_sends_the_exact_signed_response_over_the_originating_channel() {
        let relay_key = identity::Keypair::generate_ed25519();
        let relay_public_key = raw_public_key(&relay_key);
        let client_key = identity::Keypair::generate_ed25519();
        let mut relay = DiscoveryService::new_with_protocol_roles(
            relay_key.clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("relay discovery");
        let mut client = DiscoveryService::new_with_protocol_roles(
            client_key,
            DiscoveryProtocolRoles::new(true, false, false),
        )
        .expect("client discovery");
        let client_peer = *client.local_peer_id();
        let relay_peer = *relay.local_peer_id();
        let now_ms = system_unix_millis().expect("current wall time");
        let advertisement_expiry = now_ms + 30_000;
        let policy_expiry = now_ms + 60_000;
        let mut advertisement = relay_advertisement(&relay_key, relay_public_key);
        advertisement.measured_at_ms = now_ms;
        advertisement.expires_at_ms = advertisement_expiry;
        let signed_advertisement = sign_control_message_with(
            &advertisement,
            relay_public_key,
            now_ms,
            advertisement_expiry,
            [43; 32],
            TimePolicy::default(),
            |message| sign_with_key(&relay_key, message),
        )
        .expect("signed current advertisement");
        let advertisement_envelope: SignedEnvelope =
            decode_canonical(&signed_advertisement, MAX_CONTROL_MESSAGE_SIZE)
                .expect("advertisement envelope");
        relay
            .set_local_advertisement(signed_advertisement.clone())
            .expect("serve advertisement");
        let actor = PreselectionActorBinding {
            node_id: advertisement.node_id.clone(),
            peer_id: advertisement.peer_id.clone(),
            public_key: relay_public_key.to_vec(),
            advertisement_sequence: advertisement.sequence_number,
            advertisement_expires_at_ms: advertisement_expiry,
            advertisement_payload_hash: advertisement_envelope.payload_hash,
            capability_expires_at_ms: advertisement_expiry,
        };
        let policy = LocalPreselectionPolicy::new(POLICY_VERSION, POLICY_HASH, policy_expiry)
            .expect("current policy");
        let typed_request = PreselectionObservationRequest {
            protocol_version: volparossa_protocol::PROTOCOL_VERSION,
            challenge: vec![44; 32],
            actor: Some(actor),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Relay as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: POLICY_VERSION,
                policy_hash: POLICY_HASH.to_vec(),
                policy_expires_at_ms: policy_expiry,
            }),
            forwarded_control: None,
            created_at_ms: now_ms,
            expires_at_ms: now_ms + 4_000,
        };
        let canonical_request =
            encode_canonical(&typed_request, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical request");
        let wire_request =
            ClientPreselectionObservationRequest::from_canonical(canonical_request.clone())
                .expect("wire request");

        let (relay_connection, old_endpoint) =
            connect_and_capture_listener_lineage(&mut client, &mut relay).await;
        let public_endpoint = listener("/ip4/1.1.1.8/tcp/443");
        relay
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: client_peer,
                connection_id: relay_connection,
                old: &old_endpoint,
                new: &public_endpoint,
            }));
        let outbound = client
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&relay_peer, wire_request);
        let mut signer = |message: &[u8]| sign_with_key(&relay_key, message);

        let signed_response = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    event = client.next_internal_event() => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                    ..
                                },
                            )) if peer == relay_peer && request_id == outbound => {
                                break response;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                },
                            )) if request_id == outbound => {
                                panic!("response transport failed: {error}");
                            }
                            _ => {}
                        }
                    }
                    _ = relay.next_event_with_preselection_responders(
                        policy,
                        relay_public_key,
                        &mut signer,
                    ) => {}
                }
            }
        })
        .await
        .expect("signed response timeout");
        let mut response_replay_cache = ReplayCache::new(2).expect("response replay cache");
        verify_direct_preselection_transcript(
            signed_response.as_encoded(),
            &canonical_request,
            system_unix_millis().expect("verification wall time"),
            TimePolicy::default(),
            &mut response_replay_cache,
        )
        .expect("originating channel response transcript");

        let mut transplanted_request = typed_request;
        transplanted_request.challenge = vec![45; 32];
        let transplanted_request = ClientPreselectionObservationRequest::from_canonical(
            encode_canonical(&transplanted_request, MAX_CONTROL_PAYLOAD_SIZE)
                .expect("canonical transplant request"),
        )
        .expect("wire transplant request");
        let transplanted_outbound = client
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&relay_peer, transplanted_request);
        let raw_event = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    event = client.next_internal_event() => {
                        if let SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservation(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                },
                            ),
                        ) = event
                        {
                            assert_ne!(
                                request_id,
                                transplanted_outbound,
                                "transplant request failed before capture: {error}"
                            );
                        }
                    }
                    event = relay.next_internal_event() => {
                        if let SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservation(
                                event @ request_response::Event::Message {
                                    message: request_response::Message::Request { .. },
                                    ..
                                },
                            ),
                        ) = event
                        {
                            break event;
                        }
                    }
                }
            }
        })
        .await
        .expect("raw originating request capture timeout");

        let mut sibling = DiscoveryService::new_with_protocol_roles(
            relay_key.clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("sibling relay discovery");
        sibling
            .set_local_advertisement(signed_advertisement)
            .expect("sibling advertisement");
        assert_eq!(
            sibling.respond_direct_preselection_observation_event(
                raw_event,
                policy,
                relay_public_key,
                |message| sign_with_key(&relay_key, message),
            ),
            Err(DirectPreselectionResponderError::Provenance(
                PreselectionProvenanceReject::ExactConnectionMissing
            )),
            "a sibling service has no originating connection lineage and cannot answer"
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) = client.next_internal_event().await
                {
                    if request_id == transplanted_outbound {
                        break;
                    }
                }
            }
        })
        .await
        .expect("transplanted response channel omission timeout");
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one complete real Relay-to-Exit request, response handoff, and signature proof"
    )]
    async fn service_owned_poll_sends_exit_receipt_only_to_the_authenticated_relay_channel() {
        let exit_key = identity::Keypair::generate_ed25519();
        let exit_public_key = raw_public_key(&exit_key);
        let relay_key = identity::Keypair::generate_ed25519();
        let relay_public_key = raw_public_key(&relay_key);
        let mut exit = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("Exit discovery");
        let mut relay = DiscoveryService::new_with_protocol_roles(
            relay_key.clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("Relay discovery");
        let relay_peer = *relay.local_peer_id();
        let exit_peer = *exit.local_peer_id();
        let now_ms = system_unix_millis().expect("current wall time");
        let advertisement_expiry = now_ms + 30_000;
        let policy_expiry = now_ms + 60_000;
        let mut advertisement = exit_advertisement(&exit_key, exit_public_key);
        advertisement.measured_at_ms = now_ms;
        advertisement.expires_at_ms = advertisement_expiry;
        let signed_advertisement = sign_control_message_with(
            &advertisement,
            exit_public_key,
            now_ms,
            advertisement_expiry,
            [70; 32],
            TimePolicy::default(),
            |message| sign_with_key(&exit_key, message),
        )
        .expect("signed current Exit advertisement");
        let envelope: SignedEnvelope =
            decode_canonical(&signed_advertisement, MAX_CONTROL_MESSAGE_SIZE)
                .expect("advertisement envelope");
        exit.set_local_advertisement(signed_advertisement)
            .expect("serve Exit advertisement");
        let exit_actor = actor_for(
            &exit_key,
            exit_public_key,
            advertisement.sequence_number,
            envelope
                .payload_hash
                .as_slice()
                .try_into()
                .expect("payload hash"),
            advertisement_expiry,
        );
        let control_actor = actor_for(
            &relay_key,
            relay_public_key,
            14,
            [71; 32],
            advertisement_expiry,
        );
        let typed_request = PreselectionObservationRequest {
            protocol_version: volparossa_protocol::PROTOCOL_VERSION,
            challenge: vec![72; 32],
            actor: Some(exit_actor),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Exit as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: POLICY_VERSION,
                policy_hash: POLICY_HASH.to_vec(),
                policy_expires_at_ms: policy_expiry,
            }),
            forwarded_control: Some(control_actor),
            created_at_ms: now_ms,
            expires_at_ms: now_ms + 4_000,
        };
        let canonical_request =
            encode_canonical(&typed_request, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical request");
        let wire_request =
            UpstreamPreselectionObservationRequest::from_canonical(canonical_request.clone())
                .expect("wire request");
        let policy = LocalPreselectionPolicy::new(POLICY_VERSION, POLICY_HASH, policy_expiry)
            .expect("current policy");

        let (exit_connection, old_endpoint) =
            connect_and_capture_listener_lineage(&mut relay, &mut exit).await;
        let public_endpoint = listener("/ip4/1.1.1.8/tcp/443");
        exit.swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: relay_peer,
                connection_id: exit_connection,
                old: &old_endpoint,
                new: &public_endpoint,
            }));
        let outbound = relay
            .swarm
            .behaviour_mut()
            .preselection_observation_upstream
            .send_request(&exit_peer, wire_request);
        let mut signer = |message: &[u8]| sign_with_key(&exit_key, message);
        let signed_response = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    event = relay.next_internal_event() => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                    ..
                                },
                            )) if peer == exit_peer && request_id == outbound => {
                                break response;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                },
                            )) if request_id == outbound => {
                                panic!("upstream response transport failed: {error}");
                            }
                            _ => {}
                        }
                    }
                    _ = exit.next_event_with_preselection_responders(
                        policy,
                        exit_public_key,
                        &mut signer,
                    ) => {}
                }
            }
        })
        .await
        .expect("Exit response timeout");
        let mut response_replay_cache = ReplayCache::new(2).expect("response replay cache");
        let receipt = verify_control_message::<PreselectionObservationReceipt>(
            signed_response.as_encoded(),
            system_unix_millis().expect("verification wall time"),
            TimePolicy::default(),
            &mut response_replay_cache,
        )
        .expect("Exit-signed receipt")
        .into_message();
        assert_eq!(
            receipt.request_hash,
            preselection_observation_request_hash(&canonical_request)
                .expect("request hash")
                .to_vec()
        );
        assert_eq!(
            receipt.scope.expect("receipt scope").role,
            PreselectionObservationRole::Exit as i32
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one complete hermetic three-swarm affine control transaction plus failure cleanup"
    )]
    async fn affine_relay_owner_returns_one_verified_exit_wrapper_only_to_the_original_client() {
        let client_key = identity::Keypair::generate_ed25519();
        let relay_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let relay_public_key = raw_public_key(&relay_key);
        let exit_public_key = raw_public_key(&exit_key);
        let mut client = DiscoveryService::new_with_protocol_roles(
            client_key,
            DiscoveryProtocolRoles::new(true, false, false),
        )
        .expect("client discovery");
        let mut relay = DiscoveryService::new_with_protocol_roles(
            relay_key.clone(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("Relay discovery");
        let mut exit = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("Exit discovery");
        let client_peer = *client.local_peer_id();
        let relay_peer = *relay.local_peer_id();
        let exit_peer = *exit.local_peer_id();
        let now_ms = system_unix_millis().expect("current wall time");
        let advertisement_expiry = now_ms + 30_000;
        let policy_expiry = now_ms + 60_000;
        let policy = LocalPreselectionPolicy::new(POLICY_VERSION, POLICY_HASH, policy_expiry)
            .expect("current policy");

        let mut relay_advertisement = relay_advertisement(&relay_key, relay_public_key);
        relay_advertisement.measured_at_ms = now_ms;
        relay_advertisement.expires_at_ms = advertisement_expiry;
        let signed_relay_advertisement = sign_control_message_with(
            &relay_advertisement,
            relay_public_key,
            now_ms,
            advertisement_expiry,
            [73; 32],
            TimePolicy::default(),
            |message| sign_with_key(&relay_key, message),
        )
        .expect("signed current Relay advertisement");
        let relay_envelope: SignedEnvelope =
            decode_canonical(&signed_relay_advertisement, MAX_CONTROL_MESSAGE_SIZE)
                .expect("Relay advertisement envelope");
        relay
            .set_local_advertisement(signed_relay_advertisement)
            .expect("serve Relay advertisement");
        let control_actor = actor_for(
            &relay_key,
            relay_public_key,
            relay_advertisement.sequence_number,
            relay_envelope
                .payload_hash
                .as_slice()
                .try_into()
                .expect("Relay payload hash"),
            advertisement_expiry,
        );
        relay_advertisement.sequence_number = relay_advertisement.sequence_number.saturating_add(1);
        let refreshed_relay_advertisement = sign_control_message_with(
            &relay_advertisement,
            relay_public_key,
            now_ms,
            advertisement_expiry,
            [79; 32],
            TimePolicy::default(),
            |message| sign_with_key(&relay_key, message),
        )
        .expect("signed refreshed Relay advertisement");
        relay
            .set_local_advertisement(refreshed_relay_advertisement)
            .expect("refresh served Relay advertisement after client snapshot");

        let mut exit_advertisement = exit_advertisement(&exit_key, exit_public_key);
        exit_advertisement.measured_at_ms = now_ms;
        exit_advertisement.expires_at_ms = advertisement_expiry;
        let signed_exit_advertisement = sign_control_message_with(
            &exit_advertisement,
            exit_public_key,
            now_ms,
            advertisement_expiry,
            [74; 32],
            TimePolicy::default(),
            |message| sign_with_key(&exit_key, message),
        )
        .expect("signed current Exit advertisement");
        let exit_envelope: SignedEnvelope =
            decode_canonical(&signed_exit_advertisement, MAX_CONTROL_MESSAGE_SIZE)
                .expect("Exit advertisement envelope");
        exit.set_local_advertisement(signed_exit_advertisement)
            .expect("serve Exit advertisement");
        let exit_actor = actor_for(
            &exit_key,
            exit_public_key,
            exit_advertisement.sequence_number,
            exit_envelope
                .payload_hash
                .as_slice()
                .try_into()
                .expect("Exit payload hash"),
            advertisement_expiry,
        );

        let _ = connect_and_capture_both_lineages(&mut client, &mut relay).await;
        assert!(
            client.swarm.is_connected(&relay_peer),
            "the client must have its one authenticated Relay control connection"
        );
        assert!(
            !client.swarm.is_connected(&exit_peer),
            "the client must have no direct Exit connection"
        );
        let ((relay_exit_connection, relay_exit_old), (exit_relay_connection, exit_relay_old)) =
            connect_and_capture_both_lineages(&mut relay, &mut exit).await;
        let relay_exit_public = dialer("/ip4/8.8.8.8/tcp/443");
        relay
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: exit_peer,
                connection_id: relay_exit_connection,
                old: &relay_exit_old,
                new: &relay_exit_public,
            }));
        let exit_relay_public = listener("/ip4/1.1.1.8/tcp/443");
        exit.swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: relay_peer,
                connection_id: exit_relay_connection,
                old: &exit_relay_old,
                new: &exit_relay_public,
            }));

        let request_created_at = system_unix_millis().expect("request wall time");
        let typed_request = PreselectionObservationRequest {
            protocol_version: volparossa_protocol::PROTOCOL_VERSION,
            challenge: vec![75; 32],
            actor: Some(exit_actor.clone()),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Exit as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: POLICY_VERSION,
                policy_hash: POLICY_HASH.to_vec(),
                policy_expires_at_ms: policy_expiry,
            }),
            forwarded_control: Some(control_actor.clone()),
            created_at_ms: request_created_at,
            expires_at_ms: request_created_at + 4_000,
        };
        let canonical_request =
            encode_canonical(&typed_request, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical request");
        let wire_request =
            ClientPreselectionObservationRequest::from_canonical(canonical_request.clone())
                .expect("client request");
        let outbound = client
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&relay_peer, wire_request);
        let mut relay_signer = |message: &[u8]| sign_with_key(&relay_key, message);
        let mut exit_signer = |message: &[u8]| sign_with_key(&exit_key, message);

        let signed_attestation = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    event = client.next_internal_event() => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                    ..
                                },
                            )) if peer == relay_peer && request_id == outbound => {
                                break response;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                },
                            )) if request_id == outbound => {
                                panic!("three-swarm response transport failed: {error}");
                            }
                            _ => {}
                        }
                    }
                    _ = relay.next_event_with_preselection_responders(
                        policy,
                        relay_public_key,
                        &mut relay_signer,
                    ) => {}
                    _ = exit.next_event_with_preselection_responders(
                        policy,
                        exit_public_key,
                        &mut exit_signer,
                    ) => {}
                }
            }
        })
        .await
        .expect("three-swarm forwarded response timeout");

        let verification_time = system_unix_millis().expect("verification wall time");
        let mut transcript_replay = ReplayCache::new(4).expect("transcript replay cache");
        verify_forwarded_preselection_transcript(
            signed_attestation.as_encoded(),
            &canonical_request,
            verification_time,
            TimePolicy::default(),
            &mut transcript_replay,
        )
        .expect("complete forwarded transcript");
        assert!(
            verify_forwarded_preselection_transcript(
                signed_attestation.as_encoded(),
                &canonical_request,
                verification_time,
                TimePolicy::default(),
                &mut transcript_replay,
            )
            .is_err(),
            "the outer and nested signatures remain replay-protected"
        );
        let envelope: SignedEnvelope =
            decode_canonical(signed_attestation.as_encoded(), MAX_CONTROL_MESSAGE_SIZE)
                .expect("forwarded envelope");
        let attestation: ForwardedPreselectionAttestation =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
                .expect("forwarded payload");
        assert_eq!(attestation.control, Some(control_actor));
        assert_eq!(attestation.exit, Some(exit_actor));
        assert_eq!(
            attestation
                .upstream_network_prefix
                .expect("Relay-observed Exit prefix")
                .network_prefix,
            [8, 8, 8]
        );
        assert_eq!(attestation.valid_until_ms, typed_request.expires_at_ms);
        assert!(attestation.valid_until_ms <= advertisement_expiry);
        assert_ne!(attestation.nonce, vec![0; 32]);
        assert_eq!(envelope.expires_at_ms, attestation.valid_until_ms);
        assert_eq!(envelope.sender_public_key, relay_public_key);
        assert!(
            relay.forwarded_preselection_pending_deadline().is_none(),
            "successful handoff cleans the affine owner"
        );
        assert!(
            !client.swarm.is_connected(&exit_peer),
            "live connected-peer state still contains no direct client-to-Exit connection"
        );
        assert_ne!(client_peer, relay_peer);
        assert_ne!(client_peer, exit_peer);

        // A second request is deliberately left upstream-pending. Mismatched events cannot steal
        // it, while the exact Exit failure consumes both the downstream owner and upstream slot.
        let _ = send_forwarded_control_request(&mut client, relay_peer, &typed_request, 76);
        drive_client_relay_until_forwarding_pending(
            &mut client,
            &mut relay,
            policy,
            relay_public_key,
            &relay_key,
        )
        .await;
        let first_pending_upstream = relay
            .test_active_upstream_preselection_request_id()
            .expect("active upstream request ID");
        let (pending_client, _pending_connection, pending_request) = relay
            .test_forwarded_downstream_identity()
            .expect("retained downstream identity");
        assert!(!relay.handle_forwarded_preselection_upstream_failure(
            identity::Keypair::generate_ed25519().public().to_peer_id(),
            first_pending_upstream,
        ));
        assert!(!relay.handle_forwarded_preselection_downstream_failure(
            pending_client,
            ConnectionId::new_unchecked(usize::MAX),
            pending_request,
        ));
        assert!(relay.forwarded_preselection_pending_deadline().is_some());
        assert!(
            relay
                .handle_forwarded_preselection_upstream_failure(exit_peer, first_pending_upstream,)
        );
        assert!(relay.forwarded_preselection_pending_deadline().is_none());

        // A stale request ID cannot cancel a new owner; policy replacement does so atomically.
        let _ = send_forwarded_control_request(&mut client, relay_peer, &typed_request, 77);
        drive_client_relay_until_forwarding_pending(
            &mut client,
            &mut relay,
            policy,
            relay_public_key,
            &relay_key,
        )
        .await;
        let second_pending_upstream = relay
            .test_active_upstream_preselection_request_id()
            .expect("replacement upstream request ID");
        assert_ne!(second_pending_upstream, first_pending_upstream);
        assert!(
            !relay
                .handle_forwarded_preselection_upstream_failure(exit_peer, first_pending_upstream,)
        );
        relay.cancel_forwarded_preselection_if_context_changed(
            LocalPreselectionPolicy::new(POLICY_VERSION + 1, [72; 32], policy_expiry)
                .expect("replacement policy"),
            relay_public_key,
        );
        assert!(relay.forwarded_preselection_pending_deadline().is_none());

        // The exact original downstream failure also clears the affine owner.
        let _ = send_forwarded_control_request(&mut client, relay_peer, &typed_request, 78);
        drive_client_relay_until_forwarding_pending(
            &mut client,
            &mut relay,
            policy,
            relay_public_key,
            &relay_key,
        )
        .await;
        let (pending_client, pending_connection, pending_request) = relay
            .test_forwarded_downstream_identity()
            .expect("retained downstream identity");
        assert!(relay.handle_forwarded_preselection_downstream_failure(
            pending_client,
            pending_connection,
            pending_request,
        ));
        assert!(relay.forwarded_preselection_pending_deadline().is_none());

        // Deadline and generic-pump lifecycle transitions are both bounded and idempotent.
        let _ = send_forwarded_control_request(&mut client, relay_peer, &typed_request, 79);
        drive_client_relay_until_forwarding_pending(
            &mut client,
            &mut relay,
            policy,
            relay_public_key,
            &relay_key,
        )
        .await;
        let deadline = relay
            .forwarded_preselection_pending_deadline()
            .expect("pending deadline");
        relay.cancel_forwarded_preselection_at_deadline(deadline);
        assert!(relay.forwarded_preselection_pending_deadline().is_none());

        let _ = send_forwarded_control_request(&mut client, relay_peer, &typed_request, 80);
        drive_client_relay_until_forwarding_pending(
            &mut client,
            &mut relay,
            policy,
            relay_public_key,
            &relay_key,
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_millis(10), relay.next_event()).await;
        assert!(relay.forwarded_preselection_pending_deadline().is_none());
        relay.cancel_preselection_forwarding();
    }

    #[tokio::test]
    async fn replay_and_signing_failure_are_terminal_inside_the_tombstone_window() {
        let mut fixture = fixture().await;
        let first = request(fixture.actor.clone(), 22, ObservationAddressFamily::Ipv4);
        let signing_error = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &first,
                fixture.policy,
                fixture.relay_public_key,
                |_| None,
                NOW_MS + 100,
                Instant::now(),
            ),
            "signing failure",
        );
        assert_eq!(signing_error, DirectPreselectionResponderError::Signing);
        let replay = request(fixture.actor.clone(), 22, ObservationAddressFamily::Ipv4);
        assert_eq!(
            rejection(
                fixture.service.prepare_direct_preselection_response_at(
                    fixture.client_peer,
                    ConnectionId::new_unchecked(CONNECTION),
                    &replay,
                    fixture.policy,
                    fixture.relay_public_key,
                    |message| sign_with_key(&fixture.relay_key, message),
                    NOW_MS + 200,
                    Instant::now(),
                ),
                "same exact request is tombstoned",
            ),
            DirectPreselectionResponderError::Replay
        );
    }

    #[tokio::test]
    async fn identity_policy_advertisement_and_scope_substitution_fail_closed() {
        let mut fixture = fixture().await;
        let wrong_key = identity::Keypair::generate_ed25519();
        let wrong_public = raw_public_key(&wrong_key);
        let identity_error = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(fixture.actor.clone(), 23, ObservationAddressFamily::Ipv4),
                fixture.policy,
                wrong_public,
                |message| sign_with_key(&wrong_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted signer",
        );
        assert_eq!(identity_error, DirectPreselectionResponderError::Authority);

        let wrong_policy =
            LocalPreselectionPolicy::new(POLICY_VERSION + 1, POLICY_HASH, POLICY_EXPIRY_MS)
                .expect("shaped policy");
        let policy_error = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(fixture.actor.clone(), 24, ObservationAddressFamily::Ipv4),
                wrong_policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted active policy",
        );
        assert_eq!(policy_error, DirectPreselectionResponderError::Authority);

        let mut substituted_actor = fixture.actor.clone();
        substituted_actor.advertisement_payload_hash[0] ^= 1;
        let actor_error = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(substituted_actor, 25, ObservationAddressFamily::Ipv4),
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "substituted advertisement binding",
        );
        assert_eq!(actor_error, DirectPreselectionResponderError::Authority);
    }

    #[tokio::test]
    async fn disabled_role_and_missing_or_stale_advertisement_fail_closed() {
        let mut fixture = fixture().await;
        let request = request(fixture.actor.clone(), 46, ObservationAddressFamily::Ipv4);
        let mut disabled = DiscoveryService::new_with_protocol_roles(
            identity::Keypair::generate_ed25519(),
            DiscoveryProtocolRoles::new(true, false, false),
        )
        .expect("client-only discovery");
        assert_eq!(
            rejection(
                disabled.prepare_direct_preselection_response_at(
                    fixture.client_peer,
                    ConnectionId::new_unchecked(CONNECTION),
                    &request,
                    fixture.policy,
                    fixture.relay_public_key,
                    |message| sign_with_key(&fixture.relay_key, message),
                    NOW_MS,
                    Instant::now(),
                ),
                "disabled Relay role",
            ),
            DirectPreselectionResponderError::Role
        );

        let typed: PreselectionObservationRequest =
            decode_canonical(request.as_encoded(), MAX_PRESELECTION_REQUEST_SIZE)
                .expect("typed request");
        let scope = typed.scope.as_ref().expect("request scope");
        fixture.service.clear_local_advertisement();
        assert!(matches!(
            fixture.service.local_relay_authority(
                fixture.policy,
                fixture.relay_public_key,
                scope,
                NOW_MS,
            ),
            Err(DirectPreselectionResponderError::Authority)
        ));

        let mut stale = relay_advertisement(&fixture.relay_key, fixture.relay_public_key);
        stale.measured_at_ms = NOW_MS - 20_000;
        stale.expires_at_ms = NOW_MS - 1;
        let stale = sign_control_message_with(
            &stale,
            fixture.relay_public_key,
            NOW_MS - 20_000,
            NOW_MS - 1,
            [46; 32],
            TimePolicy::default(),
            |message| sign_with_key(&fixture.relay_key, message),
        )
        .expect("structurally valid expired advertisement");
        fixture
            .service
            .set_local_advertisement(stale)
            .expect("install expired advertisement bytes");
        assert!(matches!(
            fixture.service.local_relay_authority(
                fixture.policy,
                fixture.relay_public_key,
                scope,
                NOW_MS,
            ),
            Err(DirectPreselectionResponderError::Authority)
        ));
    }

    #[tokio::test]
    async fn exact_previously_served_relay_actor_survives_bounded_advertisement_refresh() {
        let mut fixture = fixture().await;
        let previously_served = fixture.actor.clone();
        let mut replacement = relay_advertisement(&fixture.relay_key, fixture.relay_public_key);
        replacement.sequence_number = replacement.sequence_number.saturating_add(1);
        let replacement = sign_control_message_with(
            &replacement,
            fixture.relay_public_key,
            NOW_MS,
            ADVERTISEMENT_EXPIRY_MS,
            [92; 32],
            TimePolicy::default(),
            |message| sign_with_key(&fixture.relay_key, message),
        )
        .expect("signed replacement Relay advertisement");
        fixture
            .service
            .set_local_advertisement(replacement)
            .expect("install replacement Relay advertisement");

        fixture
            .service
            .prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(
                    previously_served.clone(),
                    92,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            )
            .expect("exact still-valid served actor");

        let mut never_served = previously_served;
        never_served.advertisement_sequence = never_served.advertisement_sequence.saturating_sub(1);
        let error = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(never_served, 93, ObservationAddressFamily::Ipv4),
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "unserved same-identity actor",
        );
        assert_eq!(error, DirectPreselectionResponderError::Authority);
    }

    #[tokio::test]
    async fn exact_previously_served_exit_actor_survives_bounded_advertisement_refresh() {
        let mut fixture = upstream_fixture().await;
        let previously_served = fixture.exit_actor.clone();
        for refresh in 1_u8..=u8::try_from(MAX_LOCAL_ADVERTISEMENT_LINEAGE)
            .expect("bounded local advertisement lineage")
        {
            let mut replacement = exit_advertisement(&fixture.exit_key, fixture.exit_public_key);
            replacement.sequence_number = replacement
                .sequence_number
                .saturating_add(u64::from(refresh));
            let replacement = sign_control_message_with(
                &replacement,
                fixture.exit_public_key,
                NOW_MS,
                ADVERTISEMENT_EXPIRY_MS,
                [94_u8.saturating_add(refresh); 32],
                TimePolicy::default(),
                |message| sign_with_key(&fixture.exit_key, message),
            )
            .expect("signed replacement Exit advertisement");
            fixture
                .service
                .set_local_advertisement(replacement)
                .expect("install replacement Exit advertisement");
        }

        fixture
            .service
            .prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    previously_served.clone(),
                    fixture.control_actor.clone(),
                    94,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            )
            .expect("exact still-valid served Exit actor");

        let mut never_served = previously_served;
        never_served.advertisement_sequence = never_served.advertisement_sequence.saturating_sub(1);
        let error = upstream_rejection(
            fixture.service.prepare_upstream_preselection_response_at(
                fixture.relay_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &upstream_request(
                    never_served,
                    fixture.control_actor,
                    95,
                    ObservationAddressFamily::Ipv4,
                ),
                fixture.policy,
                fixture.exit_public_key,
                |message| sign_with_key(&fixture.exit_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "unserved same-identity Exit actor",
        );
        assert_eq!(error, UpstreamPreselectionResponderError::Authority);
    }

    #[tokio::test]
    async fn connection_family_and_event_connection_are_exact_with_parallel_connections() {
        let mut fixture = fixture().await;
        let wrong_family = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(fixture.actor.clone(), 26, ObservationAddressFamily::Ipv6),
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "native family mismatch",
        );
        assert_eq!(
            wrong_family,
            DirectPreselectionResponderError::Provenance(
                PreselectionProvenanceReject::FamilyPrefix
            )
        );

        let wrong_connection = rejection(
            fixture.service.prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION + 1),
                &request(fixture.actor.clone(), 27, ObservationAddressFamily::Ipv4),
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            ),
            "event connection substitution",
        );
        assert_eq!(
            wrong_connection,
            DirectPreselectionResponderError::Provenance(
                PreselectionProvenanceReject::ExactConnectionMissing
            )
        );

        establish(
            &mut fixture.service,
            fixture.client_peer,
            CONNECTION + 1,
            &dialer("/ip4/9.9.9.9/tcp/443"),
            1,
        );
        fixture
            .service
            .prepare_direct_preselection_response_at(
                fixture.client_peer,
                ConnectionId::new_unchecked(CONNECTION),
                &request(fixture.actor.clone(), 28, ObservationAddressFamily::Ipv4),
                fixture.policy,
                fixture.relay_public_key,
                |message| sign_with_key(&fixture.relay_key, message),
                NOW_MS + 100,
                Instant::now(),
            )
            .expect("request event binds its exact authenticated connection");
    }

    #[tokio::test]
    async fn stale_and_future_requests_never_consume_replay_space() {
        let mut fixture = fixture().await;
        let baseline = fixture.service.preselection_responder.requests.len();
        let mut stale: PreselectionObservationRequest = decode_canonical(
            request(fixture.actor.clone(), 29, ObservationAddressFamily::Ipv4).as_encoded(),
            MAX_PRESELECTION_REQUEST_SIZE,
        )
        .expect("request");
        stale.created_at_ms = NOW_MS - 10_000;
        stale.expires_at_ms = NOW_MS - 5_000;
        let stale = ClientPreselectionObservationRequest::from_canonical(
            encode_canonical(&stale, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical stale request"),
        )
        .expect("structurally valid stale request");
        assert_eq!(
            rejection(
                fixture.service.prepare_direct_preselection_response_at(
                    fixture.client_peer,
                    ConnectionId::new_unchecked(CONNECTION),
                    &stale,
                    fixture.policy,
                    fixture.relay_public_key,
                    |message| sign_with_key(&fixture.relay_key, message),
                    NOW_MS,
                    Instant::now(),
                ),
                "stale request",
            ),
            DirectPreselectionResponderError::Request
        );

        let mut future: PreselectionObservationRequest = decode_canonical(
            request(fixture.actor.clone(), 30, ObservationAddressFamily::Ipv4).as_encoded(),
            MAX_PRESELECTION_REQUEST_SIZE,
        )
        .expect("request");
        future.created_at_ms = NOW_MS + 1_000;
        let future = ClientPreselectionObservationRequest::from_canonical(
            encode_canonical(&future, MAX_CONTROL_PAYLOAD_SIZE).expect("canonical future request"),
        )
        .expect("structurally valid future request");
        assert_eq!(
            rejection(
                fixture.service.prepare_direct_preselection_response_at(
                    fixture.client_peer,
                    ConnectionId::new_unchecked(CONNECTION),
                    &future,
                    fixture.policy,
                    fixture.relay_public_key,
                    |message| sign_with_key(&fixture.relay_key, message),
                    NOW_MS,
                    Instant::now(),
                ),
                "future request",
            ),
            DirectPreselectionResponderError::Request
        );
        assert_eq!(
            fixture.service.preselection_responder.requests.len(),
            baseline
        );
    }

    #[tokio::test]
    async fn valid_forwarded_request_is_refused_by_the_direct_only_responder() {
        let mut fixture = fixture().await;
        let baseline = fixture.service.preselection_responder.requests.len();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit_public_key = raw_public_key(&exit_key);
        let exit_actor = PreselectionActorBinding {
            node_id: node_id_from_public_key(&exit_public_key).to_vec(),
            peer_id: exit_key.public().to_peer_id().to_bytes(),
            public_key: exit_public_key.to_vec(),
            advertisement_sequence: 99,
            advertisement_expires_at_ms: ADVERTISEMENT_EXPIRY_MS,
            advertisement_payload_hash: vec![99; 32],
            capability_expires_at_ms: ADVERTISEMENT_EXPIRY_MS,
        };
        let forwarded = PreselectionObservationRequest {
            protocol_version: volparossa_protocol::PROTOCOL_VERSION,
            challenge: vec![31; 32],
            actor: Some(exit_actor),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Exit as i32,
                transport: Transport::UdpSinglePath as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: POLICY_VERSION,
                policy_hash: POLICY_HASH.to_vec(),
                policy_expires_at_ms: POLICY_EXPIRY_MS,
            }),
            forwarded_control: Some(fixture.actor.clone()),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 4_000,
        };
        let forwarded = ClientPreselectionObservationRequest::from_canonical(
            encode_canonical(&forwarded, MAX_CONTROL_PAYLOAD_SIZE)
                .expect("canonical forwarded request"),
        )
        .expect("valid client-hop forwarded request");
        assert_eq!(
            rejection(
                fixture.service.prepare_direct_preselection_response_at(
                    fixture.client_peer,
                    ConnectionId::new_unchecked(CONNECTION),
                    &forwarded,
                    fixture.policy,
                    fixture.relay_public_key,
                    |message| sign_with_key(&fixture.relay_key, message),
                    NOW_MS + 100,
                    Instant::now(),
                ),
                "forwarded request at direct-only responder",
            ),
            DirectPreselectionResponderError::Request
        );
        assert_eq!(
            fixture.service.preselection_responder.requests.len(),
            baseline
        );
    }

    #[test]
    fn replay_tombstones_are_globally_unique_per_peer_bounded_and_monotonic_expiring() {
        let mut state = PreselectionResponderState::new();
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();
        let now = Instant::now();
        for index in 0..MAX_REQUEST_TOMBSTONES_PER_PEER {
            let mut hash = [0; 32];
            hash[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
            state
                .reserve(hash, peer, now)
                .expect("within per-peer bound");
        }
        assert_eq!(
            state.reserve([200; 32], peer, now),
            Err(TombstoneError::ResourceLimit)
        );
        let mut first_hash = [0; 32];
        first_hash[..8].copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            state.reserve(first_hash, other, now),
            Err(TombstoneError::Replay)
        );
        state
            .reserve(
                [201; 32],
                peer,
                now + REQUEST_TOMBSTONE_LIFETIME + Duration::from_millis(1),
            )
            .expect("expired monotonic tombstones are pruned");
    }

    #[test]
    fn tentative_tombstone_rolls_back_only_its_exact_pre_send_record() {
        let mut state = PreselectionResponderState::new();
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let now = Instant::now();
        let hash = [202; 32];
        let reservation = state
            .reserve_tentative(hash, peer, now)
            .expect("tentative reservation");
        assert_eq!(state.requests.len(), 1);
        assert!(state.rollback_tentative(reservation));
        assert!(state.requests.is_empty());

        let committed = state
            .reserve_tentative(hash, peer, now)
            .expect("same hash is admissible after exact pre-send rollback");
        committed.commit();
        assert_eq!(state.requests.len(), 1);
        assert_eq!(
            state.reserve(hash, peer, now),
            Err(TombstoneError::Replay),
            "a committed send boundary remains replay-tombstoned"
        );
    }

    #[test]
    fn global_replay_tombstone_bound_fails_closed_without_live_eviction() {
        let mut state = PreselectionResponderState::new();
        let now = Instant::now();
        let peer_count = MAX_REQUEST_TOMBSTONES / MAX_REQUEST_TOMBSTONES_PER_PEER;
        let mut ordinal = 1_u64;
        for _ in 0..peer_count {
            let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
            for _ in 0..MAX_REQUEST_TOMBSTONES_PER_PEER {
                let mut hash = [0; 32];
                hash[..8].copy_from_slice(&ordinal.to_be_bytes());
                state.reserve(hash, peer, now).expect("within global bound");
                ordinal += 1;
            }
        }
        assert_eq!(state.requests.len(), MAX_REQUEST_TOMBSTONES);
        let extra_peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(
            state.reserve([255; 32], extra_peer, now),
            Err(TombstoneError::ResourceLimit)
        );
        assert_eq!(state.requests.len(), MAX_REQUEST_TOMBSTONES);
    }

    #[test]
    fn policy_shape_and_scope_support_are_exact() {
        assert_eq!(
            LocalPreselectionPolicy::new(0, POLICY_HASH, POLICY_EXPIRY_MS),
            Err(DirectPreselectionResponderError::Authority)
        );
        assert_eq!(
            LocalPreselectionPolicy::new(POLICY_VERSION, [0; 32], POLICY_EXPIRY_MS),
            Err(DirectPreselectionResponderError::Authority)
        );
        let capabilities = AdvertisementCapabilities {
            tcp_mptcp: false,
            udp_single_path: true,
            multipath_quic: false,
            ipv4: true,
            ipv6: false,
            udp_hole_punching: false,
        };
        let mut scope = PreselectionObservationScope {
            role: PreselectionObservationRole::Relay as i32,
            transport: Transport::UdpSinglePath as i32,
            address_family: ObservationAddressFamily::Ipv4 as i32,
            policy_version: POLICY_VERSION,
            policy_hash: POLICY_HASH.to_vec(),
            policy_expires_at_ms: POLICY_EXPIRY_MS,
        };
        assert!(capability_supports_scope(&capabilities, &scope));
        scope.transport = Transport::TcpMptcp as i32;
        assert!(!capability_supports_scope(&capabilities, &scope));
        scope.transport = Transport::UdpSinglePath as i32;
        scope.address_family = ObservationAddressFamily::Ipv6 as i32;
        assert!(!capability_supports_scope(&capabilities, &scope));
    }

    #[test]
    fn responder_production_surface_contains_no_evidence_or_measurement_minter() {
        let source = include_str!("preselection_responder.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [
            "FreshEvidenceBatch",
            "FreshPeerEvidence",
            "CandidateEvidence",
            "observed_endpoints",
            "rtt_ms",
            "capacity_mbps",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        assert!(!production.contains("pub fn for_test"));
        assert!(!production.contains("pub(crate) fn for_test"));
        assert!(production.contains("pub async fn next_event_with_preselection_responders"));
        assert!(!production.contains("pub fn respond_direct_preselection_observation_event"));
        assert!(!production.contains("pub fn respond_upstream_preselection_observation_event"));
        assert!(!production.contains("pub fn prepare_upstream_preselection_response_at"));
        assert_eq!(production.matches("self.next_internal_event()").count(), 2);
        assert!(production.contains("tokio::time::sleep_until(deadline)"));
        assert!(production.contains("begin_forwarded_preselection_event"));
        assert!(production.contains("handle_forwarded_preselection_upstream_response"));
        assert!(production.contains("BehaviourEvent::PreselectionObservationUpstream"));
        assert!(production.contains("UpstreamPreselectionObservationResponse::from_canonical"));
        assert!(!production.contains("TODO"));
        assert!(!production.contains("unimplemented!"));

        let root = include_str!("lib.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("root production source");
        assert_eq!(root.matches("async fn next_internal_event(").count(), 1);
        assert!(!root.contains("pub async fn next_internal_event("));
        assert_eq!(root.matches("self.next_internal_event().await").count(), 1);
        let public_pump = root
            .split("pub async fn next_event(")
            .nth(1)
            .expect("public event pump")
            .split("/// Private event pump")
            .next()
            .expect("public event pump end");
        assert!(public_pump.contains("self.next_internal_event().await"));
        assert!(public_pump.contains("inbound_preselection_request(&event)"));
        assert!(!public_pump.contains("select_next_some"));
        assert_eq!(root.matches("fn inbound_preselection_request(").count(), 1);
        let inbound_filter = root
            .split("fn inbound_preselection_request(")
            .nth(1)
            .expect("private inbound filter")
            .split("fn forward_request_targets_local_relay")
            .next()
            .expect("private inbound filter end");
        assert_eq!(
            inbound_filter
                .matches("BehaviourEvent::PreselectionObservation(")
                .count(),
            1
        );
        assert_eq!(
            inbound_filter
                .matches("BehaviourEvent::PreselectionObservationUpstream(")
                .count(),
            1
        );
        assert_eq!(
            inbound_filter
                .matches("request_response::Message::Request { .. }")
                .count(),
            2
        );

        let transaction = include_str!("preselection_transaction.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("transaction production source");
        assert!(!transaction.contains("send_preselection_observation_response"));
        assert!(!transaction.contains("send_preselection_observation_upstream_response"));
        assert!(!transaction.contains("ResponseChannel"));
        assert!(!transaction.contains("next_internal_event"));
        assert_eq!(PreselectionObservationReceipt::MESSAGE_TYPE as i32, 17);
        let empty: PreselectionObservationRequest =
            decode_canonical(&[], MAX_PRESELECTION_REQUEST_SIZE).expect("protobuf default");
        assert!(empty.validate().is_err());
    }
}
