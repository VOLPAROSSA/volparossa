//! Generic content-service discovery through one current authenticated control Relay.
//!
//! No object identifiers, names, URLs or publication keys enter this protocol. Provider offers
//! locate explicit services only: they never grant origin, route, DNS or Internet-egress authority.

use super::{
    AgentState, Arc, BehaviourEvent, ConnectionId, DirectRelayCapability, DiscoveryCommand,
    DiscoveryControlHandle, DiscoveryRuntime, HashMap, HashSet, Instant, Libp2pPeerId, LogLevel,
    RwLock, SwarmEvent, capability, direct_relay_authority_lineage_matches, kad, oneshot,
    request_response, timeout, unix_millis, unix_seconds,
};
use ed25519_dalek::VerifyingKey;
use std::{collections::BTreeMap, time::Duration};
use volparossa_content::provider::{SignedProviderOffer, VerifiedProviderOffer};
use volparossa_discovery::{
    ContentControlConnectionState, ContentDiscoveryRequest, ContentDiscoveryResponse,
    ContentProviderOffer, ContentServiceRequest, ContentServiceResponse,
};
use volparossa_policy::TransportProtocol;

const MAX_OFFERS: usize = 16;
const MAX_PENDING: usize = 32;
const MAX_REPLAY: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
// Leave a response window inside the unchanged client/RPC deadline. A slow DHT walk must
// not erase independently verified offers merely because collection reached its own bound.
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(10);
const REPLAY_RETENTION: Duration = Duration::from_secs(60);
type OutboundId = request_response::OutboundRequestId;
type DiscoveryReply =
    oneshot::Sender<Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError>>;

/// A verified location hint; callers still authorize a separate protected content connection.
#[derive(Clone, Debug)]
pub(crate) struct DiscoveredContentProvider {
    pub(crate) peer_id: Libp2pPeerId,
    pub(crate) offer: VerifiedProviderOffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentDiscoveryError {
    Busy,
    Closed,
    Timeout,
    Invalid,
    Unavailable,
    Invalidated,
}

pub(super) enum ContentCommand {
    Register {
        offer: Box<SignedProviderOffer>,
        reply: oneshot::Sender<Result<VerifiedProviderOffer, ContentDiscoveryError>>,
    },
    Withdraw {
        reply: oneshot::Sender<Result<(), ContentDiscoveryError>>,
    },
    Discover {
        control_peer: Libp2pPeerId,
        maximum: usize,
        reply: DiscoveryReply,
    },
}

impl ContentCommand {
    pub(super) fn reject(self, error: ContentDiscoveryError) {
        match self {
            Self::Register { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Withdraw { reply } => {
                let _ = reply.send(Err(error));
            }
            Self::Discover { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

impl DiscoveryControlHandle {
    /// Register only after the caller owns a bound, live, explicitly populated service.
    pub(crate) async fn register_content_offer(
        &self,
        offer: SignedProviderOffer,
    ) -> Result<VerifiedProviderOffer, ContentDiscoveryError> {
        let (reply, response) = oneshot::channel();
        timeout(REQUEST_TIMEOUT, async {
            self.sender
                .send(DiscoveryCommand::Content(ContentCommand::Register {
                    offer: Box::new(offer),
                    reply,
                }))
                .await
                .map_err(|_| ContentDiscoveryError::Closed)?;
            response.await.map_err(|_| ContentDiscoveryError::Closed)?
        })
        .await
        .map_err(|_| ContentDiscoveryError::Timeout)?
    }

    pub(crate) async fn withdraw_content_offer(&self) -> Result<(), ContentDiscoveryError> {
        let (reply, response) = oneshot::channel();
        timeout(REQUEST_TIMEOUT, async {
            self.sender
                .send(DiscoveryCommand::Content(ContentCommand::Withdraw {
                    reply,
                }))
                .await
                .map_err(|_| ContentDiscoveryError::Closed)?;
            response.await.map_err(|_| ContentDiscoveryError::Closed)?
        })
        .await
        .map_err(|_| ContentDiscoveryError::Timeout)?
    }

    /// Ask the carrying route's exact current control Relay, never dial providers here.
    pub(crate) async fn discover_content_providers(
        &self,
        control_peer: Libp2pPeerId,
        maximum: usize,
    ) -> Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError> {
        if !(1..=MAX_OFFERS).contains(&maximum) {
            return Err(ContentDiscoveryError::Invalid);
        }
        let (reply, response) = oneshot::channel();
        timeout(REQUEST_TIMEOUT, async {
            self.sender
                .send(DiscoveryCommand::Content(ContentCommand::Discover {
                    control_peer,
                    maximum,
                    reply,
                }))
                .await
                .map_err(|_| ContentDiscoveryError::Closed)?;
            response.await.map_err(|_| ContentDiscoveryError::Closed)?
        })
        .await
        .map_err(|_| ContentDiscoveryError::Timeout)?
    }
}

#[derive(Default)]
pub(super) struct ContentBridge {
    events: Vec<&'static str>,
    local: Option<LocalOffer>,
    clients: HashMap<OutboundId, PendingClient>,
    relay: Option<RelayLookup>,
    upstream: HashMap<OutboundId, Libp2pPeerId>,
    replay: HashMap<(Libp2pPeerId, [u8; 32]), Instant>,
}

struct LocalOffer {
    deadline: Instant,
}

struct PendingClient {
    control: DirectRelayCapability,
    connection: ConnectionId,
    deadline: Instant,
    maximum: usize,
    reply: DiscoveryReply,
}

struct RelayWaiter {
    peer: Libp2pPeerId,
    connection: ConnectionId,
    request: ContentDiscoveryRequest,
    channel: request_response::ResponseChannel<ContentDiscoveryResponse>,
}

struct RelayLookup {
    query: kad::QueryId,
    collection_deadline: Instant,
    response_deadline: Instant,
    dht_complete: bool,
    candidates: HashSet<Libp2pPeerId>,
    offers: BTreeMap<Libp2pPeerId, Vec<u8>>,
    waiters: Vec<RelayWaiter>,
}

impl RelayLookup {
    fn offers_for_response(
        &self,
        recipient: Libp2pPeerId,
        maximum: usize,
        at: Instant,
        now_unix: u64,
    ) -> Vec<ContentProviderOffer> {
        if at >= self.response_deadline {
            return Vec::new();
        }
        self.offers
            .iter()
            .filter(|(peer, bytes)| {
                **peer != recipient && verify_provider(**peer, bytes, now_unix).is_ok()
            })
            .take(maximum)
            .filter_map(|(peer, bytes)| ContentProviderOffer::new(*peer, bytes.clone()).ok())
            .collect()
    }
}

impl ContentBridge {
    fn event(&mut self, code: &'static str) {
        if self.events.len() < MAX_PENDING {
            self.events.push(code);
        }
    }
    fn pending(&self) -> usize {
        self.clients.len()
            + self.upstream.len()
            + self.relay.as_ref().map_or(0, |lookup| lookup.waiters.len())
    }

    fn next_deadline(&self) -> Instant {
        self.clients
            .values()
            .map(|p| p.deadline)
            .chain(self.relay.iter().map(|r| r.collection_deadline))
            .chain(self.local.iter().map(|local| local.deadline))
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600))
    }
}

impl DiscoveryRuntime {
    pub(super) async fn flush_content_events(&mut self, state: &Arc<RwLock<AgentState>>) {
        if self.content.events.is_empty() {
            return;
        }
        let mut state = state.write().await;
        for event in self.content.events.drain(..) {
            state.log(LogLevel::Info, event, unix_millis());
        }
    }

    pub(super) fn handle_content_swarm_event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
    ) -> Option<SwarmEvent<BehaviourEvent>> {
        self.maintain_content();
        if let SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            ..
        } = &event
        {
            let lost: Vec<_> = self
                .content
                .clients
                .iter()
                .filter(|(_, pending)| {
                    pending.control.peer_id == *peer_id && pending.connection == *connection_id
                })
                .map(|(id, _)| *id)
                .collect();
            for id in lost {
                if let Some(pending) = self.content.clients.remove(&id) {
                    self.content
                        .event("CONTENT_DISCOVERY_CONTROL_CONNECTION_LOST");
                    let _ = pending.reply.send(Err(ContentDiscoveryError::Invalidated));
                }
            }
            if let Some(lookup) = self.content.relay.as_mut() {
                lookup.waiters.retain(|waiter| {
                    waiter.peer != *peer_id || waiter.connection != *connection_id
                });
                if lookup.waiters.is_empty() {
                    self.content.event("CONTENT_LOOKUP_CONTROL_LOST");
                    self.finish_content_lookup(false);
                }
            }
        }
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::ContentDiscovery(event)) => {
                self.handle_content_discovery_event(event);
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::ContentService(event)) => {
                self.handle_content_service_event(event);
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id, result, step, ..
                },
            )) if self
                .content
                .relay
                .as_ref()
                .is_some_and(|lookup| lookup.query == id) =>
            {
                match result {
                    kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                        key,
                        providers,
                    })) => {
                        if key.as_ref() != capability::CONTENT.as_bytes() {
                            self.content.event("CONTENT_LOOKUP_DHT_KEY_REJECTED");
                            self.finish_content_lookup(false);
                            return None;
                        }
                        self.content.event(if providers.is_empty() {
                            "CONTENT_LOOKUP_DHT_FOUND_EMPTY"
                        } else {
                            "CONTENT_LOOKUP_DHT_FOUND_PROVIDERS"
                        });
                        self.dispatch_content_providers(providers);
                    }
                    kad::QueryResult::GetProviders(Err(_)) => {
                        self.content.event("CONTENT_LOOKUP_DHT_TIMED_OUT");
                        self.finish_content_lookup(false);
                        return None;
                    }
                    _ => {}
                }
                if let Some(lookup) = self.content.relay.as_mut() {
                    lookup.dht_complete |= step.last;
                }
                self.maybe_finish_content_lookup();
                None
            }
            other => Some(other),
        }
    }

    fn handle_content_discovery_event(
        &mut self,
        event: request_response::Event<ContentDiscoveryRequest, ContentDiscoveryResponse>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message,
            } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.begin_content_lookup(peer, connection_id, request, channel);
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let Some(pending) = self.content.clients.remove(&request_id) else {
                        return;
                    };
                    let result =
                        self.accept_content_response(&pending, peer, connection_id, &response);
                    match &result {
                        Ok(offers) => {
                            self.content.event(if offers.is_empty() {
                                "CONTENT_DISCOVERY_RECEIVED_EMPTY"
                            } else {
                                "CONTENT_DISCOVERY_RECEIVED_OFFERS"
                            });
                            self.content.event("CONTENT_DISCOVERY_COMPLETED");
                        }
                        Err(error) => {
                            self.content.event(match error {
                                ContentDiscoveryError::Invalidated => {
                                    "CONTENT_DISCOVERY_RESPONSE_AUTHORITY_REJECTED"
                                }
                                _ => "CONTENT_DISCOVERY_RESPONSE_OFFER_REJECTED",
                            });
                            self.content.event("CONTENT_DISCOVERY_RESPONSE_REJECTED");
                        }
                    }
                    let _ = pending.reply.send(result);
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(pending) = self.content.clients.remove(&request_id) {
                    self.content.event(match error {
                        request_response::OutboundFailure::DialFailure => {
                            "CONTENT_DISCOVERY_DIAL_FAILED"
                        }
                        request_response::OutboundFailure::Timeout => {
                            "CONTENT_DISCOVERY_RPC_TIMED_OUT"
                        }
                        request_response::OutboundFailure::ConnectionClosed => {
                            "CONTENT_DISCOVERY_CONNECTION_CLOSED"
                        }
                        request_response::OutboundFailure::UnsupportedProtocols => {
                            "CONTENT_DISCOVERY_PROTOCOL_UNSUPPORTED"
                        }
                        request_response::OutboundFailure::Io(_) => {
                            "CONTENT_DISCOVERY_RPC_IO_FAILED"
                        }
                    });
                    let _ = pending.reply.send(Err(ContentDiscoveryError::Unavailable));
                }
            }
            _ => {}
        }
    }

    fn accept_content_response(
        &self,
        pending: &PendingClient,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        response: &ContentDiscoveryResponse,
    ) -> Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError> {
        if Instant::now() >= pending.deadline
            || peer != pending.control.peer_id
            || connection != pending.connection
            || !self
                .service
                .content_control_connection_is_current(&peer, connection)
            || !self.direct_relays.get(&peer).is_some_and(|current| {
                direct_relay_authority_lineage_matches(
                    current,
                    &pending.control,
                    unix_millis().saturating_add(1),
                )
            })
            || response.offers().len() > pending.maximum
        {
            return Err(ContentDiscoveryError::Invalidated);
        }
        let mut peers = HashSet::new();
        let mut verified = Vec::new();
        for item in response.offers() {
            let provider = item.peer_id().map_err(|_| ContentDiscoveryError::Invalid)?;
            if provider == *self.service.local_peer_id()
                || provider == peer
                || !peers.insert(provider)
            {
                return Err(ContentDiscoveryError::Invalid);
            }
            verified.push(DiscoveredContentProvider {
                peer_id: provider,
                offer: verify_provider(provider, item.signed_offer(), unix_seconds())?,
            });
        }
        Ok(verified)
    }

    fn send_empty_content_response(
        &mut self,
        request: &ContentDiscoveryRequest,
        channel: request_response::ResponseChannel<ContentDiscoveryResponse>,
    ) {
        if let Ok(response) = ContentDiscoveryResponse::new(request, Vec::new()) {
            let _ = self
                .service
                .send_content_discovery_response(channel, response);
        }
    }

    fn begin_content_lookup(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: ContentDiscoveryRequest,
        channel: request_response::ResponseChannel<ContentDiscoveryResponse>,
    ) {
        let started = Instant::now();
        self.content.event("CONTENT_DISCOVERY_RELAY_RECEIVED");
        let Ok(nonce) = <[u8; 32]>::try_from(request.nonce()) else {
            self.content.event("CONTENT_DISCOVERY_RELAY_NONCE_INVALID");
            return;
        };
        let rejection = if !self.roles.relay || self.relay_service.is_none() {
            Some("CONTENT_DISCOVERY_RELAY_SERVICE_UNAVAILABLE")
        } else if self
            .local_relay_snapshot
            .as_ref()
            .is_none_or(|cap| cap.expires_at_ms <= unix_millis().saturating_add(15_000))
        {
            Some("CONTENT_DISCOVERY_RELAY_AUTHORITY_UNAVAILABLE")
        } else if peer == *self.service.local_peer_id() {
            Some("CONTENT_DISCOVERY_RELAY_SELF_REJECTED")
        } else if !self
            .service
            .content_control_connection_is_current(&peer, connection)
        {
            Some("CONTENT_DISCOVERY_RELAY_CONNECTION_INVALID")
        } else if self.content.pending() >= MAX_PENDING {
            Some("CONTENT_DISCOVERY_RELAY_QUEUE_FULL")
        } else if self.content.replay.len() >= MAX_REPLAY {
            Some("CONTENT_DISCOVERY_RELAY_REPLAY_FULL")
        } else if self.content.replay.contains_key(&(peer, nonce)) {
            Some("CONTENT_DISCOVERY_RELAY_REPLAY_REJECTED")
        } else {
            None
        };
        if let Some(event) = rejection {
            self.content.event(event);
            self.send_empty_content_response(&request, channel);
            return;
        }
        self.content
            .replay
            .insert((peer, nonce), Instant::now() + REPLAY_RETENTION);
        let waiter = RelayWaiter {
            peer,
            connection,
            request,
            channel,
        };
        if let Some(lookup) = self.content.relay.as_mut() {
            lookup.waiters.push(waiter);
            self.content.event("CONTENT_DISCOVERY_RELAY_QUERY_JOINED");
            return;
        }
        let Ok(query) = self.service.find_providers(capability::CONTENT) else {
            self.content.event("CONTENT_DISCOVERY_RELAY_QUERY_REJECTED");
            self.send_empty_content_response(&waiter.request, waiter.channel);
            return;
        };
        self.content.relay = Some(RelayLookup {
            query,
            collection_deadline: started + COLLECTION_TIMEOUT,
            response_deadline: started + REQUEST_TIMEOUT,
            dht_complete: false,
            candidates: HashSet::new(),
            offers: BTreeMap::new(),
            waiters: vec![waiter],
        });
        self.content.event("CONTENT_PROVIDER_QUERY_STARTED");
    }

    fn dispatch_content_providers(&mut self, peers: HashSet<Libp2pPeerId>) {
        for peer in peers {
            if self.content.pending() >= MAX_PENDING {
                break;
            }
            let Some(lookup) = self.content.relay.as_mut() else {
                return;
            };
            if lookup.candidates.len() >= MAX_OFFERS {
                break;
            }
            if peer == *self.service.local_peer_id()
                || lookup.waiters.iter().any(|waiter| waiter.peer == peer)
                || !lookup.candidates.insert(peer)
            {
                self.content.event("CONTENT_PROVIDER_TARGET_SKIPPED");
                continue;
            }
            if let Ok(id) = self
                .service
                .request_content_service(&peer, ContentServiceRequest::new())
            {
                self.content.upstream.insert(id, peer);
                self.content.event("CONTENT_PROVIDER_REQUEST_DISPATCHED");
            } else {
                self.content.event("CONTENT_PROVIDER_REQUEST_REJECTED");
            }
        }
    }

    fn handle_content_service_event(
        &mut self,
        event: request_response::Event<ContentServiceRequest, ContentServiceResponse>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let Some(expected) = self.content.upstream.remove(&request_id) else {
                    return;
                };
                if peer == expected {
                    if let Some(offer) = response.offer() {
                        if verify_provider(peer, offer, unix_seconds()).is_err() {
                            self.content.event("CONTENT_PROVIDER_OFFER_REJECTED");
                        } else if let Some(lookup) = self
                            .content
                            .relay
                            .as_mut()
                            .filter(|lookup| lookup.collection_deadline > Instant::now())
                        {
                            lookup.offers.insert(peer, offer.to_vec());
                            self.content.event("CONTENT_PROVIDER_OFFER_VERIFIED");
                        } else {
                            self.content.event("CONTENT_PROVIDER_OFFER_LATE");
                        }
                    } else {
                        self.content.event("CONTENT_PROVIDER_SERVICE_EMPTY");
                    }
                } else {
                    self.content
                        .event("CONTENT_PROVIDER_RESPONSE_PEER_REJECTED");
                }
                self.maybe_finish_content_lookup();
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if self.content.upstream.remove(&request_id).is_some() {
                    self.content.event(match error {
                        request_response::OutboundFailure::DialFailure => {
                            "CONTENT_PROVIDER_REQUEST_DIAL_FAILED"
                        }
                        request_response::OutboundFailure::Timeout => {
                            "CONTENT_PROVIDER_REQUEST_TIMED_OUT"
                        }
                        request_response::OutboundFailure::ConnectionClosed => {
                            "CONTENT_PROVIDER_REQUEST_CONNECTION_CLOSED"
                        }
                        request_response::OutboundFailure::UnsupportedProtocols => {
                            "CONTENT_PROVIDER_REQUEST_PROTOCOL_UNSUPPORTED"
                        }
                        request_response::OutboundFailure::Io(_) => {
                            "CONTENT_PROVIDER_REQUEST_IO_FAILED"
                        }
                    });
                }
                self.maybe_finish_content_lookup();
            }
            // Inbound generic service requests are auto-answered by the libdiscovery pump.
            _ => {}
        }
    }

    fn maybe_finish_content_lookup(&mut self) {
        let query_done = self
            .content
            .relay
            .as_ref()
            .is_some_and(|lookup| lookup.dht_complete);
        if query_done && self.content.upstream.is_empty() {
            self.content.event("CONTENT_LOOKUP_DHT_COMPLETE");
            self.finish_content_lookup(true);
        } else if query_done {
            self.content.event("CONTENT_LOOKUP_WAITING_OFFERS");
        }
    }

    fn finish_content_lookup(&mut self, accept_collected: bool) {
        let Some(mut lookup) = self.content.relay.take() else {
            return;
        };
        let _ = self.service.finish_content_provider_query(lookup.query);
        self.content.upstream.clear();
        let within_deadline = lookup.response_deadline > Instant::now();
        let relay_current = self
            .local_relay_snapshot
            .as_ref()
            .is_some_and(|cap| cap.expires_at_ms > unix_millis());
        let valid = accept_collected && within_deadline && self.roles.relay && relay_current;
        self.content.event(lookup_authority_event(
            accept_collected,
            within_deadline,
            self.roles.relay,
            relay_current,
        ));
        self.content.event(if lookup.offers.is_empty() {
            "CONTENT_LOOKUP_COLLECTED_EMPTY"
        } else {
            "CONTENT_LOOKUP_COLLECTED_OFFERS"
        });
        for waiter in std::mem::take(&mut lookup.waiters) {
            if !self
                .service
                .content_control_connection_is_current(&waiter.peer, waiter.connection)
            {
                self.content.event("CONTENT_LOOKUP_REPLY_CONNECTION_LOST");
                continue;
            }
            let offers = if valid {
                lookup.offers_for_response(
                    waiter.peer,
                    waiter.request.maximum_offers(),
                    Instant::now(),
                    unix_seconds(),
                )
            } else {
                Vec::new()
            };
            self.content.event(if offers.is_empty() {
                "CONTENT_LOOKUP_REPLY_EMPTY"
            } else {
                "CONTENT_LOOKUP_REPLY_OFFERS"
            });
            if let Ok(response) = ContentDiscoveryResponse::new(&waiter.request, offers) {
                if self
                    .service
                    .send_content_discovery_response(waiter.channel, response)
                    .is_err()
                {
                    self.content.event("CONTENT_LOOKUP_REPLY_CHANNEL_FAILED");
                }
            } else {
                self.content.event("CONTENT_LOOKUP_REPLY_ENCODING_REJECTED");
            }
        }
    }

    pub(super) async fn handle_content_command(
        &mut self,
        command: ContentCommand,
        state: &Arc<RwLock<AgentState>>,
    ) {
        self.maintain_content();
        match command {
            ContentCommand::Register { offer, reply } => {
                if reply.is_closed() {
                    return;
                }
                let policy = state.read().await.active_policy(unix_millis());
                let result = policy
                    .as_ref()
                    .ok_or(ContentDiscoveryError::Unavailable)
                    .and_then(|policy| {
                        let verified = verify_provider(
                            *self.service.local_peer_id(),
                            &offer.encode(),
                            unix_seconds(),
                        )?;
                        if verified.provider_key() != &self.local_public_key
                            || policy
                                .authorize_domain(
                                    unix_millis(),
                                    verified.endpoint().hostname(),
                                    TransportProtocol::Tcp,
                                    verified.endpoint().port(),
                                )
                                .is_err()
                        {
                            return Err(ContentDiscoveryError::Invalid);
                        }
                        self.service
                            .set_local_content_offer(Some(offer.encode()))
                            .map_err(|_| ContentDiscoveryError::Unavailable)?;
                        if self.service.provide(capability::CONTENT).is_err() {
                            self.withdraw_content_registration();
                            return Err(ContentDiscoveryError::Unavailable);
                        }
                        self.content.local = Some(LocalOffer {
                            deadline: Instant::now()
                                + Duration::from_millis(
                                    verified
                                        .validity()
                                        .expires
                                        .saturating_mul(1000)
                                        .min(policy.expires_at_ms())
                                        .saturating_sub(unix_millis()),
                                ),
                        });
                        self.content.event("CONTENT_PROVIDER_REGISTERED");
                        Ok(verified)
                    });
                let _ = reply.send(result);
            }
            ContentCommand::Withdraw { reply } => {
                self.withdraw_content_registration();
                let _ = reply.send(Ok(()));
            }
            ContentCommand::Discover {
                control_peer,
                maximum,
                reply,
            } => {
                self.begin_content_discovery(control_peer, maximum, reply);
            }
        }
        self.flush_content_events(state).await;
    }

    fn begin_content_discovery(
        &mut self,
        control_peer: Libp2pPeerId,
        maximum: usize,
        reply: DiscoveryReply,
    ) {
        self.content.event("CONTENT_DISCOVERY_COMMAND_RECEIVED");
        if reply.is_closed() {
            self.content.event("CONTENT_DISCOVERY_CALLER_CLOSED");
            return;
        }
        let Ok(request) = ContentDiscoveryRequest::new(maximum) else {
            self.content.event("CONTENT_DISCOVERY_LIMIT_INVALID");
            let _ = reply.send(Err(ContentDiscoveryError::Invalid));
            return;
        };
        if !self.roles.client {
            self.content.event("CONTENT_DISCOVERY_CLIENT_ROLE_REJECTED");
            let _ = reply.send(Err(ContentDiscoveryError::Busy));
            return;
        }
        if self.content.pending() >= MAX_PENDING {
            self.content.event("CONTENT_DISCOVERY_CLIENT_QUEUE_FULL");
            let _ = reply.send(Err(ContentDiscoveryError::Busy));
            return;
        }
        let now_ms = unix_millis();
        let Some(control) = self.direct_relays.get(&control_peer).cloned() else {
            self.content.event("CONTENT_DISCOVERY_CONTROL_MISSING");
            let _ = reply.send(Err(ContentDiscoveryError::Unavailable));
            return;
        };
        let rejection = if control.peer_id == *self.service.local_peer_id() {
            Some("CONTENT_DISCOVERY_CONTROL_SELF_REJECTED")
        } else if control.expires_at_ms <= now_ms {
            Some("CONTENT_DISCOVERY_CONTROL_EXPIRED")
        } else if control.expires_at_ms <= now_ms.saturating_add(15_000) {
            Some("CONTENT_DISCOVERY_CONTROL_LIFETIME_SHORT")
        } else {
            None
        };
        if let Some(event) = rejection {
            self.content.event(event);
            let _ = reply.send(Err(ContentDiscoveryError::Unavailable));
            return;
        }
        let connection_state = self
            .service
            .content_control_connection_state(&control.peer_id);
        self.content.event(match connection_state {
            ContentControlConnectionState::Poisoned => {
                "CONTENT_DISCOVERY_CONNECTION_REGISTRY_POISONED"
            }
            ContentControlConnectionState::Missing => "CONTENT_DISCOVERY_CONNECTION_ABSENT",
            ContentControlConnectionState::NoDirect => "CONTENT_DISCOVERY_CONNECTION_NO_DIRECT",
            ContentControlConnectionState::Unique => "CONTENT_DISCOVERY_CONNECTION_UNIQUE",
            ContentControlConnectionState::Multiple => "CONTENT_DISCOVERY_CONNECTION_MULTIPLE",
        });
        if !matches!(
            connection_state,
            ContentControlConnectionState::Unique | ContentControlConnectionState::Multiple
        ) {
            let _ = reply.send(Err(ContentDiscoveryError::Unavailable));
            return;
        }
        if let Ok((id, connection)) = self
            .service
            .request_content_discovery(&control.peer_id, request)
        {
            self.content.event("CONTENT_DISCOVERY_REQUEST_DISPATCHED");
            self.content.clients.insert(
                id,
                PendingClient {
                    control,
                    connection,
                    maximum,
                    reply,
                    deadline: Instant::now() + REQUEST_TIMEOUT,
                },
            );
        } else {
            self.content.event("CONTENT_DISCOVERY_REQUEST_REJECTED");
            let _ = reply.send(Err(ContentDiscoveryError::Unavailable));
        }
    }

    pub(super) fn content_deadline(&self) -> Instant {
        self.content.next_deadline()
    }

    pub(super) fn maintain_content(&mut self) {
        let now = Instant::now();
        self.content.replay.retain(|_, until| *until > now);
        if self
            .content
            .local
            .as_ref()
            .is_some_and(|local| local.deadline <= now)
        {
            self.content.event("CONTENT_PROVIDER_REGISTRATION_EXPIRED");
            self.withdraw_content_registration();
        }
        let expired: Vec<_> = self
            .content
            .clients
            .iter()
            .filter(|(_, pending)| pending.deadline <= now || pending.reply.is_closed())
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(pending) = self.content.clients.remove(&id) {
                self.content.event(if pending.reply.is_closed() {
                    "CONTENT_DISCOVERY_CALLER_CLOSED"
                } else {
                    "CONTENT_DISCOVERY_LOCAL_DEADLINE"
                });
                let _ = pending.reply.send(Err(ContentDiscoveryError::Timeout));
            }
        }
        if self
            .content
            .relay
            .as_ref()
            .is_some_and(|lookup| lookup.collection_deadline <= now)
        {
            // This ends bounded collection, not a claim that the DHT walk completed. Every
            // retained offer is reverified within the separate, original response deadline.
            self.content.event("CONTENT_LOOKUP_COLLECTION_ENDED");
            self.finish_content_lookup(true);
        }
    }

    pub(super) fn withdraw_content_registration(&mut self) {
        if self.content.local.take().is_some() {
            self.content.event("CONTENT_PROVIDER_WITHDRAWN");
        }
        let _ = self.service.set_local_content_offer(None);
        let _ = self.service.stop_providing(capability::CONTENT);
    }

    pub(super) fn reannounce_content_registration(&mut self) {
        self.maintain_content();
        if self.content.local.is_some() {
            let _ = self.service.provide(capability::CONTENT);
        }
    }

    pub(super) fn invalidate_content(&mut self) {
        self.withdraw_content_registration();
        for (_, pending) in self.content.clients.drain() {
            let _ = pending.reply.send(Err(ContentDiscoveryError::Invalidated));
        }
        if self.content.relay.is_some() {
            self.content.event("CONTENT_LOOKUP_INVALIDATED");
        }
        self.finish_content_lookup(false);
    }
}

// Classifies the existing fail-closed decision only; no peer, endpoint or object is logged.
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "observe the same four independent authority gates without a new state model"
)]
fn lookup_authority_event(
    accept_collected: bool,
    within_deadline: bool,
    relay_enabled: bool,
    relay_current: bool,
) -> &'static str {
    if !accept_collected {
        "CONTENT_LOOKUP_COLLECTION_REJECTED"
    } else if !within_deadline {
        "CONTENT_LOOKUP_RESPONSE_EXPIRED"
    } else if !relay_enabled {
        "CONTENT_LOOKUP_RELAY_ROLE_REJECTED"
    } else if !relay_current {
        "CONTENT_LOOKUP_RELAY_AUTHORITY_REJECTED"
    } else {
        "CONTENT_LOOKUP_RESPONSE_AUTHORIZED"
    }
}

fn verify_provider(
    peer: Libp2pPeerId,
    encoded: &[u8],
    now: u64,
) -> Result<VerifiedProviderOffer, ContentDiscoveryError> {
    let signed =
        SignedProviderOffer::decode(encoded).map_err(|_| ContentDiscoveryError::Invalid)?;
    let bytes = signed.provider_key_hint();
    let identity = libp2p::identity::ed25519::PublicKey::try_from_bytes(&bytes)
        .map_err(|_| ContentDiscoveryError::Invalid)?;
    if libp2p::identity::PublicKey::from(identity).to_peer_id() != peer {
        return Err(ContentDiscoveryError::Invalid);
    }
    let expected = VerifyingKey::from_bytes(&bytes).map_err(|_| ContentDiscoveryError::Invalid)?;
    signed
        .verify(&expected, now)
        .map_err(|_| ContentDiscoveryError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use volparossa_content::{Validity, provider::ProviderEndpoint};

    async fn registered_content_runtime()
    -> (DiscoveryRuntime, Arc<RwLock<AgentState>>, tempfile::TempDir) {
        let (mut runtime, state, directory) = super::super::tests::content_runtime_fixture();
        let now_ms = unix_millis();
        let permission = volparossa_policy::ProtocolPort::new(TransportProtocol::Tcp, 18443)
            .expect("content port");
        let rule = volparossa_policy::DestinationRule::exact_domain(
            "replica.volparossa.test",
            [permission],
        )
        .expect("content endpoint");
        // The real threshold-verified policy expires in 30 seconds, before this offer's 300s.
        let policy =
            volparossa_test_support::verified_development_manifest(now_ms - 3_570_000, vec![rule])
                .expect("short remaining policy authority");
        state.write().await.set_policy(Some(policy));
        let pair = runtime
            .identity
            .keypair()
            .clone()
            .try_into_ed25519()
            .unwrap();
        let bytes = zeroize::Zeroizing::new(pair.to_bytes());
        let signer = SigningKey::from_keypair_bytes(&bytes).unwrap();
        let offer = SignedProviderOffer::sign(
            &signer,
            ProviderEndpoint::new("replica.volparossa.test", 18443).unwrap(),
            Validity {
                created: now_ms / 1000,
                expires: now_ms / 1000 + 300,
            },
        )
        .unwrap();
        let (reply, response) = oneshot::channel();
        runtime
            .handle_content_command(
                ContentCommand::Register {
                    offer: Box::new(offer),
                    reply,
                },
                &state,
            )
            .await;
        response
            .await
            .unwrap()
            .expect("verified explicit registration");
        (runtime, state, directory)
    }

    #[tokio::test]
    async fn native_advertisement_withdrawal_does_not_withdraw_owned_content_service() {
        let (mut runtime, state, _directory) = Box::pin(registered_content_runtime()).await;
        let deadline = runtime.content.local.as_ref().unwrap().deadline;
        assert!(deadline > Instant::now());
        assert!(deadline <= Instant::now() + Duration::from_secs(30));
        assert!(runtime.control_addresses.is_empty());
        // Exercise the real native publication gate, not a replacement service implementation.
        runtime.publish_local(&state).await;
        assert!(runtime.served_local_advertisement.is_none());
        assert!(runtime.local_relay_snapshot.is_none());
        assert_eq!(
            runtime.content.local.as_ref().map(|local| local.deadline),
            Some(deadline),
            "a native readiness gap neither withdraws nor renews the independent content offer"
        );
        runtime.reannounce_content_registration();
        assert_eq!(runtime.content.local.as_ref().unwrap().deadline, deadline);
        let (reply, response) = oneshot::channel();
        runtime
            .handle_content_command(ContentCommand::Withdraw { reply }, &state)
            .await;
        response.await.unwrap().unwrap();
        assert!(
            runtime.content.local.is_none(),
            "explicit service stop still withdraws"
        );
    }

    #[tokio::test]
    async fn content_policy_replacement_and_original_deadline_still_withdraw_service() {
        let (mut runtime, state, _directory) = Box::pin(registered_content_runtime()).await;
        let (reply, response) = oneshot::channel();
        runtime
            .handle_command(
                DiscoveryCommand::ApplyPolicy {
                    policy: None,
                    reply,
                },
                &state,
            )
            .await;
        response.await.unwrap();
        assert!(runtime.content.local.is_none());

        let (mut runtime, _state, _directory) = Box::pin(registered_content_runtime()).await;
        runtime.content.local.as_mut().unwrap().deadline = Instant::now();
        runtime.maintain_content();
        assert!(runtime.content.local.is_none());
        assert!(
            runtime
                .content
                .events
                .contains(&"CONTENT_PROVIDER_REGISTRATION_EXPIRED")
        );
        assert!(
            runtime
                .content
                .events
                .contains(&"CONTENT_PROVIDER_WITHDRAWN")
        );
    }

    fn fixture() -> (Libp2pPeerId, SignedProviderOffer) {
        let key = SigningKey::generate(&mut OsRng);
        let public =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(key.verifying_key().as_bytes())
                .expect("generated key");
        let peer = libp2p::identity::PublicKey::from(public).to_peer_id();
        let signed = SignedProviderOffer::sign(
            &key,
            ProviderEndpoint::new("replica.volparossa.test", 18443).expect("canonical endpoint"),
            Validity {
                created: 1000,
                expires: 1300,
            },
        )
        .expect("signed offer");
        (peer, signed)
    }

    #[test]
    fn lookup_diagnostics_distinguish_empty_reply_authority_without_changing_it() {
        for accept in [false, true] {
            for live in [false, true] {
                for relay in [false, true] {
                    for authority in [false, true] {
                        let event = lookup_authority_event(accept, live, relay, authority);
                        assert_eq!(
                            event == "CONTENT_LOOKUP_RESPONSE_AUTHORIZED",
                            accept && live && relay && authority
                        );
                    }
                }
            }
        }
        assert_eq!(
            lookup_authority_event(false, true, true, true),
            "CONTENT_LOOKUP_COLLECTION_REJECTED"
        );
        assert_eq!(
            lookup_authority_event(true, false, true, true),
            "CONTENT_LOOKUP_RESPONSE_EXPIRED"
        );
        assert_eq!(
            lookup_authority_event(true, true, false, true),
            "CONTENT_LOOKUP_RELAY_ROLE_REJECTED"
        );
        assert_eq!(
            lookup_authority_event(true, true, true, false),
            "CONTENT_LOOKUP_RELAY_AUTHORITY_REJECTED"
        );
    }

    #[test]
    fn authenticated_peer_key_is_required_before_offer_is_accepted() {
        let (peer, signed) = fixture();
        let verified =
            verify_provider(peer, &signed.encode(), 1100).expect("matching authenticated peer");
        assert_eq!(verified.endpoint().hostname(), "replica.volparossa.test");
        assert_eq!(verified.endpoint().port(), 18443);
        let (other, _) = fixture();
        assert_eq!(
            verify_provider(other, &signed.encode(), 1100).unwrap_err(),
            ContentDiscoveryError::Invalid
        );
    }

    #[test]
    fn forwarding_does_not_renew_the_original_signed_offer() {
        let (peer, signed) = fixture();
        for now in [1100, 1299] {
            assert_eq!(
                verify_provider(peer, &signed.encode(), now)
                    .unwrap()
                    .validity()
                    .expires,
                1300
            );
        }
        for now in [999, 1300, 1400] {
            assert_eq!(
                verify_provider(peer, &signed.encode(), now).unwrap_err(),
                ContentDiscoveryError::Invalid
            );
        }
    }

    #[test]
    fn signature_corruption_is_not_a_service_hint() {
        let (peer, signed) = fixture();
        let mut bytes = signed.encode();
        *bytes.last_mut().expect("nonempty envelope") ^= 1;
        assert_eq!(
            verify_provider(peer, &bytes, 1100).unwrap_err(),
            ContentDiscoveryError::Invalid
        );
    }

    #[test]
    fn partial_offers_survive_collection_end_only_within_original_response_authority() {
        let (provider, signed) = fixture();
        let recipient = Libp2pPeerId::random();
        let started = Instant::now();
        let mut kademlia = kad::Behaviour::new(recipient, kad::store::MemoryStore::new(recipient));
        let lookup = RelayLookup {
            query: kademlia.get_providers(kad::RecordKey::new(&capability::CONTENT)),
            collection_deadline: started + COLLECTION_TIMEOUT,
            response_deadline: started + REQUEST_TIMEOUT,
            dht_complete: false,
            candidates: HashSet::from([provider]),
            offers: BTreeMap::from([(provider, signed.encode())]),
            waiters: Vec::new(),
        };
        assert_eq!(
            lookup.collection_deadline - started,
            Duration::from_secs(10)
        );
        assert_eq!(lookup.response_deadline - started, Duration::from_secs(15));
        assert!(
            !lookup.dht_complete,
            "a partial reply is not DHT completion"
        );
        assert!(
            lookup
                .offers_for_response(provider, 16, started, 1100)
                .is_empty(),
            "a verified provider offer is never reflected to that same requester"
        );
        for elapsed in [10, 14] {
            let offers = lookup.offers_for_response(
                recipient,
                16,
                started + Duration::from_secs(elapsed),
                1100,
            );
            assert_eq!(offers.len(), 1);
            assert_eq!(offers[0].peer_id().unwrap(), provider);
            assert_eq!(offers[0].signed_offer(), signed.encode());
        }
        for elapsed in [15, 16] {
            assert!(
                lookup
                    .offers_for_response(
                        recipient,
                        16,
                        started + Duration::from_secs(elapsed),
                        1100,
                    )
                    .is_empty()
            );
        }
        assert!(
            lookup
                .offers_for_response(recipient, 16, lookup.collection_deadline, 1300,)
                .is_empty(),
            "collection never extends signed offer expiry"
        );
    }

    #[tokio::test]
    async fn discovery_command_retains_the_carrying_routes_exact_control_peer() {
        let (control_peer, _) = fixture();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let handle = DiscoveryControlHandle::from_sender(sender);
        let request = handle.discover_content_providers(control_peer, 16);
        let actor = async {
            let Some(DiscoveryCommand::Content(ContentCommand::Discover {
                control_peer: selected_control,
                maximum,
                reply,
            })) = receiver.recv().await
            else {
                panic!("exact content discovery command");
            };
            assert_eq!(selected_control, control_peer);
            assert_eq!(maximum, 16);
            assert!(reply.send(Err(ContentDiscoveryError::Invalidated)).is_ok());
        };
        let (result, ()) = tokio::join!(request, actor);
        assert_eq!(result.unwrap_err(), ContentDiscoveryError::Invalidated);
        assert!(
            receiver.try_recv().is_err(),
            "no alternate control fallback"
        );
    }
}
