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
    ContentDiscoveryRequest, ContentDiscoveryResponse, ContentProviderOffer, ContentServiceRequest,
    ContentServiceResponse,
};
use volparossa_policy::TransportProtocol;

const MAX_OFFERS: usize = 16;
const MAX_PENDING: usize = 32;
const MAX_REPLAY: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
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
    deadline: Instant,
    dht_complete: bool,
    candidates: HashSet<Libp2pPeerId>,
    offers: BTreeMap<Libp2pPeerId, Vec<u8>>,
    waiters: Vec<RelayWaiter>,
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
            .chain(self.relay.iter().map(|r| r.deadline))
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
                    let _ = pending.reply.send(Err(ContentDiscoveryError::Invalidated));
                }
            }
            if let Some(lookup) = self.content.relay.as_mut() {
                lookup.waiters.retain(|waiter| {
                    waiter.peer != *peer_id || waiter.connection != *connection_id
                });
                if lookup.waiters.is_empty() {
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
                            self.finish_content_lookup(false);
                            return None;
                        }
                        self.dispatch_content_providers(providers);
                    }
                    kad::QueryResult::GetProviders(Err(_)) => {
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
                    if result.is_ok() {
                        self.content.event("CONTENT_DISCOVERY_COMPLETED");
                    }
                    let _ = pending.reply.send(result);
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some(pending) = self.content.clients.remove(&request_id) {
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
            || self.service.content_control_connection(&peer).ok() != Some(connection)
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
        let Ok(nonce) = <[u8; 32]>::try_from(request.nonce()) else {
            return;
        };
        if !self.roles.relay
            || self.relay_service.is_none()
            || self
                .local_relay_snapshot
                .as_ref()
                .is_none_or(|cap| cap.expires_at_ms <= unix_millis().saturating_add(15_000))
            || peer == *self.service.local_peer_id()
            || self.service.content_control_connection(&peer).ok() != Some(connection)
            || self.content.pending() >= MAX_PENDING
            || self.content.replay.len() >= MAX_REPLAY
            || self.content.replay.contains_key(&(peer, nonce))
        {
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
            return;
        }
        let Ok(query) = self.service.find_providers(capability::CONTENT) else {
            self.send_empty_content_response(&waiter.request, waiter.channel);
            return;
        };
        self.content.relay = Some(RelayLookup {
            query,
            deadline: Instant::now() + REQUEST_TIMEOUT,
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
                continue;
            }
            if let Ok(id) = self
                .service
                .request_content_service(&peer, ContentServiceRequest::new())
            {
                self.content.upstream.insert(id, peer);
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
                    if let Some(offer) = response
                        .offer()
                        .filter(|bytes| verify_provider(peer, bytes, unix_seconds()).is_ok())
                    {
                        if let Some(lookup) = self
                            .content
                            .relay
                            .as_mut()
                            .filter(|lookup| lookup.deadline > Instant::now())
                        {
                            lookup.offers.insert(peer, offer.to_vec());
                            self.content.event("CONTENT_PROVIDER_OFFER_VERIFIED");
                        }
                    }
                }
                self.maybe_finish_content_lookup();
            }
            request_response::Event::OutboundFailure { request_id, .. } => {
                self.content.upstream.remove(&request_id);
                self.maybe_finish_content_lookup();
            }
            // Inbound generic service requests are auto-answered by the libdiscovery pump.
            _ => {}
        }
    }

    fn maybe_finish_content_lookup(&mut self) {
        if self
            .content
            .relay
            .as_ref()
            .is_some_and(|lookup| lookup.dht_complete)
            && self.content.upstream.is_empty()
        {
            self.finish_content_lookup(true);
        }
    }

    fn finish_content_lookup(&mut self, successful: bool) {
        let Some(lookup) = self.content.relay.take() else {
            return;
        };
        let _ = self.service.finish_content_provider_query(lookup.query);
        self.content.upstream.clear();
        let valid = successful
            && lookup.deadline > Instant::now()
            && self.roles.relay
            && self
                .local_relay_snapshot
                .as_ref()
                .is_some_and(|cap| cap.expires_at_ms > unix_millis());
        for waiter in lookup.waiters {
            if self.service.content_control_connection(&waiter.peer).ok() != Some(waiter.connection)
            {
                continue;
            }
            let offers = if valid {
                lookup
                    .offers
                    .iter()
                    .filter(|(peer, bytes)| {
                        **peer != waiter.peer
                            && verify_provider(**peer, bytes, unix_seconds()).is_ok()
                    })
                    .take(waiter.request.maximum_offers())
                    .filter_map(|(peer, bytes)| {
                        ContentProviderOffer::new(*peer, bytes.clone()).ok()
                    })
                    .collect()
            } else {
                Vec::new()
            };
            if let Ok(response) = ContentDiscoveryResponse::new(&waiter.request, offers) {
                let _ = self
                    .service
                    .send_content_discovery_response(waiter.channel, response);
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
        if reply.is_closed() {
            return;
        }
        let Ok(request) = ContentDiscoveryRequest::new(maximum) else {
            let _ = reply.send(Err(ContentDiscoveryError::Invalid));
            return;
        };
        if !self.roles.client || self.content.pending() >= MAX_PENDING {
            let _ = reply.send(Err(ContentDiscoveryError::Busy));
            return;
        }
        let until = unix_millis().saturating_add(15_000);
        let control = self
            .direct_relays
            .get(&control_peer)
            .filter(|c| c.expires_at_ms > until && c.peer_id != *self.service.local_peer_id())
            .and_then(|c| {
                self.service
                    .content_control_connection(&c.peer_id)
                    .ok()
                    .map(|id| (c.clone(), id))
            });
        let Some((control, connection)) = control else {
            let _ = reply.send(Err(ContentDiscoveryError::Unavailable));
            return;
        };
        match self
            .service
            .request_content_discovery(&control.peer_id, connection, request)
        {
            Ok(id) => {
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
            }
            Err(_) => {
                let _ = reply.send(Err(ContentDiscoveryError::Unavailable));
            }
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
                let _ = pending.reply.send(Err(ContentDiscoveryError::Timeout));
            }
        }
        if self
            .content
            .relay
            .as_ref()
            .is_some_and(|lookup| lookup.deadline <= now)
        {
            self.finish_content_lookup(false);
        }
    }

    pub(super) fn withdraw_content_registration(&mut self) {
        self.content.local = None;
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
        self.finish_content_lookup(false);
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
