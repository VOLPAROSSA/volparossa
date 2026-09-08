//! Cache-only DNSSEC exchange owned by the discovery actor. Names never enter the DHT/logs.

use libp2p::{
    PeerId, kad, request_response,
    swarm::{ConnectionId, SwarmEvent},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, oneshot};
use volparossa_discovery::{
    BehaviourEvent, ContentControlConnectionState, DnsCacheRequest, DnsCacheResponse, capability,
};
use volparossa_protocol::{
    ControlPayload, DnsCacheQuery, DnsCacheReply, MAX_DNS_CACHE_LIFETIME_MS, ReplayCache,
    TimePolicy, VerifiedControlMessage, dns_cache_request_hash, generate_nonce,
    sign_control_message_with, verify_control_message,
};
use volparossa_udp::{
    DnsPeerBackend, DnsPeerFuture, DnsProofBundle, DnsQueryType, DnsQuestion, DnsResolutionScope,
    DnsResolverError, ExitResolver,
};

use super::{DiscoveryCommand, DiscoveryControlHandle, DiscoveryRuntime, unix_millis};
use crate::{AgentState, LogLevel};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_LOOKUPS: usize = 8;
const MAX_CANDIDATES: usize = 16;
const MAX_PEERS: usize = 2;
const MAX_STAGE_EVENTS: usize = 32;
type OutboundId = request_response::OutboundRequestId;
type Reply = oneshot::Sender<Result<Option<DnsProofBundle>, DnsResolverError>>;

pub(super) enum DnsCommand {
    Fetch {
        question: DnsQuestion,
        scope: DnsResolutionScope,
        reply: Reply,
    },
}
impl DnsCommand {
    pub(super) fn reject(self) {
        match self {
            Self::Fetch { reply, .. } => {
                let _ = reply.send(Err(DnsResolverError::Unavailable));
            }
        }
    }
}

struct PeerBackend(DiscoveryControlHandle);
impl DnsPeerBackend for PeerBackend {
    fn fetch<'a>(
        &'a self,
        question: &'a DnsQuestion,
        scope: &'a DnsResolutionScope,
    ) -> DnsPeerFuture<'a> {
        Box::pin(async move {
            if !scope.permits_peers() {
                return Ok(None);
            }
            let (reply, answer) = oneshot::channel();
            tokio::time::timeout(LOOKUP_TIMEOUT, async {
                self.0
                    .sender
                    .send(DiscoveryCommand::DnsCache(DnsCommand::Fetch {
                        question: question.clone(),
                        scope: scope.clone(),
                        reply,
                    }))
                    .await
                    .map_err(|_| DnsResolverError::Unavailable)?;
                answer.await.map_err(|_| DnsResolverError::Unavailable)?
            })
            .await
            .map_err(|_| DnsResolverError::Unavailable)?
        })
    }
}

impl DiscoveryControlHandle {
    /// No question is sent until the caller supplies complete route-peer exclusions.
    pub(crate) fn dns_peer_backend(&self) -> Arc<dyn DnsPeerBackend> {
        Arc::new(PeerBackend(self.clone()))
    }
}

struct Lookup {
    question: DnsQuestion,
    excluded: HashSet<PeerId>,
    request: DnsCacheRequest,
    selected: HashSet<PeerId>,
    sent: HashSet<PeerId>,
    deadline: Instant,
    reply: Reply,
}
struct Pending {
    lookup: u64,
    peer: PeerId,
    connection: ConnectionId,
    request_hash: [u8; 32],
}
pub(super) struct DnsBridge {
    pub(super) resolver: Option<Arc<ExitResolver>>,
    advertised: bool,
    advertisement_query: Option<kad::QueryId>,
    publication_ready: bool,
    lookups: HashMap<u64, Lookup>,
    outbound: HashMap<OutboundId, Pending>,
    provider_query: Option<(kad::QueryId, Instant)>,
    candidates: Vec<PeerId>,
    next_id: u64,
    replay: ReplayCache,
    events: VecDeque<(&'static str, u64)>,
}
impl Default for DnsBridge {
    fn default() -> Self {
        Self {
            resolver: None,
            advertised: false,
            advertisement_query: None,
            publication_ready: false,
            lookups: HashMap::new(),
            outbound: HashMap::new(),
            provider_query: None,
            candidates: Vec::new(),
            next_id: 0,
            replay: ReplayCache::new(256).expect("fixed nonzero DNS replay capacity"),
            events: VecDeque::new(),
        }
    }
}

impl DnsBridge {
    // Deduplicate between actor maintenance turns; no names, peers, addresses or raw errors.
    fn stage(&mut self, code: &'static str) {
        if self.events.len() < MAX_STAGE_EVENTS
            && !self.events.iter().any(|(queued, _)| *queued == code)
        {
            self.events.push_back((code, unix_millis()));
        }
    }
}

fn time_policy() -> TimePolicy {
    TimePolicy {
        maximum_lifetime_ms: MAX_DNS_CACHE_LIFETIME_MS,
        maximum_clock_skew_ms: 1000,
    }
}
fn peer_matches<T: ControlPayload>(message: &VerifiedControlMessage<T>, peer: PeerId) -> bool {
    libp2p::identity::ed25519::PublicKey::try_from_bytes(message.sender_public_key())
        .is_ok_and(|key| libp2p::identity::PublicKey::from(key).to_peer_id() == peer)
}
fn exclusions(scope: &DnsResolutionScope) -> Option<HashSet<PeerId>> {
    if !scope.permits_peers() {
        return None;
    }
    scope
        .excluded_peers()
        .iter()
        .map(|bytes| {
            PeerId::from_bytes(bytes)
                .ok()
                .filter(|peer| peer.to_bytes() == *bytes)
        })
        .collect()
}

impl DiscoveryRuntime {
    /// Configure during synchronous agent construction; capability publication waits for `run()`.
    pub(crate) fn configure_dns_cache(&mut self, resolver: Arc<ExitResolver>) {
        self.stop_dns_cache();
        if let Some(service) = &mut self.exit_service {
            service.set_dns_resolver(Arc::clone(&resolver));
        }
        self.dns_cache.resolver = Some(resolver);
    }

    pub(super) fn handle_dns_command(&mut self, command: DnsCommand) {
        match command {
            DnsCommand::Fetch {
                question,
                scope,
                reply,
            } => {
                if reply.is_closed() {
                    return;
                }
                let Some(excluded) = exclusions(&scope) else {
                    self.dns_cache.stage("DNS_CACHE_SCOPE_REJECTED");
                    let _ = reply.send(Ok(None));
                    return;
                };
                if !self.roles.exit || self.dns_cache.lookups.len() >= MAX_LOOKUPS {
                    self.dns_cache.stage("DNS_CACHE_LOOKUP_UNAVAILABLE");
                    let _ = reply.send(Err(DnsResolverError::Unavailable));
                    return;
                }
                let query = DnsCacheQuery {
                    name: question.name().to_owned(),
                    query_type: match question.query_type() {
                        DnsQueryType::A => 1,
                        DnsQueryType::Aaaa => 28,
                    },
                    policy_hash: scope.policy_hash().to_vec(),
                };
                let now = unix_millis();
                let Some(request) = self
                    .sign_dns(&query, now + MAX_DNS_CACHE_LIFETIME_MS)
                    .and_then(|bytes| DnsCacheRequest::new(bytes).ok())
                else {
                    let _ = reply.send(Err(DnsResolverError::Unavailable));
                    return;
                };
                let Some(id) = self.dns_cache.next_id.checked_add(1) else {
                    let _ = reply.send(Err(DnsResolverError::Unavailable));
                    return;
                };
                if self.dns_cache.provider_query.is_none() {
                    let Ok(query) = self.service.find_providers(capability::DNSSEC_CACHE) else {
                        self.dns_cache.stage("DNS_CACHE_QUERY_REJECTED");
                        let _ = reply.send(Err(DnsResolverError::Unavailable));
                        return;
                    };
                    self.dns_cache.candidates.clear();
                    self.dns_cache.provider_query =
                        Some((query, Instant::now() + COLLECTION_TIMEOUT));
                    self.dns_cache.stage("DNS_CACHE_QUERY_STARTED");
                }
                self.dns_cache.next_id = id;
                self.dns_cache.lookups.insert(
                    id,
                    Lookup {
                        question,
                        excluded,
                        request,
                        selected: HashSet::new(),
                        sent: HashSet::new(),
                        deadline: Instant::now() + LOOKUP_TIMEOUT,
                        reply,
                    },
                );
                self.choose_dns_peers();
            }
        }
    }

    fn sign_dns<T: ControlPayload>(&self, payload: &T, expires: u64) -> Option<Vec<u8>> {
        sign_control_message_with(
            payload,
            self.local_public_key,
            unix_millis(),
            expires,
            generate_nonce(),
            time_policy(),
            |bytes| self.identity.sign(bytes).ok(),
        )
        .ok()
    }

    fn choose_dns_peers(&mut self) {
        let candidates = self.dns_cache.candidates.clone();
        let local = *self.service.local_peer_id();
        let mut connecting = HashSet::new();
        for lookup in self.dns_cache.lookups.values_mut() {
            for peer in &candidates {
                if lookup.selected.len() >= MAX_PEERS {
                    break;
                }
                if *peer != local
                    && !lookup.excluded.contains(peer)
                    && lookup.selected.insert(*peer)
                {
                    connecting.insert(*peer);
                }
            }
        }
        for peer in connecting {
            let state = self.service.content_control_connection_state(&peer);
            self.dns_cache.stage(match state {
                ContentControlConnectionState::Unique => "DNS_CACHE_CONNECTION_UNIQUE",
                ContentControlConnectionState::Multiple => "DNS_CACHE_CONNECTION_MULTIPLE",
                ContentControlConnectionState::Missing => "DNS_CACHE_CONNECTION_MISSING",
                ContentControlConnectionState::NoDirect => "DNS_CACHE_CONNECTION_NOT_DIRECT",
                ContentControlConnectionState::Poisoned => "DNS_CACHE_CONNECTION_POISONED",
            });
            if matches!(
                state,
                ContentControlConnectionState::Unique | ContentControlConnectionState::Multiple
            ) {
                self.send_dns_on_ready_peer(peer);
            } else if state == ContentControlConnectionState::Missing {
                // Only generic connection establishment is allowed here, never question bytes.
                if self.service.connect_dns_cache_peer(peer).is_err() {
                    self.dns_cache.stage("DNS_CACHE_CONNECT_REJECTED");
                }
            }
        }
    }

    fn send_dns_on_ready_peer(&mut self, peer: PeerId) {
        if !matches!(
            self.service.content_control_connection_state(&peer),
            ContentControlConnectionState::Unique | ContentControlConnectionState::Multiple
        ) {
            return;
        }
        let mut dispatched = false;
        let mut rejected = false;
        for (id, lookup) in &mut self.dns_cache.lookups {
            if lookup.deadline <= Instant::now()
                || lookup.reply.is_closed()
                || !lookup.selected.contains(&peer)
                || lookup.excluded.contains(&peer)
                || !lookup.sent.insert(peer)
            {
                continue;
            }
            if let Ok((request_id, connection)) =
                self.service.request_dns_cache(peer, lookup.request.clone())
            {
                dispatched = true;
                self.dns_cache.outbound.insert(
                    request_id,
                    Pending {
                        lookup: *id,
                        peer,
                        connection,
                        request_hash: dns_cache_request_hash(lookup.request.signed()),
                    },
                );
            } else {
                rejected = true;
            }
        }
        if dispatched {
            self.dns_cache.stage("DNS_CACHE_REQUEST_DISPATCHED");
        }
        if rejected {
            self.dns_cache.stage("DNS_CACHE_REQUEST_REJECTED");
        }
    }

    pub(super) fn handle_dns_event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
    ) -> Option<SwarmEvent<BehaviourEvent>> {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id,
                    result: kad::QueryResult::StartProviding(result),
                    ..
                },
            )) if self.dns_cache.advertisement_query == Some(id) => {
                self.dns_cache.advertisement_query = None;
                self.dns_cache.publication_ready = result.is_ok();
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::DnsCache(event)) => {
                self.handle_dns_rpc(event);
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id, result, step, ..
                },
            )) if self
                .dns_cache
                .provider_query
                .is_some_and(|(query, _)| query == id) =>
            {
                if let kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    key,
                    providers,
                })) = result
                {
                    if key == kad::RecordKey::new(&capability::DNSSEC_CACHE) {
                        self.dns_cache.stage("DNS_CACHE_PROVIDERS_FOUND");
                        for peer in providers {
                            if self.dns_cache.candidates.len() >= MAX_CANDIDATES {
                                break;
                            }
                            if !self.dns_cache.candidates.contains(&peer) {
                                self.dns_cache.candidates.push(peer);
                            }
                        }
                        self.choose_dns_peers();
                    }
                }
                if step.last {
                    self.dns_cache.stage("DNS_CACHE_QUERY_COMPLETED");
                    self.finish_dns_query();
                }
                None
            }
            event @ SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.send_dns_on_ready_peer(peer_id);
                Some(event)
            }
            other => Some(other),
        }
    }

    fn handle_dns_rpc(
        &mut self,
        event: request_response::Event<DnsCacheRequest, DnsCacheResponse>,
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
                    self.dns_cache.stage("DNS_CACHE_REQUEST_RECEIVED");
                    if !(self.roles.client || self.roles.relay || self.roles.exit) {
                        return;
                    }
                    if !self
                        .service
                        .content_control_connection_is_current(&peer, connection_id)
                    {
                        self.dns_cache.stage("DNS_CACHE_INBOUND_LINEAGE_REJECTED");
                        return;
                    }
                    let Ok(verified) = verify_control_message::<DnsCacheQuery>(
                        request.signed(),
                        unix_millis(),
                        time_policy(),
                        &mut self.dns_cache.replay,
                    ) else {
                        self.dns_cache.stage("DNS_CACHE_INBOUND_SIGNATURE_REJECTED");
                        return;
                    };
                    if !peer_matches(&verified, peer) {
                        return;
                    }
                    let query = verified.message();
                    let Ok(policy) = <[u8; 32]>::try_from(query.policy_hash.as_slice()) else {
                        return;
                    };
                    let kind = if query.query_type == 1 {
                        DnsQueryType::A
                    } else {
                        DnsQueryType::Aaaa
                    };
                    let Ok(question) = DnsQuestion::new(&query.name, kind) else {
                        return;
                    };
                    let Some(resolver) = &self.dns_cache.resolver else {
                        self.dns_cache.stage("DNS_CACHE_RESPONDER_UNAVAILABLE");
                        return;
                    };
                    // This synchronous accessor reads independently validated positive RAM entries only.
                    // A miss never calls resolve(), recursive DNS, or the operating-system resolver.
                    let bundle = resolver
                        .cached_bundle(&question, &policy)
                        .map(|b| b.encode())
                        .unwrap_or_default();
                    let cache_miss = bundle.is_empty();
                    self.dns_cache.stage(if cache_miss {
                        "DNS_CACHE_REPLY_EMPTY"
                    } else {
                        "DNS_CACHE_REPLY_BUNDLE"
                    });
                    let reply = DnsCacheReply {
                        request_hash: dns_cache_request_hash(request.signed()).to_vec(),
                        bundle,
                    };
                    if let Some(response) = self
                        .sign_dns(&reply, verified.expires_at_ms())
                        .and_then(|bytes| DnsCacheResponse::new(bytes).ok())
                    {
                        if self
                            .service
                            .respond_dns_cache(peer, connection_id, channel, response)
                            .is_ok()
                            && cache_miss
                        {
                            self.metrics.record_dns_cache_miss_reply();
                        }
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => self.handle_dns_response(peer, connection_id, request_id, &response),
            },
            request_response::Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => self.handle_dns_failure(peer, connection_id, request_id, &error),
            _ => {}
        }
    }

    fn handle_dns_failure(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        request: OutboundId,
        error: &request_response::OutboundFailure,
    ) {
        if !self
            .dns_cache
            .outbound
            .get(&request)
            .is_some_and(|p| p.peer == peer && p.connection == connection)
        {
            return;
        }
        self.service.finish_dns_cache_request(request);
        self.dns_cache.outbound.remove(&request);
        self.dns_cache.stage(match error {
            request_response::OutboundFailure::DialFailure => "DNS_CACHE_RPC_DIAL_FAILED",
            request_response::OutboundFailure::Timeout => "DNS_CACHE_RPC_TIMEOUT",
            request_response::OutboundFailure::ConnectionClosed => {
                "DNS_CACHE_RPC_CONNECTION_CLOSED"
            }
            request_response::OutboundFailure::UnsupportedProtocols => "DNS_CACHE_RPC_UNSUPPORTED",
            request_response::OutboundFailure::Io(_) => "DNS_CACHE_RPC_IO_FAILED",
        });
    }

    fn handle_dns_response(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundId,
        response: &DnsCacheResponse,
    ) {
        let Some(pending) = self.dns_cache.outbound.get(&request_id) else {
            return;
        };
        if peer != pending.peer
            || connection_id != pending.connection
            || !self
                .service
                .content_control_connection_is_current(&peer, connection_id)
        {
            self.dns_cache.stage("DNS_CACHE_RESPONSE_LINEAGE_REJECTED");
            return;
        }
        let pending = self
            .dns_cache
            .outbound
            .remove(&request_id)
            .expect("checked pending request");
        self.service.finish_dns_cache_request(request_id);
        let Ok(verified) = verify_control_message::<DnsCacheReply>(
            response.signed(),
            unix_millis(),
            time_policy(),
            &mut self.dns_cache.replay,
        ) else {
            self.dns_cache
                .stage("DNS_CACHE_RESPONSE_SIGNATURE_REJECTED");
            return;
        };
        if !peer_matches(&verified, peer) || verified.message().request_hash != pending.request_hash
        {
            self.dns_cache.stage("DNS_CACHE_RESPONSE_BINDING_REJECTED");
            return;
        }
        let Some(lookup) = self.dns_cache.lookups.get(&pending.lookup) else {
            return;
        };
        if lookup.deadline <= Instant::now() || lookup.excluded.contains(&peer) {
            return;
        }
        if verified.message().bundle.is_empty() {
            self.dns_cache.stage("DNS_CACHE_RESPONSE_EMPTY_VERIFIED");
            return;
        }
        let Ok(bundle) = DnsProofBundle::decode(&verified.message().bundle) else {
            self.dns_cache.stage("DNS_CACHE_RESPONSE_BUNDLE_REJECTED");
            return;
        };
        if bundle.question() != &lookup.question || bundle.expires_at_unix_ms() <= unix_millis() {
            self.dns_cache.stage("DNS_CACHE_RESPONSE_BUNDLE_REJECTED");
            return;
        }
        // This stage proves the signed peer envelope, not DNSSEC: the resolver validates that.
        self.dns_cache.stage("DNS_CACHE_RESPONSE_BUNDLE_RECEIVED");
        self.finish_dns_lookup(pending.lookup, Some(bundle));
    }

    fn finish_dns_lookup(&mut self, id: u64, bundle: Option<DnsProofBundle>) {
        if let Some(lookup) = self.dns_cache.lookups.remove(&id) {
            let _ = lookup.reply.send(Ok(bundle));
        }
        let requests: Vec<_> = self
            .dns_cache
            .outbound
            .iter()
            .filter_map(|(request, p)| (p.lookup == id).then_some(*request))
            .collect();
        for request in requests {
            self.dns_cache.outbound.remove(&request);
            self.service.finish_dns_cache_request(request);
        }
    }
    fn finish_dns_query(&mut self) {
        if let Some((query, _)) = self.dns_cache.provider_query.take() {
            let _ = self.service.finish_dns_cache_provider_query(query);
        }
    }
    pub(super) async fn maintain_dns_cache(&mut self, state: &Arc<RwLock<AgentState>>) {
        if let Some(resolver) = &self.dns_cache.resolver {
            let counts = resolver.counts();
            self.metrics.set_dns_resolution_counts(
                counts.local_validated,
                counts.peer_validated,
                counts.upstream_validated,
                counts.trusted_fallback,
            );
        }
        // Having a resolver configured is not an offer: a cold consumer must not publish its
        // permanent identity/address as an empty cache for unrelated Exits to dial.
        let available = (self.roles.client || self.roles.relay || self.roles.exit)
            && state
                .read()
                .await
                .active_policy(unix_millis())
                .is_some_and(|policy| {
                    self.dns_cache
                        .resolver
                        .as_ref()
                        .is_some_and(|resolver| resolver.has_shareable_proof(policy.policy_hash()))
                });
        if self.dns_cache.advertised && !available {
            let _ = self.service.stop_providing(capability::DNSSEC_CACHE);
            self.dns_cache.advertised = false;
            self.dns_cache.advertisement_query = None;
            self.dns_cache.publication_ready = false;
            state.write().await.log(
                LogLevel::Info,
                "DNS_CACHE_PROVIDER_WITHDRAWN",
                unix_millis(),
            );
        }
        if available && !self.dns_cache.advertised {
            self.dns_cache.advertisement_query =
                self.service.provide(capability::DNSSEC_CACHE).ok();
            self.dns_cache.advertised = self.dns_cache.advertisement_query.is_some();
        }
        if available && std::mem::take(&mut self.dns_cache.publication_ready) {
            // Kademlia completed its publication query; this is not a remote receipt or a
            // guarantee that an already propagated provider record can be recalled on expiry.
            state.write().await.log(
                LogLevel::Info,
                "DNS_CACHE_PROVIDER_AVAILABLE",
                unix_millis(),
            );
        }
        let now = Instant::now();
        if self
            .dns_cache
            .provider_query
            .is_some_and(|(_, expires)| expires <= now)
        {
            self.dns_cache.stage("DNS_CACHE_COLLECTION_DEADLINE");
            self.finish_dns_query();
        }
        let finished: Vec<_> = self
            .dns_cache
            .lookups
            .iter()
            .filter_map(|(id, lookup)| {
                (lookup.deadline <= now
                    || lookup.reply.is_closed()
                    || !self.roles.exit
                    || (self.dns_cache.provider_query.is_none()
                        && lookup.selected.len() == lookup.sent.len()
                        && !self
                            .dns_cache
                            .outbound
                            .values()
                            .any(|pending| pending.lookup == *id)))
                .then_some(*id)
            })
            .collect();
        for id in finished {
            let code = self.dns_cache.lookups.get(&id).map(|lookup| {
                if lookup.reply.is_closed() {
                    "DNS_CACHE_LOOKUP_CALLER_CLOSED"
                } else if lookup.deadline <= now {
                    "DNS_CACHE_LOOKUP_DEADLINE"
                } else if lookup.selected.is_empty() {
                    "DNS_CACHE_LOOKUP_NO_CANDIDATE"
                } else {
                    "DNS_CACHE_LOOKUP_NO_BUNDLE"
                }
            });
            if let Some(code) = code {
                self.dns_cache.stage(code);
            }
            self.finish_dns_lookup(id, None);
        }
        if self.dns_cache.lookups.is_empty() {
            self.finish_dns_query();
        }
        if !self.dns_cache.events.is_empty() {
            let mut state = state.write().await;
            for (code, timestamp) in self.dns_cache.events.drain(..) {
                state.log(LogLevel::Info, code, timestamp);
            }
        }
    }
    pub(super) fn dns_deadline(&self) -> tokio::time::Instant {
        self.dns_cache
            .lookups
            .values()
            .map(|p| p.deadline)
            .chain(self.dns_cache.provider_query.map(|(_, deadline)| deadline))
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600))
            .into()
    }
    pub(super) fn stop_dns_cache(&mut self) {
        for id in self.dns_cache.lookups.keys().copied().collect::<Vec<_>>() {
            self.finish_dns_lookup(id, None);
        }
        self.finish_dns_query();
        let _ = self.service.stop_providing(capability::DNSSEC_CACHE);
        self.dns_cache.advertised = false;
        self.dns_cache.advertisement_query = None;
        self.dns_cache.publication_ready = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_discovery::DiscoveryEvent;

    fn run_actor_test_in_isolated_namespace(test: &str) -> bool {
        const MARKER: &str = "VOLPAROSSA_DNS_CACHE_PARENT_NETNS";
        if let Some(parent) = std::env::var_os(MARKER) {
            let current = std::fs::read_link("/proc/self/ns/net").unwrap();
            assert_ne!(
                current.as_os_str(),
                parent,
                "actor requires a new network namespace"
            );
            return false;
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-test.sh");
        let status = std::process::Command::new(runner)
            .arg(std::env::current_exe().unwrap())
            .arg(test)
            .arg(MARKER)
            .arg("none")
            .status()
            .unwrap();
        assert!(status.success(), "isolated actor test failed: {status}");
        true
    }

    #[test]
    fn missing_or_invalid_route_exclusions_never_allow_a_peer_query() {
        assert!(exclusions(&DnsResolutionScope::without_peers([1; 32])).is_none());
        let bad = DnsResolutionScope::new([1; 32], vec![vec![1, 2, 3]]).unwrap();
        assert!(exclusions(&bad).is_none());
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let scope = DnsResolutionScope::new([1; 32], vec![peer.to_bytes()]).unwrap();
        assert_eq!(exclusions(&scope).unwrap(), HashSet::from([peer]));
    }

    #[tokio::test]
    async fn actual_dns_cache_actor_returns_signed_cache_miss_without_upstream_and_excludes_route_peers()
     {
        if run_actor_test_in_isolated_namespace(
            "discovery::dns_cache::tests::actual_dns_cache_actor_returns_signed_cache_miss_without_upstream_and_excludes_route_peers",
        ) {
            return;
        }
        Box::pin(cache_miss_actor_exchange(1)).await;
    }

    #[tokio::test]
    async fn actual_dns_cache_actor_pins_two_authenticated_connections() {
        if run_actor_test_in_isolated_namespace(
            "discovery::dns_cache::tests::actual_dns_cache_actor_pins_two_authenticated_connections",
        ) {
            return;
        }
        Box::pin(cache_miss_actor_exchange(2)).await;
    }

    async fn cache_miss_actor_exchange(connections: usize) {
        let (mut exit, exit_state, _exit_dir) = super::super::tests::retirement_runtime_fixture();
        let (mut cache, cache_state, _cache_dir) =
            super::super::tests::retirement_runtime_fixture();
        for _ in 0..connections {
            super::super::tests::connect_runtime_client_to_control(&mut exit, &mut cache.service)
                .await;
        }
        assert_eq!(
            exit.service
                .content_control_connection_state(cache.service.local_peer_id()),
            if connections == 1 {
                ContentControlConnectionState::Unique
            } else {
                ContentControlConnectionState::Multiple
            },
            "real authenticated sibling connections must exist before the DNS request"
        );
        let (peer, question) =
            cold_cache_and_exclusions(&mut exit, &exit_state, &mut cache, &cache_state).await;
        let other = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut responses = Vec::new();
        for _ in 0..connections {
            let (reply, response) = oneshot::channel();
            exit.handle_dns_command(DnsCommand::Fetch {
                question: question.clone(),
                scope: DnsResolutionScope::new([1; 32], vec![other.to_bytes()]).unwrap(),
                reply,
            });
            responses.push(response);
        }
        // Test only the exact actor/cache/RPC seam. Generic DHT discovery is not mocked as proven.
        exit.dns_cache.candidates = vec![peer];
        exit.choose_dns_peers();
        exit.finish_dns_query();
        assert_eq!(exit.dns_cache.outbound.len(), connections);
        assert_eq!(
            exit.dns_cache
                .outbound
                .values()
                .map(|p| p.connection)
                .collect::<HashSet<_>>()
                .len(),
            connections,
            "capture both actual round-robin siblings, never select an arbitrary first connection"
        );
        assert_eq!(
            exit.dns_cache
                .outbound
                .values()
                .map(|p| p.request_hash)
                .collect::<HashSet<_>>()
                .len(),
            connections,
            "each request has its own fresh signed nonce"
        );
        let response = async move {
            let mut results = Vec::new();
            for response in responses {
                results.push(response.await);
            }
            results
        };
        tokio::pin!(response);
        let mut cache_requests = 0;
        let mut rejected_wrong_sibling = false;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                exit.maintain_dns_cache(&exit_state).await;
                tokio::select! {
                    result = &mut response => break result,
                    event = exit.service.next_event() => if let DiscoveryEvent::Other(event) = event {
                        if connections == 2 && !rejected_wrong_sibling {
                            rejected_wrong_sibling = reject_wrong_sibling(&mut exit, &event);
                        }
                        let _ = exit.handle_dns_event(event);
                    },
                    event = cache.service.next_event() => if let DiscoveryEvent::Other(event) = event {
                        if matches!(&event, SwarmEvent::Behaviour(BehaviourEvent::DnsCache(request_response::Event::Message { message: request_response::Message::Request { .. }, .. }))) { cache_requests += 1; }
                        let _ = cache.handle_dns_event(event);
                    },
                }
            }
        }).await.unwrap();
        assert!(
            result
                .into_iter()
                .all(|answer| answer.unwrap().unwrap().is_none())
        );
        assert_eq!(rejected_wrong_sibling, connections == 2);
        assert_eq!(cache_requests, connections);
        assert_completed_misses(&exit, &cache, connections, &question);
    }

    fn assert_completed_misses(
        exit: &DiscoveryRuntime,
        cache: &DiscoveryRuntime,
        connections: usize,
        question: &DnsQuestion,
    ) {
        assert!(exit.dns_cache.outbound.is_empty());
        assert!(exit.dns_cache.lookups.is_empty());
        assert!(exit.dns_cache.provider_query.is_none());
        assert_eq!(
            cache.metrics.snapshot().dns_cache_miss_replies,
            u64::try_from(connections).unwrap()
        );
        assert_eq!(exit.metrics.snapshot().dns_cache_miss_replies, 0);
        assert_eq!(cache.dns_cache.replay.len(), connections);
        assert_eq!(
            exit.dns_cache.replay.len(),
            connections,
            "the miss was independently signed and correlated"
        );
        assert!(
            cache
                .dns_cache
                .resolver
                .as_ref()
                .unwrap()
                .cached_bundle(question, &[1; 32])
                .is_none()
        );
    }

    async fn cold_cache_and_exclusions(
        exit: &mut DiscoveryRuntime,
        exit_state: &Arc<RwLock<AgentState>>,
        cache: &mut DiscoveryRuntime,
        cache_state: &Arc<RwLock<AgentState>>,
    ) -> (PeerId, DnsQuestion) {
        cache.configure_dns_cache(Arc::new(ExitResolver::new(None, None)));
        // A real cold resolver cannot publish DNSSEC_CACHE; withdraw an actual old provider
        // operation as well, including its late completion event.
        cache.roles = volparossa_config::RolesConfig {
            client: true,
            relay: false,
            exit: false,
        };
        cache.maintain_dns_cache(cache_state).await;
        assert!(!cache.dns_cache.advertised);
        assert!(cache.dns_cache.advertisement_query.is_none());
        let old_query = cache.service.provide(capability::DNSSEC_CACHE).unwrap();
        cache.dns_cache.advertised = true;
        cache.dns_cache.advertisement_query = Some(old_query);
        cache.dns_cache.publication_ready = true;
        cache.maintain_dns_cache(cache_state).await;
        assert!(!cache.dns_cache.advertised);
        assert!(cache.dns_cache.advertisement_query.is_none());
        assert!(!cache.dns_cache.publication_ready);
        let peer = *cache.service.local_peer_id();
        let question = DnsQuestion::new("www.example.org", DnsQueryType::A).unwrap();
        // Self and the live cache peer are excluded: no DNS-bearing RPC can exist.
        let (reply, response) = oneshot::channel();
        exit.handle_dns_command(DnsCommand::Fetch {
            question: question.clone(),
            scope: DnsResolutionScope::new([1; 32], vec![peer.to_bytes()]).unwrap(),
            reply,
        });
        exit.dns_cache.candidates = vec![peer, *exit.service.local_peer_id()];
        exit.choose_dns_peers();
        assert!(exit.dns_cache.outbound.is_empty());
        exit.finish_dns_query();
        exit.maintain_dns_cache(exit_state).await;
        assert!(response.await.unwrap().unwrap().is_none());
        (peer, question)
    }

    fn reject_wrong_sibling(
        exit: &mut DiscoveryRuntime,
        event: &SwarmEvent<BehaviourEvent>,
    ) -> bool {
        let SwarmEvent::Behaviour(BehaviourEvent::DnsCache(request_response::Event::Message {
            peer,
            connection_id,
            message:
                request_response::Message::Response {
                    request_id,
                    response,
                },
        })) = event
        else {
            return false;
        };
        assert_eq!(
            exit.dns_cache.outbound[request_id].connection,
            *connection_id
        );
        let sibling = exit
            .dns_cache
            .outbound
            .values()
            .find(|p| p.connection != *connection_id)
            .unwrap()
            .connection;
        let pending = exit.dns_cache.outbound.len();
        let replay = exit.dns_cache.replay.len();
        // A correctly signed real response still cannot consume another connection's request.
        exit.handle_dns_response(*peer, sibling, *request_id, response);
        exit.handle_dns_rpc(request_response::Event::OutboundFailure {
            peer: *peer,
            connection_id: sibling,
            request_id: *request_id,
            error: request_response::OutboundFailure::ConnectionClosed,
        });
        assert_eq!(exit.dns_cache.outbound.len(), pending);
        assert_eq!(exit.dns_cache.replay.len(), replay);
        true
    }
}
