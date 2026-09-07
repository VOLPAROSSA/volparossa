//! Bounded public content-service discovery, never content or object discovery.
//!
//! Clients ask an already authenticated control relay for opaque signed service offers. Only
//! the relay-facing API can request an individual provider's offer. The agent validates offer
//! signatures, identity, lifetime and policy; these bytes confer no route or Exit authority.

use std::{
    collections::HashMap,
    io,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    PeerId, StreamProtocol, kad, request_response,
    swarm::{ConnectionId, SwarmEvent},
};
use prost::Message;
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use volparossa_protocol::{decode_canonical, encode_canonical};

use crate::{
    BehaviourEvent, ContentControlConnectionState, DiscoveryError, DiscoveryService,
    advertisement_budget::AdvertisementBudgets,
};

/// Control relay to individual content provider, without an object identifier.
pub const CONTENT_SERVICE_PROTOCOL: &str = "/volparossa/content-service/1";
/// Client to an authenticated current control relay, without an object identifier.
pub const CONTENT_DISCOVERY_PROTOCOL: &str = "/volparossa/content-discovery/1";
/// Maximum number of opaque signed service offers per discovery response.
pub const MAX_CONTENT_OFFERS: usize = 16;
/// Maximum encoded size of one independently signed service offer.
pub const MAX_CONTENT_OFFER_BYTES: usize = 2_048;
/// Maximum encoded response size, including protobuf framing.
pub const MAX_CONTENT_DISCOVERY_FRAME_BYTES: usize = 36 * 1_024;
/// Combined pending outbound request budget across both protocols.
pub const MAX_PENDING_CONTENT_REQUESTS: usize = 32;
/// Deadline for each request-response exchange.
pub const CONTENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_BYTES: usize = 64;
const SERVICE_RESPONSE_BYTES: usize = MAX_CONTENT_OFFER_BYTES + 64;
const NONCE_BYTES: usize = 32;

/// Detail-free canonical framing or request-correlation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ContentProviderRpcError {
    /// A version, allocation bound, nonce or canonical protobuf encoding is invalid.
    #[error("invalid content provider RPC frame")]
    InvalidFrame,
    /// A response does not echo the original request or exceeds its requested limit.
    #[error("content provider RPC response correlation failed")]
    Correlation,
}

/// Request for one provider's generic, independently signed service offer.
#[derive(Clone, PartialEq, Message)]
pub struct ContentServiceRequest {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
}

impl ContentServiceRequest {
    /// Generate a fresh request; this does not dial a peer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 1,
            nonce: random_nonce(),
        }
    }

    fn validate(&self) -> Result<(), ContentProviderRpcError> {
        validate_header(self.version, &self.nonce)
    }
}

/// One opaque signed offer, or an empty offer when no service is registered.
#[derive(Clone, PartialEq, Message)]
pub struct ContentServiceResponse {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    offer: Vec<u8>,
}

impl ContentServiceResponse {
    /// Echo a validated request with an optional bounded service offer.
    ///
    /// # Errors
    /// Rejects an invalid request or an empty/oversized explicit offer.
    pub fn new(
        request: &ContentServiceRequest,
        offer: Option<Vec<u8>>,
    ) -> Result<Self, ContentProviderRpcError> {
        request.validate()?;
        if let Some(offer) = &offer {
            validate_offer(offer)?;
        }
        Ok(Self {
            version: 1,
            nonce: request.nonce.clone(),
            offer: offer.unwrap_or_default(),
        })
    }

    /// Borrow the untrusted signed offer. Its signature and policy require caller validation.
    #[must_use]
    pub fn offer(&self) -> Option<&[u8]> {
        (!self.offer.is_empty()).then_some(self.offer.as_slice())
    }

    /// Enforce the exact request nonce in addition to structural bounds.
    ///
    /// # Errors
    /// Rejects malformed frames or a response to another request.
    pub fn validate_for(
        &self,
        request: &ContentServiceRequest,
    ) -> Result<(), ContentProviderRpcError> {
        request.validate()?;
        self.validate()?;
        if self.nonce != request.nonce {
            return Err(ContentProviderRpcError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ContentProviderRpcError> {
        validate_header(self.version, &self.nonce)?;
        if !self.offer.is_empty() {
            validate_offer(&self.offer)?;
        }
        Ok(())
    }
}

/// Bounded request for generic public services through a control relay.
#[derive(Clone, PartialEq, Message)]
pub struct ContentDiscoveryRequest {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(uint32, tag = "3")]
    maximum_offers: u32,
}

impl ContentDiscoveryRequest {
    /// Generate a fresh request for one to sixteen offers; no object interests are encoded.
    ///
    /// # Errors
    /// Rejects an empty or excessive requested offer count.
    pub fn new(maximum_offers: usize) -> Result<Self, ContentProviderRpcError> {
        let request = Self {
            version: 1,
            nonce: random_nonce(),
            maximum_offers: u32::try_from(maximum_offers)
                .map_err(|_| ContentProviderRpcError::InvalidFrame)?,
        };
        request.validate()?;
        Ok(request)
    }

    /// Requested upper bound on returned offers.
    #[must_use]
    pub fn maximum_offers(&self) -> usize {
        self.maximum_offers as usize
    }

    /// Exact 32-byte correlation nonce, also usable in a bounded inbound replay cache.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    fn validate(&self) -> Result<(), ContentProviderRpcError> {
        validate_header(self.version, &self.nonce)?;
        if self.maximum_offers == 0 || self.maximum_offers() > MAX_CONTENT_OFFERS {
            return Err(ContentProviderRpcError::InvalidFrame);
        }
        Ok(())
    }
}

/// Opaque independently signed public service offers; not a node or content catalogue.
#[derive(Clone, PartialEq, Message)]
pub struct ContentProviderOffer {
    #[prost(bytes = "vec", tag = "1")]
    peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signed_offer: Vec<u8>,
}

impl ContentProviderOffer {
    /// Bind an opaque signed offer to the upstream authenticated provider peer.
    ///
    /// # Errors
    /// Rejects an empty or oversized signed offer.
    pub fn new(peer: PeerId, signed_offer: Vec<u8>) -> Result<Self, ContentProviderRpcError> {
        let offer = Self {
            peer_id: peer.to_bytes(),
            signed_offer,
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Decode the advertised upstream provider identity, without trusting its signed offer.
    ///
    /// # Errors
    /// Rejects a malformed or noncanonical peer ID.
    pub fn peer_id(&self) -> Result<PeerId, ContentProviderRpcError> {
        let peer =
            PeerId::from_bytes(&self.peer_id).map_err(|_| ContentProviderRpcError::InvalidFrame)?;
        if peer.to_bytes() != self.peer_id {
            return Err(ContentProviderRpcError::InvalidFrame);
        }
        Ok(peer)
    }

    /// Borrow bytes requiring signature, identity, expiry and policy verification by the caller.
    #[must_use]
    pub fn signed_offer(&self) -> &[u8] {
        &self.signed_offer
    }

    fn validate(&self) -> Result<(), ContentProviderRpcError> {
        if self.peer_id.len() > 64 {
            return Err(ContentProviderRpcError::InvalidFrame);
        }
        self.peer_id()?;
        validate_offer(&self.signed_offer)
    }
}

/// Nonce-correlated collection of bounded service offers and their provider identities.
#[derive(Clone, PartialEq, Message)]
pub struct ContentDiscoveryResponse {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    offers: Vec<ContentProviderOffer>,
}

impl ContentDiscoveryResponse {
    /// Echo the exact request and enforce its smaller offer-count limit.
    ///
    /// # Errors
    /// Rejects malformed requests or oversized/empty individual offers.
    pub fn new(
        request: &ContentDiscoveryRequest,
        offers: Vec<ContentProviderOffer>,
    ) -> Result<Self, ContentProviderRpcError> {
        let response = Self {
            version: 1,
            nonce: request.nonce.clone(),
            offers,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    /// Borrow untrusted offers for independent cryptographic and endpoint-policy verification.
    #[must_use]
    pub fn offers(&self) -> &[ContentProviderOffer] {
        &self.offers
    }

    /// Validate response bounds, request nonce and the exact requested offer-count ceiling.
    ///
    /// # Errors
    /// Rejects malformed frames or an unrelated/excessive response.
    pub fn validate_for(
        &self,
        request: &ContentDiscoveryRequest,
    ) -> Result<(), ContentProviderRpcError> {
        request.validate()?;
        self.validate()?;
        if self.nonce != request.nonce || self.offers.len() > request.maximum_offers() {
            return Err(ContentProviderRpcError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ContentProviderRpcError> {
        validate_header(self.version, &self.nonce)?;
        if self.offers.len() > MAX_CONTENT_OFFERS {
            return Err(ContentProviderRpcError::InvalidFrame);
        }
        for offer in &self.offers {
            offer.validate()?;
        }
        Ok(())
    }
}

fn random_nonce() -> Vec<u8> {
    let mut nonce = vec![0; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn validate_header(version: u32, nonce: &[u8]) -> Result<(), ContentProviderRpcError> {
    if version != 1 || nonce.len() != NONCE_BYTES {
        return Err(ContentProviderRpcError::InvalidFrame);
    }
    Ok(())
}

fn validate_offer(offer: &[u8]) -> Result<(), ContentProviderRpcError> {
    if offer.is_empty() || offer.len() > MAX_CONTENT_OFFER_BYTES {
        return Err(ContentProviderRpcError::InvalidFrame);
    }
    Ok(())
}

macro_rules! content_codec {
    ($codec:ident, $request:ty, $response:ty, $protocol:ident, $response_bytes:ident) => {
        /// Canonical, bounded codec for one role-separated content control protocol.
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $codec;

        #[async_trait]
        impl request_response::Codec for $codec {
            type Protocol = StreamProtocol;
            type Request = $request;
            type Response = $response;

            async fn read_request<T>(
                &mut self,
                protocol: &Self::Protocol,
                io: &mut T,
            ) -> io::Result<Self::Request>
            where
                T: AsyncRead + Unpin + Send,
            {
                require_protocol(protocol, $protocol)?;
                let encoded = read_bounded(io, REQUEST_BYTES).await?;
                let value =
                    decode_canonical::<$request>(&encoded, REQUEST_BYTES).map_err(invalid_data)?;
                value.validate().map_err(invalid_data)?;
                Ok(value)
            }

            async fn read_response<T>(
                &mut self,
                protocol: &Self::Protocol,
                io: &mut T,
            ) -> io::Result<Self::Response>
            where
                T: AsyncRead + Unpin + Send,
            {
                require_protocol(protocol, $protocol)?;
                let encoded = read_bounded(io, $response_bytes).await?;
                let value = decode_canonical::<$response>(&encoded, $response_bytes)
                    .map_err(invalid_data)?;
                value.validate().map_err(invalid_data)?;
                Ok(value)
            }

            async fn write_request<T>(
                &mut self,
                protocol: &Self::Protocol,
                io: &mut T,
                value: Self::Request,
            ) -> io::Result<()>
            where
                T: AsyncWrite + Unpin + Send,
            {
                require_protocol(protocol, $protocol)?;
                value.validate().map_err(invalid_data)?;
                io.write_all(&encode_canonical(&value, REQUEST_BYTES).map_err(invalid_data)?)
                    .await
            }

            async fn write_response<T>(
                &mut self,
                protocol: &Self::Protocol,
                io: &mut T,
                value: Self::Response,
            ) -> io::Result<()>
            where
                T: AsyncWrite + Unpin + Send,
            {
                require_protocol(protocol, $protocol)?;
                value.validate().map_err(invalid_data)?;
                io.write_all(&encode_canonical(&value, $response_bytes).map_err(invalid_data)?)
                    .await
            }
        }
    };
}

content_codec!(
    ContentServiceCodec,
    ContentServiceRequest,
    ContentServiceResponse,
    CONTENT_SERVICE_PROTOCOL,
    SERVICE_RESPONSE_BYTES
);
content_codec!(
    ContentDiscoveryCodec,
    ContentDiscoveryRequest,
    ContentDiscoveryResponse,
    CONTENT_DISCOVERY_PROTOCOL,
    MAX_CONTENT_DISCOVERY_FRAME_BYTES
);

pub(crate) fn service_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<ContentServiceCodec> {
    request_response::Behaviour::with_codec(
        ContentServiceCodec,
        support
            .into_iter()
            .map(|support| (StreamProtocol::new(CONTENT_SERVICE_PROTOCOL), support)),
        rpc_config(),
    )
}

pub(crate) fn discovery_behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<ContentDiscoveryCodec> {
    request_response::Behaviour::with_codec(
        ContentDiscoveryCodec,
        support
            .into_iter()
            .map(|support| (StreamProtocol::new(CONTENT_DISCOVERY_PROTOCOL), support)),
        rpc_config(),
    )
}

fn rpc_config() -> request_response::Config {
    request_response::Config::default()
        .with_request_timeout(CONTENT_REQUEST_TIMEOUT)
        .with_max_concurrent_streams(MAX_PENDING_CONTENT_REQUESTS)
}

async fn read_bounded<T: AsyncRead + Unpin + Send>(
    io: &mut T,
    maximum: usize,
) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    io.take((maximum + 1) as u64)
        .read_to_end(&mut encoded)
        .await?;
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(invalid_data(ContentProviderRpcError::InvalidFrame));
    }
    Ok(encoded)
}

fn require_protocol(protocol: &StreamProtocol, expected: &str) -> io::Result<()> {
    if protocol.as_ref() != expected {
        return Err(invalid_data(ContentProviderRpcError::InvalidFrame));
    }
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

struct Pending<Request> {
    peer: PeerId,
    connection: Option<ConnectionId>,
    request: Request,
    deadline: Instant,
}

#[derive(Default)]
pub(crate) struct ContentProviderState {
    local_offer: Option<Vec<u8>>,
    pub(crate) provider_query: Option<kad::QueryId>,
    service: HashMap<request_response::OutboundRequestId, Pending<ContentServiceRequest>>,
    discovery: HashMap<request_response::OutboundRequestId, Pending<ContentDiscoveryRequest>>,
}

impl ContentProviderState {
    fn finish_provider_query(
        &mut self,
        kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
        budgets: &mut AdvertisementBudgets,
        id: kad::QueryId,
    ) -> Result<(), DiscoveryError> {
        if self.provider_query != Some(id) {
            return Err(DiscoveryError::ProtocolPeer);
        }
        if let Some(mut query) = kademlia.query_mut(&id) {
            if !matches!(query.info(), kad::QueryInfo::GetProviders { key, .. } if key == &kad::RecordKey::new(&crate::capability::CONTENT))
            {
                return Err(DiscoveryError::Capability);
            }
            query.finish();
        }
        budgets.finish_provider_query(id);
        self.provider_query = None;
        Ok(())
    }

    fn reserve(&mut self) -> Result<(), DiscoveryError> {
        let now = Instant::now();
        self.service.retain(|_, pending| pending.deadline > now);
        self.discovery.retain(|_, pending| pending.deadline > now);
        if self.service.len() + self.discovery.len() >= MAX_PENDING_CONTENT_REQUESTS {
            return Err(DiscoveryError::ResourceLimit);
        }
        Ok(())
    }
}

impl DiscoveryService {
    /// Finish only the exact generic content-provider lookup owned by this service.
    /// A bounded relay job uses this when its shorter deadline precedes Kademlia's deadline,
    /// preventing the next caller from joining an abandoned, partially consumed query.
    ///
    /// # Errors
    /// Rejects a foreign query ID or a live query outside the generic content namespace.
    pub fn finish_content_provider_query(
        &mut self,
        id: kad::QueryId,
    ) -> Result<(), DiscoveryError> {
        self.content_provider.finish_provider_query(
            &mut self.swarm.behaviour_mut().kademlia,
            &mut self.advertisement_budgets,
            id,
        )
    }

    /// Detail-free registry state; this never selects a connection or confers relay authority.
    #[must_use]
    pub fn content_control_connection_state(&self, peer: &PeerId) -> ContentControlConnectionState {
        self.swarm
            .behaviour()
            .connection_provenance
            .content_control_state(*peer)
    }

    /// Validate an exact current authenticated direct connection, including when siblings exist.
    /// The agent must independently hold the current direct-relay authority.
    #[must_use]
    pub fn content_control_connection_is_current(
        &self,
        peer: &PeerId,
        connection: ConnectionId,
    ) -> bool {
        peer != self.local_peer_id()
            && self
                .swarm
                .behaviour()
                .connection_provenance
                .content_control_connection_is_current(*peer, connection)
    }

    /// Register or withdraw the bounded local public service offer, without announcing in DHT.
    /// The caller must first verify its own offer signature, lifetime, identity and endpoint.
    ///
    /// # Errors
    /// Rejects an empty or oversized explicit offer.
    pub fn set_local_content_offer(
        &mut self,
        offer: Option<Vec<u8>>,
    ) -> Result<(), DiscoveryError> {
        if let Some(offer) = &offer {
            validate_offer(offer)?;
        }
        self.content_provider.local_offer = offer;
        Ok(())
    }

    /// Ask one provider for its generic signed offer as a control relay, never as a client hop.
    /// The agent must separately authorize this upstream operation and must not substitute it
    /// for client-side forwarded discovery on a node with combined roles.
    ///
    /// # Errors
    /// Rejects a non-relay role, self-target, invalid request or exhausted pending budget.
    pub fn request_content_service(
        &mut self,
        provider: &PeerId,
        request: ContentServiceRequest,
    ) -> Result<request_response::OutboundRequestId, DiscoveryError> {
        if !self.protocol_roles.relay() {
            return Err(DiscoveryError::ProtocolRole);
        }
        if provider == self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        request.validate()?;
        self.content_provider.reserve()?;
        let id = self
            .swarm
            .behaviour_mut()
            .content_service
            .send_request(provider, request.clone());
        self.content_provider.service.insert(
            id,
            Pending {
                peer: *provider,
                connection: None,
                request,
                deadline: Instant::now() + CONTENT_REQUEST_TIMEOUT,
            },
        );
        Ok(id)
    }

    /// Ask an already authenticated current control relay for bounded public service offers.
    /// The agent supplies current direct-relay authority; an arbitrary connected peer is not
    /// thereby authorized. The exact connection and peer are checked again on the response.
    ///
    /// # Errors
    /// Rejects non-client roles, invalid frames, missing connection lineage or pending capacity.
    pub fn request_content_discovery(
        &mut self,
        control_relay: &PeerId,
        request: ContentDiscoveryRequest,
    ) -> Result<(request_response::OutboundRequestId, ConnectionId), DiscoveryError> {
        if !self.protocol_roles.client() {
            return Err(DiscoveryError::ProtocolRole);
        }
        if control_relay == self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        request.validate()?;
        self.content_provider.reserve()?;
        let behaviour = &mut self.swarm.behaviour_mut().0;
        let (id, connection) = behaviour.content_discovery.send_bound_request(
            control_relay,
            request.clone(),
            |connection| {
                behaviour
                    .connection_provenance
                    .content_control_connection_is_current(*control_relay, connection)
            },
        )?;
        self.content_provider.discovery.insert(
            id,
            Pending {
                peer: *control_relay,
                connection: Some(connection),
                request,
                deadline: Instant::now() + CONTENT_REQUEST_TIMEOUT,
            },
        );
        Ok((id, connection))
    }

    /// Reply over the inbound client's existing authenticated request-response channel.
    /// The agent owns the bounded upstream job and validates every forwarded signed offer.
    ///
    /// # Errors
    /// Rejects non-relay roles, malformed frames or an already closed response channel.
    pub fn send_content_discovery_response(
        &mut self,
        channel: request_response::ResponseChannel<ContentDiscoveryResponse>,
        response: ContentDiscoveryResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.relay() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        self.swarm
            .behaviour_mut()
            .content_discovery
            .send_response(channel, response)
            .map_err(|_| DiscoveryError::Swarm("content discovery response channel closed".into()))
    }

    pub(crate) fn handle_content_event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
    ) -> Option<SwarmEvent<BehaviourEvent>> {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::ContentService(
                request_response::Event::Message {
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                if let Ok(response) =
                    ContentServiceResponse::new(&request, self.content_provider.local_offer.clone())
                {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .content_service
                        .send_response(channel, response);
                }
                None
            }
            event => {
                let valid = match &event {
                    SwarmEvent::Behaviour(BehaviourEvent::ContentService(
                        request_response::Event::Message {
                            peer,
                            message:
                                request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                            ..
                        },
                    )) => self
                        .content_provider
                        .service
                        .remove(request_id)
                        .is_some_and(|pending| {
                            pending.peer == *peer
                                && pending.deadline > Instant::now()
                                && response.validate_for(&pending.request).is_ok()
                        }),
                    SwarmEvent::Behaviour(BehaviourEvent::ContentDiscovery(
                        request_response::Event::Message {
                            peer,
                            connection_id,
                            message:
                                request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                        },
                    )) => {
                        self.content_provider
                            .discovery
                            .remove(request_id)
                            .is_some_and(|pending| {
                                pending.peer == *peer
                                    && pending.connection == Some(*connection_id)
                                    && pending.deadline > Instant::now()
                                    && response.validate_for(&pending.request).is_ok()
                            })
                            && self.content_control_connection_is_current(peer, *connection_id)
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::ContentService(
                        request_response::Event::OutboundFailure { request_id, .. },
                    )) => {
                        self.content_provider.service.remove(request_id);
                        true
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::ContentDiscovery(
                        request_response::Event::OutboundFailure {
                            request_id,
                            peer,
                            connection_id,
                            ..
                        },
                    )) => self
                        .content_provider
                        .discovery
                        .remove(request_id)
                        .is_some_and(|pending| {
                            pending.peer == *peer && pending.connection == Some(*connection_id)
                        }),
                    _ => true,
                };
                valid.then_some(event)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    #[test]
    fn content_provider_lookup_timeout_releases_only_the_exact_query() {
        let peer = PeerId::random();
        let mut kademlia = kad::Behaviour::new(peer, kad::store::MemoryStore::new(peer));
        let mut budgets = AdvertisementBudgets::new();
        let content = budgets
            .provider_query_or_insert(crate::capability::CONTENT, || {
                kademlia.get_providers(kad::RecordKey::new(&crate::capability::CONTENT))
            })
            .unwrap();
        let relay = budgets
            .provider_query_or_insert(crate::capability::RELAY, || {
                kademlia.get_providers(kad::RecordKey::new(&crate::capability::RELAY))
            })
            .unwrap();
        let mut state = ContentProviderState {
            provider_query: Some(content),
            ..ContentProviderState::default()
        };
        assert!(matches!(
            state.finish_provider_query(&mut kademlia, &mut budgets, relay),
            Err(DiscoveryError::ProtocolPeer)
        ));
        assert_eq!(state.provider_query, Some(content));
        state
            .finish_provider_query(&mut kademlia, &mut budgets, content)
            .unwrap();
        assert!(kademlia.query_mut(&content).is_none());
        let next = budgets
            .provider_query_or_insert(crate::capability::CONTENT, || {
                kademlia.get_providers(kad::RecordKey::new(&crate::capability::CONTENT))
            })
            .unwrap();
        assert_ne!(next, content);
        assert_eq!(
            budgets.provider_query_or_insert(crate::capability::RELAY, || panic!(
                "relay query must remain owned"
            )),
            Some(relay)
        );
        state.provider_query = Some(next);
        assert!(
            state
                .finish_provider_query(&mut kademlia, &mut budgets, content)
                .is_err()
        );
    }

    #[tokio::test]
    async fn content_service_codec_roundtrip_and_correlation() {
        let protocol = StreamProtocol::new(CONTENT_SERVICE_PROTOCOL);
        let request = ContentServiceRequest::new();
        let mut codec = ContentServiceCodec;
        let mut wire = Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut wire, request.clone())
            .await
            .unwrap();
        wire.set_position(0);
        assert_eq!(
            codec.read_request(&protocol, &mut wire).await.unwrap(),
            request
        );
        let response =
            ContentServiceResponse::new(&request, Some(vec![3; MAX_CONTENT_OFFER_BYTES])).unwrap();
        let mut wire = Cursor::new(Vec::new());
        codec
            .write_response(&protocol, &mut wire, response.clone())
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = codec.read_response(&protocol, &mut wire).await.unwrap();
        assert_eq!(decoded, response);
        assert!(decoded.validate_for(&request).is_ok());
        assert_eq!(
            decoded.validate_for(&ContentServiceRequest::new()),
            Err(ContentProviderRpcError::Correlation)
        );
        assert!(
            ContentServiceResponse::new(&request, Some(vec![0; MAX_CONTENT_OFFER_BYTES + 1]))
                .is_err()
        );
    }

    #[tokio::test]
    async fn content_discovery_codec_roundtrip_and_bounds() {
        let protocol = StreamProtocol::new(CONTENT_DISCOVERY_PROTOCOL);
        let request = ContentDiscoveryRequest::new(MAX_CONTENT_OFFERS).unwrap();
        let mut codec = ContentDiscoveryCodec;
        let mut wire = Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut wire, request.clone())
            .await
            .unwrap();
        wire.set_position(0);
        assert_eq!(
            codec.read_request(&protocol, &mut wire).await.unwrap(),
            request
        );
        let offer =
            ContentProviderOffer::new(PeerId::random(), vec![4; MAX_CONTENT_OFFER_BYTES]).unwrap();
        let response =
            ContentDiscoveryResponse::new(&request, vec![offer.clone(); MAX_CONTENT_OFFERS])
                .unwrap();
        let mut wire = Cursor::new(Vec::new());
        codec
            .write_response(&protocol, &mut wire, response.clone())
            .await
            .unwrap();
        assert!(wire.get_ref().len() <= MAX_CONTENT_DISCOVERY_FRAME_BYTES);
        wire.set_position(0);
        let decoded = codec.read_response(&protocol, &mut wire).await.unwrap();
        assert_eq!(decoded, response);
        assert!(decoded.validate_for(&request).is_ok());
        assert_eq!(
            decoded.validate_for(&ContentDiscoveryRequest::new(MAX_CONTENT_OFFERS).unwrap()),
            Err(ContentProviderRpcError::Correlation)
        );
        assert!(ContentDiscoveryRequest::new(0).is_err());
        assert!(ContentDiscoveryRequest::new(MAX_CONTENT_OFFERS + 1).is_err());
        assert!(
            ContentDiscoveryResponse::new(
                &ContentDiscoveryRequest::new(1).unwrap(),
                vec![offer.clone(), offer]
            )
            .is_err()
        );
        let mut oversized = Cursor::new(vec![0; MAX_CONTENT_DISCOVERY_FRAME_BYTES + 1]);
        assert!(
            codec
                .read_response(&protocol, &mut oversized)
                .await
                .is_err()
        );
        assert_eq!(
            oversized.position(),
            (MAX_CONTENT_DISCOVERY_FRAME_BYTES + 1) as u64
        );
        let mut noncanonical = request.encode_to_vec();
        noncanonical.extend_from_slice(&[0x08, 0x01]);
        assert!(
            codec
                .read_request(&protocol, &mut Cursor::new(noncanonical))
                .await
                .is_err()
        );
        let mut wire = Cursor::new(Vec::new());
        assert!(
            codec
                .write_request(
                    &StreamProtocol::new(CONTENT_SERVICE_PROTOCOL),
                    &mut wire,
                    request
                )
                .await
                .is_err()
        );
        assert!(wire.get_ref().is_empty());
    }

    #[test]
    fn pending_budget_is_shared_and_expired_entries_are_reclaimed() {
        let peer = PeerId::random();
        let mut service = service_behaviour(Some(request_response::ProtocolSupport::Full));
        let mut discovery = discovery_behaviour(Some(request_response::ProtocolSupport::Full));
        let mut state = ContentProviderState::default();
        for index in 0..MAX_PENDING_CONTENT_REQUESTS {
            state.reserve().unwrap();
            if index % 2 == 0 {
                let request = ContentServiceRequest::new();
                let id = service.send_request(&peer, request.clone());
                state.service.insert(
                    id,
                    Pending {
                        peer,
                        connection: None,
                        request,
                        deadline: Instant::now() + CONTENT_REQUEST_TIMEOUT,
                    },
                );
            } else {
                let request = ContentDiscoveryRequest::new(2).unwrap();
                let id = discovery.send_request(&peer, request.clone());
                state.discovery.insert(
                    id,
                    Pending {
                        peer,
                        connection: Some(ConnectionId::new_unchecked(1)),
                        request,
                        deadline: Instant::now() + CONTENT_REQUEST_TIMEOUT,
                    },
                );
            }
        }
        assert!(matches!(
            state.reserve(),
            Err(DiscoveryError::ResourceLimit)
        ));
        state.service.values_mut().next().unwrap().deadline = Instant::now();
        state.reserve().unwrap();
        assert_eq!(
            state.service.len() + state.discovery.len(),
            MAX_PENDING_CONTENT_REQUESTS - 1
        );
    }
}
