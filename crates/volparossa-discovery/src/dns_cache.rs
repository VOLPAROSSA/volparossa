//! Bounded signed DNSSEC cache RPC over an already authenticated direct peer connection.

use crate::{DiscoveryError, DiscoveryService};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use libp2p::{PeerId, StreamProtocol, kad, request_response, swarm::ConnectionId};
use prost::Message;
use std::{
    collections::HashMap,
    io,
    time::{Duration, Instant},
};
use volparossa_protocol::{
    ControlPayload, DnsCacheQuery, DnsCacheReply, MAX_DNS_CACHE_BUNDLE_BYTES, SignedEnvelope,
    decode_canonical, encode_canonical,
};

/// Cache-only DNSSEC exchange. Never forwards the question through a control Relay.
pub const DNS_CACHE_PROTOCOL: &str = "/volparossa/dns-cache/1";
/// RPC bound inside the caller's original lookup deadline.
pub const DNS_CACHE_RPC_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_MAX: usize = 1024;
const RESPONSE_MAX: usize = MAX_DNS_CACHE_BUNDLE_BYTES + 1024;
const MAX_PENDING: usize = 16;

/// An opaque signed cache query. Its signer and DNS/policy semantics require actor verification.
#[derive(Clone, PartialEq, Message)]
pub struct DnsCacheRequest {
    #[prost(bytes = "vec", tag = "1")]
    signed: Vec<u8>,
}
impl DnsCacheRequest {
    /// Bound canonical signed-query framing; this does not establish authority or dial.
    /// # Errors
    /// Rejects malformed, oversized or incorrectly typed envelopes.
    pub fn new(signed: Vec<u8>) -> Result<Self, DiscoveryError> {
        let value = Self { signed };
        validate::<DnsCacheQuery>(&value.signed, REQUEST_MAX)?;
        Ok(value)
    }
    /// Untrusted signed bytes, never log or retain as browsing history.
    #[must_use]
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
}

/// One signed response, containing a proof or an authenticated empty-cache reply.
#[derive(Clone, PartialEq, Message)]
pub struct DnsCacheResponse {
    #[prost(bytes = "vec", tag = "1")]
    signed: Vec<u8>,
}
impl DnsCacheResponse {
    /// Bound canonical signed-reply framing without granting DNS authority.
    /// # Errors
    /// Rejects malformed, oversized or incorrectly typed envelopes.
    pub fn new(signed: Vec<u8>) -> Result<Self, DiscoveryError> {
        let value = Self { signed };
        validate::<DnsCacheReply>(&value.signed, RESPONSE_MAX)?;
        Ok(value)
    }
    /// Untrusted signed bytes for the independent actor/core verifier.
    #[must_use]
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
}

fn validate<T: ControlPayload>(bytes: &[u8], maximum: usize) -> Result<(), DiscoveryError> {
    let envelope: SignedEnvelope =
        decode_canonical(bytes, maximum).map_err(|_| DiscoveryError::ProtocolPeer)?;
    if envelope.message_type != T::MESSAGE_TYPE as i32 {
        return Err(DiscoveryError::ProtocolPeer);
    }
    let payload: T =
        decode_canonical(&envelope.payload, maximum).map_err(|_| DiscoveryError::ProtocolPeer)?;
    payload.validate().map_err(|_| DiscoveryError::ProtocolPeer)
}

/// Internal canonical codec for the composed libp2p behaviour.
#[derive(Clone, Copy, Debug, Default)]
pub struct DnsCacheCodec;

async fn read<T: AsyncRead + Unpin + Send, M: Message + Default>(
    io: &mut T,
    max: usize,
) -> io::Result<M> {
    let mut encoded = Vec::new();
    io.take(u64::try_from(max + 1).map_err(|_| invalid())?)
        .read_to_end(&mut encoded)
        .await?;
    decode_canonical(&encoded, max).map_err(|_| invalid())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "DNS cache frame rejected")
}
fn protocol(value: &StreamProtocol) -> io::Result<()> {
    if value.as_ref() == DNS_CACHE_PROTOCOL {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[async_trait]
impl request_response::Codec for DnsCacheCodec {
    type Protocol = StreamProtocol;
    type Request = DnsCacheRequest;
    type Response = DnsCacheResponse;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        p: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        protocol(p)?;
        let value: DnsCacheRequest = read(io, REQUEST_MAX).await?;
        validate::<DnsCacheQuery>(&value.signed, REQUEST_MAX).map_err(|_| invalid())?;
        Ok(value)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        p: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        protocol(p)?;
        let value: DnsCacheResponse = read(io, RESPONSE_MAX).await?;
        validate::<DnsCacheReply>(&value.signed, RESPONSE_MAX).map_err(|_| invalid())?;
        Ok(value)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        p: &StreamProtocol,
        io: &mut T,
        value: Self::Request,
    ) -> io::Result<()> {
        protocol(p)?;
        validate::<DnsCacheQuery>(&value.signed, REQUEST_MAX).map_err(|_| invalid())?;
        io.write_all(&encode_canonical(&value, REQUEST_MAX).map_err(|_| invalid())?)
            .await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        p: &StreamProtocol,
        io: &mut T,
        value: Self::Response,
    ) -> io::Result<()> {
        protocol(p)?;
        validate::<DnsCacheReply>(&value.signed, RESPONSE_MAX).map_err(|_| invalid())?;
        io.write_all(&encode_canonical(&value, RESPONSE_MAX).map_err(|_| invalid())?)
            .await
    }
}

pub(crate) fn behaviour(
    support: Option<request_response::ProtocolSupport>,
) -> request_response::Behaviour<DnsCacheCodec> {
    request_response::Behaviour::with_codec(
        DnsCacheCodec,
        support
            .into_iter()
            .map(|s| (StreamProtocol::new(DNS_CACHE_PROTOCOL), s)),
        request_response::Config::default()
            .with_request_timeout(DNS_CACHE_RPC_TIMEOUT)
            .with_max_concurrent_streams(MAX_PENDING),
    )
}

#[derive(Default)]
pub(crate) struct DnsCacheState {
    pending: HashMap<request_response::OutboundRequestId, Instant>,
}

impl DiscoveryService {
    /// Connect without sending a DNS question. The ordinary address/transport guards apply.
    /// # Errors
    /// Rejects self, non-Exit use or unavailable admitted transport addresses.
    pub fn connect_dns_cache_peer(&mut self, peer: PeerId) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.exit() || peer == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .dial(peer)
            .map_err(|_| DiscoveryError::ProtocolPeer)
    }
    /// Bind request-response's actual connection before dispatch; never queue a DNS-bearing dial.
    /// # Errors
    /// Rejects poisoned, relayed, unconnected or stale selected lineage and exhausted capacity.
    pub fn request_dns_cache(
        &mut self,
        peer: PeerId,
        request: DnsCacheRequest,
    ) -> Result<(request_response::OutboundRequestId, ConnectionId), DiscoveryError> {
        if !self.protocol_roles.exit() || peer == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        validate::<DnsCacheQuery>(request.signed(), REQUEST_MAX)?;
        self.dns_cache
            .pending
            .retain(|_, deadline| *deadline > Instant::now());
        if self.dns_cache.pending.len() >= MAX_PENDING {
            return Err(DiscoveryError::ResourceLimit);
        }
        let behaviour = &mut self.swarm.behaviour_mut().0;
        let (id, connection) =
            behaviour
                .dns_cache
                .send_bound_request(&peer, request, |chosen| {
                    behaviour
                        .connection_provenance
                        .content_control_connection_is_current(peer, chosen)
                })?;
        self.dns_cache
            .pending
            .insert(id, Instant::now() + DNS_CACHE_RPC_TIMEOUT);
        Ok((id, connection))
    }
    /// Retire this actor's bounded request bookkeeping after completion/cancellation.
    pub fn finish_dns_cache_request(&mut self, id: request_response::OutboundRequestId) {
        self.dns_cache.pending.remove(&id);
    }
    /// Respond on the exact live inbound authenticated direct connection.
    /// # Errors
    /// Rejects stale/relayed lineage, malformed frames, or closed request channels.
    pub fn respond_dns_cache(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        channel: request_response::ResponseChannel<DnsCacheResponse>,
        response: DnsCacheResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.content_control_connection_is_current(&peer, connection) {
            return Err(DiscoveryError::ProtocolPeer);
        }
        validate::<DnsCacheReply>(response.signed(), RESPONSE_MAX)?;
        self.swarm
            .behaviour_mut()
            .dns_cache
            .send_response(channel, response)
            .map_err(|_| DiscoveryError::ProtocolPeer)
    }
    /// Finish only the fixed DNSSEC capability query, never another caller's namespace.
    /// # Errors
    /// Rejects a live foreign query or a query of another capability.
    pub fn finish_dns_cache_provider_query(
        &mut self,
        id: kad::QueryId,
    ) -> Result<(), DiscoveryError> {
        if let Some(mut query) = self.swarm.behaviour_mut().kademlia.query_mut(&id) {
            if !matches!(query.info(), kad::QueryInfo::GetProviders { key, .. } if key == &kad::RecordKey::new(&crate::capability::DNSSEC_CACHE))
            {
                return Err(DiscoveryError::Capability);
            }
            query.finish();
        }
        self.advertisement_budgets.finish_provider_query(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{identity, request_response::Codec as _};
    use volparossa_protocol::{
        TimePolicy, dns_cache_request_hash, generate_nonce, sign_control_message_with,
    };

    #[tokio::test]
    async fn dns_cache_codec_roundtrip_and_bounded_signed_reply() {
        let key = identity::Keypair::generate_ed25519();
        let public = key.public().try_into_ed25519().unwrap().to_bytes();
        let query = DnsCacheQuery {
            name: "www.example.org".into(),
            query_type: 28,
            policy_hash: vec![1; 32],
        };
        let signed = sign_control_message_with(
            &query,
            public,
            1000,
            6000,
            generate_nonce(),
            TimePolicy::default(),
            |b| key.sign(b).ok().and_then(|s| s.try_into().ok()),
        )
        .unwrap();
        let request = DnsCacheRequest::new(signed.clone()).unwrap();
        let p = StreamProtocol::new(DNS_CACHE_PROTOCOL);
        let mut codec = DnsCacheCodec;
        let mut wire = futures::io::Cursor::new(Vec::new());
        codec
            .write_request(&p, &mut wire, request.clone())
            .await
            .unwrap();
        wire.set_position(0);
        assert_eq!(codec.read_request(&p, &mut wire).await.unwrap(), request);
        let reply = DnsCacheReply {
            request_hash: dns_cache_request_hash(&signed).to_vec(),
            bundle: vec![7; MAX_DNS_CACHE_BUNDLE_BYTES],
        };
        let signed = sign_control_message_with(
            &reply,
            public,
            1000,
            6000,
            generate_nonce(),
            TimePolicy::default(),
            |b| key.sign(b).ok().and_then(|s| s.try_into().ok()),
        )
        .unwrap();
        let response = DnsCacheResponse::new(signed).unwrap();
        let mut wire = futures::io::Cursor::new(Vec::new());
        codec
            .write_response(&p, &mut wire, response.clone())
            .await
            .unwrap();
        wire.set_position(0);
        assert_eq!(codec.read_response(&p, &mut wire).await.unwrap(), response);
        let mut oversized = futures::io::Cursor::new(vec![0; RESPONSE_MAX + 1]);
        assert!(codec.read_response(&p, &mut oversized).await.is_err());
    }
}
