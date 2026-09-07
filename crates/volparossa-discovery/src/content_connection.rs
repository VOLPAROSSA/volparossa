//! Pin content discovery to request-response's actual, already authenticated connection.
//!
//! The pinned request-response 0.29 behaviour queues exactly one `NotifyHandler::One`
//! synchronously for an already connected peer. Observe that choice before handing it to the
//! swarm; never predict its private round-robin index or substitute a registry's first sibling.

use std::{
    collections::VecDeque,
    io,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    request_response,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
};

use crate::{
    ContentDiscoveryRequest, ContentDiscoveryResponse, DiscoveryError,
    content_provider::ContentDiscoveryCodec,
};

type Inner = request_response::Behaviour<ContentDiscoveryCodec>;
type Action = ToSwarm<<Inner as NetworkBehaviour>::ToSwarm, THandlerInEvent<Inner>>;
const MAX_DEFERRED_EVENTS: usize = 128;

/// Private protocol adapter; syntactically public for the composed behaviour's handler type.
pub struct ContentConnectionBehaviour {
    inner: Inner,
    deferred: VecDeque<Action>,
    incompatible: bool,
}

impl ContentConnectionBehaviour {
    pub(super) fn new(inner: Inner) -> Self {
        Self {
            inner,
            deferred: VecDeque::new(),
            incompatible: false,
        }
    }

    /// Capture and authorize the actual dispatch atomically, before any handler receives it.
    pub(super) fn send_bound_request(
        &mut self,
        peer: &PeerId,
        request: ContentDiscoveryRequest,
        authorized: impl FnOnce(ConnectionId) -> bool,
    ) -> Result<(request_response::OutboundRequestId, ConnectionId), DiscoveryError> {
        if self.incompatible || !self.inner.is_connected(peer) {
            return Err(DiscoveryError::ProtocolPeer);
        }
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        // Preserve already generated inbound/failure/dispatch events, without letting one of
        // them be mistaken for the new request. No handler/swarm callback can interleave here.
        loop {
            if self.deferred.len() >= MAX_DEFERRED_EVENTS - 1 {
                return Err(DiscoveryError::ResourceLimit);
            }
            match self.inner.poll(&mut cx) {
                Poll::Ready(action) => self.deferred.push_back(action),
                Poll::Pending => break,
            }
        }
        let id = self.inner.send_request(peer, request);
        let Poll::Ready(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection),
            event,
        }) = self.inner.poll(&mut cx)
        else {
            // Fail closed if a future dependency changes this tested synchronous contract.
            // Never forward an unexpected Dial/Any event or continue allocating requests.
            self.incompatible = true;
            return Err(DiscoveryError::ProtocolPeer);
        };
        if peer_id != *peer || !authorized(connection) {
            // This request has not reached its handler. Retire its pending response via the
            // behaviour's normal failure bookkeeping; no connection is closed or retargeted.
            self.inner.on_connection_handler_event(
                peer_id,
                connection,
                THandlerOutEvent::<Inner>::OutboundStreamFailed {
                    request_id: id,
                    error: io::Error::other("content control lineage rejected before dispatch"),
                },
            );
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.deferred.push_back(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection),
            event,
        });
        Ok((id, connection))
    }

    pub(super) fn send_response(
        &mut self,
        channel: request_response::ResponseChannel<ContentDiscoveryResponse>,
        response: ContentDiscoveryResponse,
    ) -> Result<(), ContentDiscoveryResponse> {
        self.inner.send_response(channel, response)
    }
}

impl NetworkBehaviour for ContentConnectionBehaviour {
    type ConnectionHandler = THandler<Inner>;
    type ToSwarm = <Inner as NetworkBehaviour>::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner
            .handle_pending_outbound_connection(id, peer, addresses, role)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_outbound_connection(id, peer, address, role, port)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        if let FromSwarm::ConnectionClosed(closed) = event {
            self.deferred.retain(|action| {
                !matches!(action,
                    ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), .. }
                    if *peer_id == closed.peer_id && *id == closed.connection_id
                )
            });
        }
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, event);
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Action> {
        if let Some(action) = self.deferred.pop_front() {
            Poll::Ready(action)
        } else if self.incompatible {
            Poll::Pending
        } else {
            self.inner.poll(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt as _;
    use libp2p::{core::ConnectedPoint, swarm::behaviour::ConnectionClosed};

    fn behaviour() -> ContentConnectionBehaviour {
        ContentConnectionBehaviour::new(crate::content_provider::discovery_behaviour(Some(
            request_response::ProtocolSupport::Full,
        )))
    }

    fn connect(behaviour: &mut ContentConnectionBehaviour, peer: PeerId, id: usize) {
        let _handler = behaviour
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(id),
                peer,
                &"/memory/73581".parse().unwrap(),
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .unwrap();
    }

    fn next(behaviour: &mut ContentConnectionBehaviour) -> Poll<Action> {
        behaviour.poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
    }

    #[test]
    fn content_dispatch_captures_actual_sibling_before_any_notify_is_emitted() {
        let mut behaviour = behaviour();
        let peer = PeerId::random();
        connect(&mut behaviour, peer, 11);
        connect(&mut behaviour, peer, 22);
        let mut actual = Vec::new();
        let mut requests = Vec::new();
        for _ in 0..2 {
            let mut checked = None;
            let (id, connection) = behaviour
                .send_bound_request(&peer, ContentDiscoveryRequest::new(2).unwrap(), |chosen| {
                    checked = Some(chosen);
                    true
                })
                .unwrap();
            assert_eq!(checked, Some(connection));
            assert!(behaviour.inner.is_pending_outbound(&peer, &id));
            actual.push(connection);
            requests.push((id, connection));
        }
        assert_ne!(
            actual[0], actual[1],
            "two actual round-robin choices, not first registry entry"
        );
        for (id, connection) in requests {
            let Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::One(chosen),
                ..
            }) = next(&mut behaviour)
            else {
                panic!("one existing exact handler")
            };
            assert_eq!(peer_id, peer);
            assert_eq!(chosen, connection);
            behaviour.inner.on_connection_handler_event(
                peer,
                connection,
                THandlerOutEvent::<Inner>::OutboundTimeout(id),
            );
        }
        for _ in 0..2 {
            assert!(matches!(
                next(&mut behaviour),
                Poll::Ready(ToSwarm::GenerateEvent(
                    request_response::Event::OutboundFailure { .. }
                ))
            ));
        }
        assert!(next(&mut behaviour).is_pending());
    }

    #[test]
    fn content_dispatch_rejection_has_no_notify_dial_or_pending_leak() {
        let mut behaviour = behaviour();
        let peer = PeerId::random();
        connect(&mut behaviour, peer, 11);
        connect(&mut behaviour, peer, 22);
        for _ in 0..256 {
            assert!(
                behaviour
                    .send_bound_request(&peer, ContentDiscoveryRequest::new(2).unwrap(), |_| false)
                    .is_err()
            );
            let Poll::Ready(ToSwarm::GenerateEvent(request_response::Event::OutboundFailure {
                request_id,
                peer: failed_peer,
                ..
            })) = next(&mut behaviour)
            else {
                panic!("only a bounded local cancellation")
            };
            assert_eq!(failed_peer, peer);
            assert!(!behaviour.inner.is_pending_outbound(&peer, &request_id));
            assert!(next(&mut behaviour).is_pending());
        }
        let other = PeerId::random();
        assert!(
            behaviour
                .send_bound_request(&other, ContentDiscoveryRequest::new(2).unwrap(), |_| true)
                .is_err()
        );
        assert!(
            next(&mut behaviour).is_pending(),
            "never autodial an absent peer"
        );
    }

    #[test]
    fn content_dispatch_closed_choice_is_not_retargeted_to_replacement() {
        let mut behaviour = behaviour();
        let peer = PeerId::random();
        connect(&mut behaviour, peer, 11);
        connect(&mut behaviour, peer, 22);
        let (id, connection) = behaviour
            .send_bound_request(&peer, ContentDiscoveryRequest::new(2).unwrap(), |_| true)
            .unwrap();
        let endpoint = ConnectedPoint::Dialer {
            address: "/memory/73581".parse().unwrap(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: connection,
            endpoint: &endpoint,
            remaining_established: 1,
            cause: None,
        }));
        connect(&mut behaviour, peer, 33);
        assert!(!behaviour.inner.is_pending_outbound(&peer, &id));
        assert!(
            matches!(next(&mut behaviour), Poll::Ready(ToSwarm::GenerateEvent(
            request_response::Event::OutboundFailure {
                request_id, connection_id, error: request_response::OutboundFailure::ConnectionClosed, ..
            }
        )) if request_id == id && connection_id == connection)
        );
        assert!(
            next(&mut behaviour).is_pending(),
            "closed dispatch never moves to its sibling/replacement"
        );
    }

    fn memory_swarm() -> libp2p::Swarm<ContentConnectionBehaviour> {
        use libp2p::{
            Transport as _,
            core::{transport::MemoryTransport, upgrade},
            identity, noise, yamux,
        };
        let identity = identity::Keypair::generate_ed25519();
        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&identity).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();
        libp2p::Swarm::new(
            transport,
            behaviour(),
            identity.public().to_peer_id(),
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(std::time::Duration::from_secs(30)),
        )
    }

    #[tokio::test]
    async fn content_dispatch_real_authenticated_memory_siblings_reply_on_exact_choices() {
        use libp2p::swarm::{
            SwarmEvent,
            dial_opts::{DialOpts, PeerCondition},
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            // Only MemoryTransport is installed: no TCP/UDP sockets, DNS or host networking.
            let mut client = memory_swarm();
            let mut relay = memory_swarm();
            let peer = *relay.local_peer_id();
            relay.listen_on("/memory/0".parse().unwrap()).unwrap();
            let address = loop {
                if let SwarmEvent::NewListenAddr { address, .. } = relay.select_next_some().await {
                    break address;
                }
            };
            for _ in 0..2 {
                client.dial(DialOpts::peer_id(peer).condition(PeerCondition::Always)
                    .addresses(vec![address.clone()]).build()).unwrap();
            }
            let mut client_connections = Vec::new();
            let mut relay_connections = 0;
            while client_connections.len() < 2 || relay_connections < 2 {
                tokio::select! {
                    event = client.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { connection_id, peer_id, .. } => {
                            assert_eq!(peer_id, peer);
                            client_connections.push(connection_id);
                        }
                        SwarmEvent::OutgoingConnectionError { error, .. } => panic!("{error}"),
                        _ => {}
                    },
                    event = relay.select_next_some() => if let SwarmEvent::ConnectionEstablished { .. } = event {
                        relay_connections += 1;
                    }
                }
            }
            let mut pending = std::collections::HashMap::new();
            for _ in 0..2 {
                let request = ContentDiscoveryRequest::new(2).unwrap();
                let (id, connection) = client.behaviour_mut().send_bound_request(
                    &peer, request.clone(), |chosen| client_connections.contains(&chosen)).unwrap();
                assert!(!pending.values().any(|(existing, _)| *existing == connection));
                pending.insert(id, (connection, request));
            }
            while !pending.is_empty() {
                tokio::select! {
                    event = client.select_next_some() => match event {
                        SwarmEvent::Behaviour(request_response::Event::Message { peer: responding, connection_id,
                            message: request_response::Message::Response { request_id, response } }) => {
                            let (chosen, request) = pending.remove(&request_id).unwrap();
                            assert_eq!(responding, peer);
                            assert_eq!(connection_id, chosen);
                            response.validate_for(&request).unwrap();
                        }
                        SwarmEvent::Behaviour(request_response::Event::OutboundFailure { error, .. }) => panic!("{error}"),
                        _ => {}
                    },
                    event = relay.select_next_some() => if let SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Request { request, channel, .. }, ..
                    }) = event {
                        relay.behaviour_mut().send_response(channel,
                            ContentDiscoveryResponse::new(&request, Vec::new()).unwrap()).unwrap();
                    }
                }
            }
        }).await.expect("two authenticated memory-transport content roundtrips");
    }
}
