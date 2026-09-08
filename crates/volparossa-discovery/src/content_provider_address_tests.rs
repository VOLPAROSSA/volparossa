//! Real Kad/provider RPC address-lifetime probe. `MemoryTransport` only: no host networking.
//! Deliberately excludes Identify/address admission: this characterizes the upstream boundary,
//! not a failure of the full production discovery service, which retains admitted addresses.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, Transport as _,
    core::{Endpoint, transport::MemoryTransport, upgrade},
    identity,
    kad::{
        self,
        store::{MemoryStore, RecordStore},
    },
    noise, request_response,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent},
    yamux,
};

use crate::{
    ContentServiceRequest, ContentServiceResponse, KADEMLIA_PROTOCOL,
    content_provider::{ContentServiceCodec, service_behaviour},
};

#[derive(NetworkBehaviour)]
struct Probe {
    kad: kad::Behaviour<MemoryStore>,
    service: request_response::Behaviour<ContentServiceCodec>,
}

fn swarm() -> Swarm<Probe> {
    let key = identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let mut config = kad::Config::new(StreamProtocol::new(KADEMLIA_PROTOCOL));
    config.set_query_timeout(Duration::from_secs(30));
    config.set_kbucket_inserts(kad::BucketInserts::Manual);
    let mut kad = kad::Behaviour::with_config(peer, MemoryStore::new(peer), config);
    kad.set_mode(Some(kad::Mode::Server));
    let transport = MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed();
    Swarm::new(
        transport,
        Probe {
            kad,
            service: service_behaviour(Some(request_response::ProtocolSupport::Full)),
        },
        peer,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    )
}

async fn listen(node: &mut Swarm<Probe>) -> Multiaddr {
    node.listen_on("/memory/0".parse().unwrap()).unwrap();
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
            return address;
        }
    }
}

fn respond(node: &mut Swarm<Probe>, event: SwarmEvent<ProbeEvent>) {
    if let SwarmEvent::Behaviour(ProbeEvent::Service(request_response::Event::Message {
        message: request_response::Message::Request {
            request, channel, ..
        },
        ..
    })) = event
    {
        // Codec-level opaque service payload, not a signed offer or content authority.
        node.behaviour_mut()
            .service
            .send_response(
                channel,
                ContentServiceResponse::new(&request, Some(vec![7; 32])).unwrap(),
            )
            .unwrap();
    }
}

fn dial_addresses(node: &mut Swarm<Probe>, peer: PeerId) -> Vec<Multiaddr> {
    node.behaviour_mut()
        .kad
        .handle_pending_outbound_connection(
            ConnectionId::new_unchecked(987),
            Some(peer),
            &[],
            Endpoint::Dialer,
        )
        .unwrap()
}

async fn disconnect_provider(
    relay: &mut Swarm<Probe>,
    provider: &mut Swarm<Probe>,
    contact: &mut Swarm<Probe>,
) {
    let peer = *provider.local_peer_id();
    let relay_peer = *relay.local_peer_id();
    relay.disconnect_peer_id(peer).unwrap();
    while relay.is_connected(&peer) || provider.is_connected(&relay_peer) {
        tokio::select! {
            event = provider.select_next_some() => respond(provider, event),
            event = contact.select_next_some() => respond(contact, event),
            event = relay.select_next_some() => respond(relay, event),
        }
    }
}

#[tokio::test]
async fn content_provider_memory_lookup_distinguishes_network_and_unadmitted_cached_records() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut provider = swarm();
        let address = listen(&mut provider).await;
        let peer = *provider.local_peer_id();
        let mut contact = swarm();
        let contact_address = listen(&mut contact).await;
        let mut relay = swarm();
        let relay_address = listen(&mut relay).await;
        relay.behaviour_mut().kad.add_address(contact.local_peer_id(), contact_address);
        // One untrusted generic provider record at the bootstrap contact. The relay must
        // retrieve it through real Kad frames; it receives no out-of-band provider address.
        let key = kad::RecordKey::new(&b"/volparossa/v1/provider/content");
        contact.behaviour_mut().kad.store_mut().add_provider(kad::ProviderRecord {
            key: key.clone(), provider: peer, expires: None, addresses: vec![address],
        }).unwrap();
        for round in 0..3 {
        if round == 2 {
            // Receive a real ADD_PROVIDER, rather than injecting the relay's local cache.
            // The actual actor requests service at its first FoundProviders event.
            provider.behaviour_mut().kad.add_address(relay.local_peer_id(), relay_address.clone());
            let publication = provider.behaviour_mut().kad.start_providing(key.clone()).unwrap();
            let mut announced = false;
            while !announced || !relay.behaviour_mut().kad.store_mut().providers(&key)
                .iter().any(|record| record.provider == peer) {
                tokio::select! {
                    event = provider.select_next_some() => {
                        if let SwarmEvent::Behaviour(ProbeEvent::Kad(kad::Event::OutboundQueryProgressed {
                            id, result: kad::QueryResult::StartProviding(result), ..
                        })) = &event {
                            if *id == publication { result.as_ref().unwrap(); announced = true; }
                        }
                        respond(&mut provider, event);
                    },
                    event = contact.select_next_some() => respond(&mut contact, event),
                    event = relay.select_next_some() => respond(&mut relay, event),
                }
            }
        }
        if round > 0 {
            disconnect_provider(&mut relay, &mut provider, &mut contact).await;
        }
        let cached = relay.behaviour_mut().kad.store_mut().providers(&key).len();
        let query = relay.behaviour_mut().kad.get_providers(key.clone());
        let mut found = false;
        loop {
            tokio::select! {
                event = provider.select_next_some() => respond(&mut provider, event),
                event = contact.select_next_some() => respond(&mut contact, event),
                event = relay.select_next_some() => {
                    if let SwarmEvent::Behaviour(ProbeEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id, result: kad::QueryResult::GetProviders(result), step, ..
                    })) = event {
                        if id != query { continue; }
                        match result.unwrap() {
                            kad::GetProvidersOk::FoundProviders { providers, .. } => {
                                if providers.contains(&peer) {
                                    found = true;
                                }
                            }
                            kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {}
                        }
                        if step.last || (round == 2 && found) { break; }
                    }
                },
            }
        }
        assert!(found, "actual DHT response must identify the live provider");
        let connected = relay.is_connected(&peer);
        let addresses = dial_addresses(&mut relay, peer).len();
        let request = ContentServiceRequest::new();
        let id = relay.behaviour_mut().service.send_request(&peer, request.clone());
        // Isolate the cached-hit boundary: a later network referral must not supply the
        // missing address before this one RPC dials. Provider hints are not address admission.
        loop {
            tokio::select! {
                event = provider.select_next_some() => respond(&mut provider, event),
                event = contact.select_next_some(), if round != 2 => respond(&mut contact, event),
                event = relay.select_next_some() => match event {
                    SwarmEvent::Behaviour(ProbeEvent::Service(request_response::Event::Message {
                        peer: actual, message: request_response::Message::Response {
                            request_id, response,
                        }, ..
                    })) if request_id == id => {
                        assert_ne!(round, 2, "cached-only peer has no admitted dial address");
                        assert_eq!(actual, peer);
                        response.validate_for(&request).unwrap();
                        assert_eq!(response.offer(), Some([7_u8; 32].as_slice()));
                        break;
                    }
                    SwarmEvent::Behaviour(ProbeEvent::Service(request_response::Event::OutboundFailure {
                        request_id, error, ..
                    })) if request_id == id => {
                        assert_eq!(round, 2, "ordinary network lookup must support the real RPC");
                        assert!(matches!(error, request_response::OutboundFailure::DialFailure));
                        assert_eq!(cached, 1);
                        assert!(!connected);
                        assert_eq!(addresses, 0);
                        eprintln!("KAD_PROVIDER_RPC cached_without_Identify=expected_DialFailure");
                        break;
                    },
                    _ => {}
                },
            }
        }
        }
    }).await.expect("bounded real MemoryTransport query and service exchange");
}
