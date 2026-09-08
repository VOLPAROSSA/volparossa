//! Actual authenticated `MemoryTransport` connections; the service constructor's mDNS socket is
//! additionally isolated with the existing capless namespace runner. No host networking.

use std::{fs, process::Command, task::Poll, time::Duration};

use futures::{StreamExt, future::poll_fn};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport as _,
    core::{transport::MemoryTransport, upgrade},
    identity, noise, ping,
    swarm::{ConnectionId, ListenError, SwarmEvent},
    yamux,
};

use crate::{BehaviourEvent, DiscoveryEvent, DiscoveryProtocolRoles, DiscoveryService};

const INNER: &str = "VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS";
const TEST: &str = "connection_capacity::tests::connection_capacity_live_growth_and_shrink";

#[test]
fn connection_capacity_live_growth_and_shrink() {
    let current = fs::read_link("/proc/self/ns/net").expect("current namespace");
    if let Some(parent) = std::env::var_os(INNER) {
        assert_ne!(current.as_os_str(), parent, "no host socket fallback");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("isolated runtime")
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(60), scenario())
                    .await
                    .expect("bounded actual connection lifecycle");
            });
        return;
    }
    let output = Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/run-isolated-test.sh"
    ))
    .arg(std::env::current_exe().expect("current test executable"))
    .args([TEST, INNER, "none"])
    .output()
    .expect("disposable namespace runner");
    assert!(
        output.status.success(),
        "isolated connection proof failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn peer() -> Swarm<ping::Behaviour> {
    let key = identity::Keypair::generate_ed25519();
    let transport = MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&key).expect("Noise identity"))
        .multiplex(yamux::Config::default())
        .boxed();
    Swarm::new(
        transport,
        ping::Behaviour::new(ping::Config::new()),
        key.public().to_peer_id(),
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(120)),
    )
}

async fn next(
    service: &mut DiscoveryService,
    peers: &mut [Swarm<ping::Behaviour>],
) -> SwarmEvent<BehaviourEvent> {
    loop {
        tokio::select! {
            event = service.next_event() => {
                if let DiscoveryEvent::Other(event) = event {
                    return event;
                }
            }
            () = poll_fn(|cx| {
                for peer in peers.iter_mut() {
                    if peer.poll_next_unpin(cx).is_ready() {
                        return Poll::Ready(());
                    }
                }
                Poll::Pending
            }) => {}
        }
    }
}

async fn add_peer(
    service: &mut DiscoveryService,
    peers: &mut Vec<Swarm<ping::Behaviour>>,
    address: &Multiaddr,
) -> (PeerId, ConnectionId) {
    let mut remote = peer();
    let expected = *remote.local_peer_id();
    remote.dial(address.clone()).expect("bounded single dial");
    peers.push(remote);
    loop {
        match next(service, peers).await {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } if peer_id == expected => return (peer_id, connection_id),
            SwarmEvent::ConnectionClosed { .. } | SwarmEvent::IncomingConnectionError { .. } => {
                panic!("no live connection may close or be denied while growing")
            }
            _ => {}
        }
    }
}

async fn reject_new(
    service: &mut DiscoveryService,
    peers: &mut Vec<Swarm<ping::Behaviour>>,
    address: &Multiaddr,
) {
    let mut remote = peer();
    remote.dial(address.clone()).expect("one final dial");
    peers.push(remote);
    loop {
        match next(service, peers).await {
            SwarmEvent::IncomingConnectionError {
                error: ListenError::Denied { cause },
                ..
            } => {
                let exceeded = cause
                    .downcast_ref::<libp2p::connection_limits::Exceeded>()
                    .expect("typed admission rejection, not failed authentication");
                assert_eq!(exceeded.limit(), 0);
                return;
            }
            SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::ConnectionClosed { .. } => {
                panic!("lowering rejects newcomers without closing any existing connection")
            }
            _ => {}
        }
    }
}

async fn scenario() {
    let mut service = DiscoveryService::new_with_protocol_roles(
        identity::Keypair::generate_ed25519(),
        DiscoveryProtocolRoles::new(false, false, true),
    )
    .expect("production discovery service");
    assert_eq!(service.connection_counters().num_connections(), 0);
    service.listen_on("/memory/0".parse().unwrap()).unwrap();
    let mut peers = Vec::new();
    let address = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = next(&mut service, &mut peers).await {
            break address;
        }
    };
    let first = add_peer(&mut service, &mut peers, &address).await;
    let original = service
        .bind_native_probe_control_connection(first.0, first.1)
        .expect("original affine binding");
    // This is a live update, with an original binding already held under bootstrap defaults.
    service.set_connection_capacity(512);
    let mut last = first;
    for _ in 1..385 {
        last = add_peer(&mut service, &mut peers, &address).await;
    }
    let counts = service.connection_counters();
    assert_eq!(counts.num_established(), 385);
    assert_eq!(counts.num_established_incoming(), 385);
    assert_eq!(counts.num_established_outgoing(), 0);
    assert_eq!(counts.num_pending(), 0);

    service.set_connection_capacity(0);
    reject_new(&mut service, &mut peers, &address).await;
    assert_eq!(service.connection_counters().num_established(), 385);
    let registry = &service.swarm.behaviour().connection_provenance;
    assert!(registry.consume_bound_native_probe_control(original, first.0));
    let closed = registry
        .bind_native_probe_control(first.0, first.1)
        .unwrap();
    let retained = registry.bind_native_probe_control(last.0, last.1).unwrap();
    assert!(service.swarm.close_connection(first.1));
    loop {
        if let SwarmEvent::ConnectionClosed { connection_id, .. } =
            next(&mut service, &mut peers).await
        {
            assert_eq!(
                connection_id, first.1,
                "only explicitly closed lineage retires"
            );
            break;
        }
    }
    assert_eq!(service.connection_counters().num_established(), 384);
    let registry = &service.swarm.behaviour().connection_provenance;
    assert!(!registry.consume_bound_native_probe_control(closed, first.0));
    assert!(registry.consume_bound_native_probe_control(retained, last.0));
}
