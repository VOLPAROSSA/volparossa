//! Recovery of exact, locally configured discovery listeners.

use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    Multiaddr, Swarm,
    core::transport::ListenerId,
    swarm::{NetworkBehaviour, SwarmEvent},
};

use crate::{DiscoveryError, MAX_DISCOVERY_ADDRESS_BYTES};

// Product configuration has at most sixteen listeners; reserve bounded headroom for one
// explicitly installed mesh listener and other local callers. Events cannot add requests.
const MAX_CONFIGURED_LISTENERS: usize = 32;
const LISTENER_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerState {
    Listening(ListenerId),
    Backoff(Instant),
}

struct ConfiguredListener {
    request: Multiaddr,
    state: ListenerState,
}

/// The original configured request is retained independently of transport-derived addresses.
/// There is no background task: retries exist only while the owning discovery pump is running.
#[derive(Default)]
pub(super) struct ConfiguredListeners {
    entries: Vec<ConfiguredListener>,
    stopped: bool,
}

impl ConfiguredListeners {
    fn validate_request(&self, address: &Multiaddr) -> Result<bool, DiscoveryError> {
        if self.stopped {
            return Err(DiscoveryError::Swarm(
                "discovery listeners are stopped".into(),
            ));
        }
        if address.len() > MAX_DISCOVERY_ADDRESS_BYTES {
            return Err(DiscoveryError::ResourceLimit);
        }
        if self.entries.iter().any(|entry| entry.request == *address) {
            return Ok(false);
        }
        if self.entries.len() >= MAX_CONFIGURED_LISTENERS {
            return Err(DiscoveryError::ResourceLimit);
        }
        Ok(true)
    }

    pub(super) fn listen_on<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        address: Multiaddr,
    ) -> Result<(), DiscoveryError> {
        if !self.validate_request(&address)? {
            return Ok(());
        }
        // A failed initial bind keeps its existing startup error semantics. Only successfully
        // owned listeners gain recovery authority, not arbitrary failed/event-derived addresses.
        let listener_id = swarm
            .listen_on(address.clone())
            .map_err(|error| DiscoveryError::Swarm(error.to_string()))?;
        self.entries.push(ConfiguredListener {
            request: address,
            state: ListenerState::Listening(listener_id),
        });
        Ok(())
    }

    fn closed(&mut self, listener_id: ListenerId, now: Instant) {
        if self.stopped {
            return;
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.state == ListenerState::Listening(listener_id))
        {
            entry.state = ListenerState::Backoff(now + LISTENER_RETRY_INTERVAL);
            tracing::warn!(
                event = "DISCOVERY_CONFIGURED_LISTENER_CLOSED",
                "configured discovery listener closed; bounded recovery scheduled"
            );
        }
    }

    fn next_retry(&self) -> Option<Instant> {
        if self.stopped {
            return None;
        }
        self.entries
            .iter()
            .filter_map(|entry| match entry.state {
                ListenerState::Backoff(deadline) => Some(deadline),
                ListenerState::Listening(_) => None,
            })
            .min()
    }

    fn retry_due<B: NetworkBehaviour>(&mut self, swarm: &mut Swarm<B>, now: Instant) {
        if self.stopped {
            return;
        }
        for entry in &mut self.entries {
            let ListenerState::Backoff(deadline) = entry.state else {
                continue;
            };
            if deadline > now {
                continue;
            }
            entry.state = match swarm.listen_on(entry.request.clone()) {
                Ok(listener_id) => ListenerState::Listening(listener_id),
                Err(_) => ListenerState::Backoff(now + LISTENER_RETRY_INTERVAL),
            };
        }
    }

    pub(super) async fn next_event<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
    ) -> SwarmEvent<B::ToSwarm> {
        loop {
            self.retry_due(swarm, Instant::now());
            let event = tokio::select! {
                event = swarm.select_next_some() => event,
                () = wait_for_retry(self.next_retry()) => continue,
            };
            if let SwarmEvent::ListenerClosed { listener_id, .. } = &event {
                // Quinn may end its driver and libp2p reports this as an Ok closure. Both
                // reasons are unexpected while this exact configured owner is still active.
                self.closed(*listener_id, Instant::now());
            }
            return event;
        }
    }

    pub(super) fn stop_recovery(&mut self) {
        self.stopped = true;
    }

    pub(super) fn stop<B: NetworkBehaviour>(&mut self, swarm: &mut Swarm<B>) {
        self.stop_recovery();
        for entry in self.entries.drain(..) {
            if let ListenerState::Listening(listener_id) = entry.state {
                swarm.remove_listener(listener_id);
            }
        }
    }
}

async fn wait_for_retry(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        net::UdpSocket,
        path::Path,
        process::Command,
        time::{Duration, Instant},
    };

    use libp2p::{Multiaddr, PeerId, core::transport::ListenerId, identity, swarm::SwarmEvent};
    use tokio::time::timeout;

    use super::{
        ConfiguredListener, ConfiguredListeners, LISTENER_RETRY_INTERVAL, ListenerState,
        MAX_CONFIGURED_LISTENERS,
    };
    use crate::{DiscoveryService, PeerLink};

    async fn next_listener(service: &mut DiscoveryService) -> (ListenerId, Multiaddr) {
        loop {
            if let SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } = service.next_internal_event().await
            {
                return (listener_id, address);
            }
        }
    }

    async fn connect_exact(
        server: &mut DiscoveryService,
        client: &mut DiscoveryService,
        address: &Multiaddr,
    ) {
        let server_peer = *server.local_peer_id();
        let client_peer = *client.local_peer_id();
        client
            .dial_peerlink(&PeerLink::new(server_peer, address.clone()).unwrap())
            .unwrap();
        timeout(Duration::from_secs(8), async {
            let mut server_authenticated = false;
            let mut client_authenticated = false;
            while !server_authenticated || !client_authenticated {
                tokio::select! {
                    event = server.next_internal_event() => {
                        server_authenticated |= established_peer(&event) == Some(client_peer);
                    }
                    event = client.next_internal_event() => {
                        client_authenticated |= established_peer(&event) == Some(server_peer);
                    }
                }
            }
        })
        .await
        .expect("both exact peers authenticate over the actual QUIC listener");
    }

    fn established_peer(event: &SwarmEvent<crate::BehaviourEvent>) -> Option<PeerId> {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => Some(*peer_id),
            _ => None,
        }
    }

    async fn prove_retirement_preserves_connection(
        server: &mut DiscoveryService,
        client: &mut DiscoveryService,
    ) {
        let server_peer = *server.local_peer_id();
        let client_peer = *client.local_peer_id();
        server.stop_listener_recovery();
        assert!(server.configured_listeners.next_retry().is_none());
        assert!(timeout(Duration::from_millis(250), async {
            loop {
                tokio::select! {
                    event = server.next_internal_event() => {
                        if let SwarmEvent::ConnectionClosed { peer_id, .. } = event {
                            assert_ne!(peer_id, client_peer, "retirement retains the actual QUIC connection");
                        }
                    }
                    event = client.next_internal_event() => {
                        if let SwarmEvent::ConnectionClosed { peer_id, .. } = event {
                            assert_ne!(peer_id, server_peer, "retirement retains the actual QUIC connection");
                        }
                    }
                }
            }
        }).await.is_err());
        assert!(server.swarm.is_connected(&client_peer));
        assert!(client.swarm.is_connected(&server_peer));
    }

    async fn prove_quic_recovery() {
        let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let requested: Multiaddr = format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .unwrap();
        drop(reservation);
        let mut server = DiscoveryService::new(identity::Keypair::generate_ed25519()).unwrap();
        let mut client = DiscoveryService::new(identity::Keypair::generate_ed25519()).unwrap();
        server.listen_on(requested.clone()).unwrap();
        let (original_id, original_address) =
            timeout(Duration::from_secs(3), next_listener(&mut server))
                .await
                .unwrap();
        assert_eq!(original_address, requested);
        connect_exact(&mut server, &mut client, &requested).await;

        // Close the real transport underneath the owner, just as an endpoint driver stopping
        // does. The pinned QUIC transport emits ListenerClosed with Ok, not ListenerError.
        assert!(server.swarm.remove_listener(original_id));
        timeout(Duration::from_secs(3), async {
            loop {
                if let SwarmEvent::ListenerClosed {
                    listener_id,
                    reason,
                    ..
                } = server.next_internal_event().await
                {
                    assert_eq!(listener_id, original_id);
                    assert!(reason.is_ok());
                    break;
                }
            }
        })
        .await
        .unwrap();
        let (replacement_id, replacement_address) =
            timeout(Duration::from_secs(4), next_listener(&mut server))
                .await
                .expect("unexpected listener closure must reopen the exact configured address");
        assert_ne!(replacement_id, original_id);
        assert_eq!(replacement_address, requested);
        let mut replacement_client =
            DiscoveryService::new(identity::Keypair::generate_ed25519()).unwrap();
        connect_exact(&mut server, &mut replacement_client, &requested).await;
        prove_unavailable_bind_backoff(&mut server);
        prove_retirement_preserves_connection(&mut server, &mut replacement_client).await;
        server.stop_listening();
        assert!(server.configured_listeners.entries.is_empty());
        assert!(server.listen_on(requested.clone()).is_err());
        assert!(
            timeout(LISTENER_RETRY_INTERVAL * 2, async {
                loop {
                    if let SwarmEvent::NewListenAddr { .. } = server.next_internal_event().await {
                        panic!("intentional shutdown must not recreate any listener");
                    }
                }
            })
            .await
            .is_err()
        );
        println!("CONFIGURED_LISTENER_QUIC_RECOVERY=pass");
    }

    fn prove_unavailable_bind_backoff(server: &mut DiscoveryService) {
        let now = Instant::now();
        // This address is not assigned in the disposable namespace. A real bind failure must
        // retain one slot and defer the next syscall; it must not fall back to a wildcard socket.
        let unavailable: Multiaddr = "/ip4/192.0.2.99/udp/41000/quic-v1".parse().unwrap();
        let mut listeners = ConfiguredListeners::default();
        listeners.entries.push(ConfiguredListener {
            request: unavailable.clone(),
            state: ListenerState::Backoff(now),
        });
        listeners.retry_due(&mut server.swarm, now);
        assert_eq!(listeners.next_retry(), Some(now + LISTENER_RETRY_INTERVAL));
        listeners.retry_due(&mut server.swarm, now + LISTENER_RETRY_INTERVAL / 2);
        assert_eq!(listeners.next_retry(), Some(now + LISTENER_RETRY_INTERVAL));
        listeners.retry_due(&mut server.swarm, now + LISTENER_RETRY_INTERVAL);
        assert_eq!(
            listeners.next_retry(),
            Some(now + LISTENER_RETRY_INTERVAL * 2)
        );
        assert_eq!(listeners.entries.len(), 1);
        assert_eq!(listeners.entries[0].request, unavailable);
        let pending = listeners.entries[0].state;
        listeners.stop_recovery();
        listeners.retry_due(&mut server.swarm, now + LISTENER_RETRY_INTERVAL * 3);
        assert_eq!(listeners.entries[0].state, pending);
        listeners.stop(&mut server.swarm);
        assert!(listeners.next_retry().is_none());
    }

    #[test]
    fn configured_listener_recovery_is_bounded_and_duplicate_closure_cannot_delay_retry() {
        let now = Instant::now();
        let mut listeners = ConfiguredListeners::default();
        for index in 0..MAX_CONFIGURED_LISTENERS {
            let request: Multiaddr = format!("/memory/{}", index + 1).parse().unwrap();
            assert!(listeners.validate_request(&request).unwrap());
            listeners.entries.push(ConfiguredListener {
                request,
                state: ListenerState::Listening(ListenerId::next()),
            });
        }
        assert!(
            listeners
                .validate_request(&"/memory/1000".parse().unwrap())
                .is_err()
        );
        let original_request = listeners.entries[0].request.clone();
        assert!(!listeners.validate_request(&original_request).unwrap());
        let ListenerState::Listening(id) = listeners.entries[0].state else {
            panic!("active fixture")
        };
        listeners.closed(id, now);
        listeners.closed(id, now + LISTENER_RETRY_INTERVAL / 2);
        listeners.closed(ListenerId::next(), now);
        assert_eq!(listeners.next_retry(), Some(now + LISTENER_RETRY_INTERVAL));
        assert_eq!(listeners.entries.len(), MAX_CONFIGURED_LISTENERS);
        assert_eq!(listeners.entries[0].request, original_request);
        assert!(!listeners.validate_request(&original_request).unwrap());
        listeners.stopped = true;
        assert!(listeners.validate_request(&original_request).is_err());
    }

    #[test]
    fn configured_listener_quic_close_reopens_in_disposable_namespace() {
        const PARENT: &str = "VOLPAROSSA_LISTENER_RECOVERY_PARENT_NETNS";
        const TEST: &str = "listener_recovery::tests::configured_listener_quic_close_reopens_in_disposable_namespace";
        let namespace = || fs::read_link("/proc/thread-self/ns/net").unwrap();
        let original = namespace();
        let Ok(parent) = env::var(PARENT) else {
            let output = Command::new("/usr/bin/timeout")
                .args([
                    "30",
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                ])
                .arg(env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(PARENT, &original)
                .output()
                .expect("bounded disposable listener proof");
            assert_eq!(namespace(), original, "host network namespace is unchanged");
            if output.status.code() == Some(1)
                && output.stdout.is_empty()
                && matches!(
                    output.stderr.as_slice(),
                    b"unshare: unshare failed: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                )
            {
                eprintln!("SKIP: disposable user/netns unavailable; no host networking changed");
                return;
            }
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("CONFIGURED_LISTENER_QUIC_RECOVERY=pass")
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
            return;
        };
        eprintln!("CONFIGURED_LISTENER_CHILD_STARTED");
        assert_ne!(
            original,
            Path::new(&parent),
            "never configure host loopback"
        );
        let output = Command::new("/usr/bin/ip")
            .args(["link", "set", "lo", "up"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(prove_quic_recovery());
    }
}
