//! Real production listener/session/TLS ownership with a contended diagnostic lock.
//! Registration replies are controlled; this is not a relay datapath or consumer proof.

use super::*;
use std::{env, fs, io};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::oneshot,
    time::{Instant, interval_at, sleep},
};
use volparossa_config::Config;
use volparossa_local_control::ProviderActivityStage;
use volparossa_metrics::MetricsRegistry;

fn require_isolation() {
    let parent = env::var_os("VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS")
        .expect("run only through the disposable namespace harness");
    assert!(
        parent
            .to_str()
            .and_then(|value| value.strip_prefix("net:["))
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0)
    );
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
        parent
    );
}

struct Fixture {
    runtime: ContentRuntime,
    state: Arc<RwLock<AgentState>>,
    registry: Arc<Mutex<PublicationRegistry>>,
    peer: libp2p::PeerId,
    endpoint: ProviderEndpoint,
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    actor: JoinHandle<usize>,
    observed: tokio::sync::mpsc::Receiver<usize>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A failing assertion must not detach either fixture-owned task.
        self.task.abort();
        self.actor.abort();
    }
}

impl Fixture {
    async fn new(reply: oneshot::Receiver<Result<(), DiscoveryError>>) -> Self {
        require_isolation();
        let identity = Identity::generate();
        let peer = *identity.peer_id();
        let runtime = ContentRuntime::new(&identity).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = ProviderEndpoint::new("provider.volparossa.test", address.port()).unwrap();
        let tls = tls::ContentTlsServer::new(identity.keypair(), endpoint.hostname()).unwrap();
        let registry = Arc::new(Mutex::new(PublicationRegistry::default()));
        let config = Config::default();
        let state = Arc::new(RwLock::new(
            AgentState::new(&config, config.roles, None, MetricsRegistry::new()).unwrap(),
        ));
        let (discovery, observed, actor) =
            DiscoveryControlHandle::content_refresh_latched_for_test(peer, vec![reply]);
        let (stop, receiver) = watch::channel(false);
        let server = ServingLoop {
            listener,
            tls,
            registry: Arc::clone(&registry),
            signer: Arc::clone(&runtime.signer),
            endpoint: endpoint.clone(),
            discovery,
            stop: receiver,
            automatic: false,
            events: Some(Arc::clone(&state)),
            activity: Arc::clone(&runtime.provider_activity),
            fixture: Arc::clone(&runtime.fixture_correlation),
        };
        // Keep the production 60s cadence; offset only the fixture's first refresh to 100ms.
        let refresh = interval_at(
            Instant::now() - Duration::from_secs(60) + Duration::from_millis(100),
            Duration::from_secs(60),
        );
        let task = tokio::spawn(ContentRuntime::serve_loop_with_refresh(server, refresh));
        Self {
            runtime,
            state,
            registry,
            peer,
            endpoint,
            address,
            stop,
            task,
            actor,
            observed,
        }
    }

    async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ()> {
        let offer = self
            .runtime
            .offer(self.endpoint.clone())
            .unwrap()
            .verify(&self.runtime.signer.verifying_key(), now())
            .unwrap();
        timeout(Duration::from_secs(5), async {
            let stream = TcpStream::connect(self.address).await.map_err(|_| ())?;
            tls::connect(stream, self.peer, &offer)
                .await
                .map_err(|_| ())
        })
        .await
        .map_err(|_| ())?
    }

    async fn stop_joined(&mut self) -> bool {
        let _ = self.stop.send(true);
        let stopped = if let Ok(result) = timeout(Duration::from_secs(5), &mut self.task).await {
            result.is_ok()
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            false
        };
        let actor_joined = if stopped {
            if let Ok(result) = timeout(Duration::from_secs(5), &mut self.actor).await {
                result.is_ok()
            } else {
                self.actor.abort();
                let _ = (&mut self.actor).await;
                false
            }
        } else {
            self.actor.abort();
            let _ = (&mut self.actor).await;
            false
        };
        stopped && actor_joined && TcpStream::connect(self.address).await.is_err()
    }
}

async fn refresh_log_lock_case(outcome: DiscoveryError) {
    let (reply, gate) = oneshot::channel();
    let mut fixture = Fixture::new(gate).await;
    let state = Arc::clone(&fixture.state);
    let lock = state.write().await;
    assert_eq!(
        timeout(Duration::from_secs(5), fixture.observed.recv())
            .await
            .unwrap(),
        Some(1)
    );
    reply.send(Err(outcome)).unwrap();
    // Give the production loop a turn to consume the completed registration before connecting.
    // With the original inline log await it now waits on the held state lock.
    sleep(Duration::from_millis(100)).await;
    let connected = fixture.connect().await;
    let tls_accepted = connected.is_ok();
    // Cancellation of the diagnostic drain must let stop join without releasing the lock.
    let stopped = fixture.stop_joined().await;
    let active = fixture.runtime.provider_activity().active_sessions;
    let logs_while_held = lock.logs(400).records;
    drop(connected);
    drop(lock);
    assert!(logs_while_held.is_empty());
    assert_eq!(active, Some(0));
    assert!(
        tls_accepted && stopped,
        "PROVIDER_EVENT_DRAIN_REFRESH_BLOCKED: fresh TLS or joined stop waited for the held event lock: tls={tls_accepted}, stopped={stopped}"
    );
    println!("PROVIDER_EVENT_DRAIN_REFRESH_PASS");
}

#[tokio::test]
#[ignore = "requires explicit disposable loopback namespace and real provider TLS"]
async fn busy_refresh_log_lock_keeps_accept_and_stop_pollable() {
    refresh_log_lock_case(DiscoveryError::Busy).await;
}

#[tokio::test]
#[ignore = "requires explicit disposable loopback namespace and real provider TLS"]
async fn timeout_refresh_log_lock_keeps_accept_and_stop_pollable() {
    refresh_log_lock_case(DiscoveryError::Timeout).await;
}

#[tokio::test]
#[ignore = "requires explicit disposable loopback namespace; retains real 2-second registry deadline"]
async fn four_rejected_sessions_release_admission_before_event_lock() {
    assert_eq!(MAX_PROVIDER_SESSIONS, 4);
    assert_eq!(REGISTRY_SNAPSHOT_TIMEOUT, Duration::from_secs(2));
    assert_eq!(
        TransferLimits::default().exchange_timeout,
        Duration::from_secs(15)
    );
    let (reply, gate) = oneshot::channel();
    // Leave refresh pending; the same production loop must continue accepting and stopping.
    let mut fixture = Fixture::new(gate).await;
    let state = Arc::clone(&fixture.state);
    let lock = state.write().await;
    let registry = Arc::clone(&fixture.registry);
    let registry_lock = registry.lock().await;
    let mut clients = Vec::new();
    for _ in 0..MAX_PROVIDER_SESSIONS {
        clients.push(fixture.connect().await.expect("initial real TLS session"));
    }
    let all_admitted = timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = fixture.runtime.provider_activity();
            if snapshot.active_sessions == Some(4)
                && snapshot
                    .groups
                    .iter()
                    .all(|group| group.stage == ProviderActivityStage::RegistrySnapshot as i32)
            {
                break;
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_ok();
    let mut all_closed = true;
    for client in &mut clients {
        let closure = timeout(Duration::from_secs(8), client.read(&mut [0_u8; 1])).await;
        all_closed &= matches!(closure, Ok(Ok(0)))
            || matches!(closure, Ok(Err(ref error)) if matches!(error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted));
    }
    // Release only registry access: the fifth TLS exchange still faces the held log lock.
    drop(registry_lock);
    let fifth = fixture.connect().await;
    let fifth_accepted = fifth.is_ok();
    let stopped = fixture.stop_joined().await;
    let active = fixture.runtime.provider_activity().active_sessions;
    let logs_while_held = lock.logs(400).records;
    drop(fifth);
    drop(clients);
    drop(reply);
    drop(lock);
    assert!(
        all_admitted,
        "four real authenticated registry waiters required"
    );
    assert!(
        all_closed,
        "PROVIDER_STREAM_RETAINED_BEHIND_EVENT_LOCK: rejected sockets must close before log unlock"
    );
    assert!(logs_while_held.is_empty());
    assert_eq!(active, Some(0));
    assert!(
        fifth_accepted && stopped,
        "PROVIDER_EVENT_DRAIN_ADMISSION_BLOCKED: fifth TLS or joined stop waited for event logging: tls={fifth_accepted}, stopped={stopped}"
    );
    println!("PROVIDER_EVENT_DRAIN_ADMISSION_PASS");
}
