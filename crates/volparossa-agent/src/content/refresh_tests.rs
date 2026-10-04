//! Real listener/TLS/signed compute framing across synthetic registration failures.
//! This proves service ownership and recovery, not model execution or overlay routing.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use volparossa_content::provider::compute::{
    self as wire, ComputeBackend, ComputeFuture, ComputeService,
};
use volparossa_local_control::compute as rpc;

struct RefusingBroker(AtomicUsize);

impl ComputeBackend for RefusingBroker {
    fn exchange(&self, requester: [u8; 32], bytes: Vec<u8>) -> ComputeFuture<'_> {
        Box::pin(async move {
            let request: rpc::Request = serde_json::from_slice(&bytes).unwrap();
            request.validate(now()).unwrap();
            assert_eq!(request.requester_key, hex::encode(requester));
            assert!(matches!(request.operation, rpc::Operation::Capabilities));
            self.0.fetch_add(1, Ordering::Relaxed);
            // No fake successful inference: the exact attached broker refuses work.
            Ok(serde_json::to_vec(&rpc::Response {
                version: rpc::VERSION,
                request_id: request.request_id,
                outcome: rpc::Outcome::Error(rpc::ErrorCode::Busy),
            })
            .unwrap())
        })
    }
}

struct Fixture {
    runtime: ContentRuntime,
    peer: libp2p::PeerId,
    endpoint: ProviderEndpoint,
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    actor: JoinHandle<usize>,
    observed: tokio::sync::mpsc::Receiver<usize>,
    backend: Arc<RefusingBroker>,
}

async fn fixture(outcomes: Vec<Result<(), DiscoveryError>>) -> Fixture {
    let identity = Identity::generate();
    let peer = *identity.peer_id();
    let runtime = ContentRuntime::new(&identity).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = ProviderEndpoint::new("provider.example", address.port()).unwrap();
    let tls = tls::ContentTlsServer::new(identity.keypair(), endpoint.hostname()).unwrap();
    let backend = Arc::new(RefusingBroker(AtomicUsize::new(0)));
    let mut registry = PublicationRegistry::new();
    registry.set_compute(Arc::new(ComputeService::new(
        Arc::clone(&runtime.signer),
        backend.clone(),
    )));
    let (discovery, observed, actor) =
        DiscoveryControlHandle::content_refresh_for_test(peer, outcomes);
    let (stop, receiver) = watch::channel(false);
    let server = ServingLoop {
        listener,
        tls,
        registry: Arc::new(Mutex::new(registry)),
        signer: Arc::clone(&runtime.signer),
        endpoint: endpoint.clone(),
        discovery,
        stop: receiver,
        automatic: false,
        events: None,
    };
    // Only this test supplies a faster clock; production constructs its fixed 60s timer.
    let task = tokio::spawn(ContentRuntime::serve_loop_with_refresh(
        server,
        interval(Duration::from_millis(100)),
    ));
    Fixture {
        runtime,
        peer,
        endpoint,
        address,
        stop,
        task,
        actor,
        observed,
        backend,
    }
}

async fn observe(fixture: &mut Fixture) -> usize {
    timeout(Duration::from_secs(5), fixture.observed.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn compute_exchange(fixture: &Fixture) {
    let offer = fixture
        .runtime
        .offer(fixture.endpoint.clone())
        .unwrap()
        .verify(&fixture.runtime.signer.verifying_key(), now())
        .unwrap();
    let stream = TcpStream::connect(fixture.address).await.unwrap();
    let mut stream = tls::connect(stream, fixture.peer, &offer).await.unwrap();
    let challenge = wire::begin(
        &mut stream,
        fixture.runtime.signer.verifying_key().as_bytes(),
    )
    .await
    .unwrap();
    let requester = SigningKey::generate(&mut rand_core::OsRng);
    let request = rpc::Request {
        version: rpc::VERSION,
        request_id: "a".repeat(32),
        requester_key: hex::encode(requester.verifying_key().as_bytes()),
        operation: rpc::Operation::Capabilities,
    };
    let response = wire::exchange(
        &mut stream,
        challenge,
        &requester,
        serde_json::to_vec(&request).unwrap(),
    )
    .await
    .unwrap();
    let response: rpc::Response = serde_json::from_slice(&response).unwrap();
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.outcome, rpc::Outcome::Error(rpc::ErrorCode::Busy));
    tls::finish(&mut stream).await.unwrap();
}

#[tokio::test]
async fn transient_registration_refresh_retains_compute_listener_and_recovers() {
    for transient in [DiscoveryError::Busy, DiscoveryError::Timeout] {
        let mut fixture = fixture(vec![Err(transient), Ok(())]).await;
        assert_eq!(observe(&mut fixture).await, 1);
        tokio::task::yield_now().await;
        assert!(
            !fixture.task.is_finished(),
            "transient refresh killed the owned listener"
        );
        compute_exchange(&fixture).await;
        assert_eq!(observe(&mut fixture).await, 2);
        compute_exchange(&fixture).await;
        assert_eq!(fixture.backend.0.load(Ordering::Relaxed), 2);
        fixture.stop.send(true).unwrap();
        timeout(Duration::from_secs(5), fixture.task)
            .await
            .unwrap()
            .unwrap();
        assert!(fixture.actor.await.unwrap() >= 2);
        assert!(
            TcpStream::connect(fixture.address).await.is_err(),
            "owner stop left listener bound"
        );
    }
}

#[tokio::test]
async fn fatal_registration_refresh_still_withdraws_and_joins() {
    for fatal in [
        DiscoveryError::Invalid,
        DiscoveryError::Invalidated,
        DiscoveryError::Unavailable,
        DiscoveryError::Closed,
    ] {
        let mut fixture = fixture(vec![Err(fatal)]).await;
        assert_eq!(observe(&mut fixture).await, 1);
        timeout(Duration::from_secs(5), fixture.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fixture.actor.await.unwrap(), 1);
        assert!(TcpStream::connect(fixture.address).await.is_err());
        assert_eq!(fixture.backend.0.load(Ordering::Relaxed), 0);
    }
}
