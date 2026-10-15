//! Real listener/TLS/signed compute framing across synthetic registration failures.
//! This proves service ownership and recovery, not model execution or overlay routing.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use volparossa_content::provider::compute::{
    self as wire, ComputeBackend, ComputeFuture, ComputeService,
    guest::GuestLimits,
    quote::{QuoteAuthority, QuoteAuthorityFuture, QuoteError, QuoteGrant, QuoteService},
};
use volparossa_local_control::compute as rpc;

struct RefusingBroker(AtomicUsize);

struct QuoteRequester([u8; 32]);

impl QuoteAuthority for QuoteRequester {
    fn check(&self, requester: [u8; 32]) -> QuoteAuthorityFuture<'_> {
        Box::pin(async move {
            if requester == self.0 {
                Ok(())
            } else {
                Err(QuoteError::Unauthorized)
            }
        })
    }
}

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
    fixture_with_replies(RefreshReplies::Immediate(outcomes)).await
}

enum RefreshReplies {
    Immediate(Vec<Result<(), DiscoveryError>>),
    Latched(Vec<oneshot::Receiver<Result<(), DiscoveryError>>>),
}

async fn fixture_with_replies(replies: RefreshReplies) -> Fixture {
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
    let (discovery, observed, actor) = match replies {
        RefreshReplies::Immediate(outcomes) => {
            DiscoveryControlHandle::content_refresh_for_test(peer, outcomes)
        }
        RefreshReplies::Latched(replies) => {
            DiscoveryControlHandle::content_refresh_latched_for_test(peer, replies)
        }
    };
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
        activity: Arc::clone(&runtime.provider_activity),
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

async fn joined(fixture: Fixture) -> usize {
    timeout(Duration::from_secs(5), fixture.task)
        .await
        .unwrap()
        .unwrap();
    let registrations = timeout(Duration::from_secs(5), fixture.actor)
        .await
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(fixture.address).await.is_err());
    registrations
}

#[tokio::test]
async fn automatic_quote_only_refresh_registers_then_withdraws_after_deactivation() {
    let identity = Identity::generate();
    let runtime = ContentRuntime::new(&identity).unwrap();
    let endpoint = ProviderEndpoint::new("provider.example", 8443).unwrap();
    let requester_key = SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes();
    let quote = QuoteService::new(
        Arc::clone(&runtime.signer),
        QuoteGrant {
            requester_key,
            limits: GuestLimits {
                expires_at: now() + 60,
                maximum_attempts: 1,
            },
        },
        Arc::clone(&runtime.quote_firmware),
        Arc::new(QuoteRequester(requester_key)),
    )
    .unwrap();
    // A real owned supervisor is live, but no request or firmware operation is made.
    let supervisor = tokio::spawn(Arc::clone(&quote).supervise().unwrap());
    let mut registry = PublicationRegistry::new();
    registry.set_quote(Arc::clone(&quote));
    assert!(registry.has_quote());
    assert!(!registry.has_compute());
    assert!(!registry.has_private_storage());
    let registry = Mutex::new(registry);
    let (discovery, mut observed, actor) =
        DiscoveryControlHandle::content_refresh_for_test(*identity.peer_id(), vec![Ok(())]);
    let refresh = refresh_provider_offer(true, &registry, &runtime.signer, &endpoint, &discovery);
    assert!(matches!(
        timeout(Duration::from_secs(5), refresh).await.unwrap(),
        ProviderRefresh::Registered(Ok(()))
    ));
    assert_eq!(observed.try_recv().unwrap(), 1);

    quote.deactivate();
    assert!(!registry.lock().await.has_quote());
    let refresh = refresh_provider_offer(true, &registry, &runtime.signer, &endpoint, &discovery);
    assert!(matches!(
        timeout(Duration::from_secs(5), refresh).await.unwrap(),
        ProviderRefresh::Withdrawn
    ));
    assert_eq!(
        timeout(Duration::from_secs(5), actor)
            .await
            .unwrap()
            .unwrap(),
        1
    );
    timeout(Duration::from_secs(5), supervisor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.quote_firmware.available_permits(), 1);
}

#[tokio::test]
async fn pending_registration_refresh_serves_real_tls_without_overlapping_refreshes() {
    let (reply, gate) = oneshot::channel();
    let mut fixture = fixture_with_replies(RefreshReplies::Latched(vec![gate])).await;
    assert_eq!(observe(&mut fixture).await, 1);
    // The real bounded register_content_offer call has not received its reply.
    // The old inline-await loop cannot accept this ClientHello until we release it.
    timeout(Duration::from_secs(5), compute_exchange(&fixture))
        .await
        .expect("pending registration must not block the real TLS exchange");
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(matches!(
        fixture.observed.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(!reply.is_closed());
    assert_eq!(fixture.backend.0.load(Ordering::Relaxed), 1);
    fixture.stop.send(true).unwrap();
    assert_eq!(joined(fixture).await, 1);
    assert!(reply.is_closed());
}

#[tokio::test]
async fn stop_cancels_pending_registration_before_withdrawal() {
    let (reply, gate) = oneshot::channel();
    let mut fixture = fixture_with_replies(RefreshReplies::Latched(vec![gate])).await;
    assert_eq!(observe(&mut fixture).await, 1);
    assert!(!reply.is_closed());
    fixture.stop.send(true).unwrap();
    // The actor verifies that the original registration receiver is closed before
    // acknowledging Withdraw; no 15s RPC timeout or fixture reply is needed to stop.
    assert_eq!(joined(fixture).await, 1);
    assert!(reply.is_closed());
}

#[tokio::test]
async fn delayed_transient_registration_recovers_without_restarting_listener() {
    for transient in [DiscoveryError::Busy, DiscoveryError::Timeout] {
        let (first, first_gate) = oneshot::channel();
        let (second, second_gate) = oneshot::channel();
        let mut fixture =
            fixture_with_replies(RefreshReplies::Latched(vec![first_gate, second_gate])).await;
        assert_eq!(observe(&mut fixture).await, 1);
        timeout(Duration::from_secs(5), compute_exchange(&fixture))
            .await
            .unwrap();
        first.send(Err(transient)).unwrap();
        assert_eq!(observe(&mut fixture).await, 2);
        timeout(Duration::from_secs(5), compute_exchange(&fixture))
            .await
            .unwrap();
        assert!(!second.is_closed());
        second.send(Ok(())).unwrap();
        assert_eq!(observe(&mut fixture).await, 3);
        assert!(!fixture.task.is_finished());
        assert_eq!(fixture.backend.0.load(Ordering::Relaxed), 2);
        fixture.stop.send(true).unwrap();
        assert!(joined(fixture).await >= 3);
    }
}

#[tokio::test]
async fn delayed_fatal_registration_closes_listener_and_owned_tls_session() {
    use tokio::io::AsyncReadExt;

    let (reply, gate) = oneshot::channel();
    let mut fixture = fixture_with_replies(RefreshReplies::Latched(vec![gate])).await;
    assert_eq!(observe(&mut fixture).await, 1);
    let offer = fixture
        .runtime
        .offer(fixture.endpoint.clone())
        .unwrap()
        .verify(&fixture.runtime.signer.verifying_key(), now())
        .unwrap();
    let stream = TcpStream::connect(fixture.address).await.unwrap();
    let mut stream = timeout(
        Duration::from_secs(5),
        tls::connect(stream, fixture.peer, &offer),
    )
    .await
    .unwrap()
    .unwrap();
    wire::begin(
        &mut stream,
        fixture.runtime.signer.verifying_key().as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(fixture.backend.0.load(Ordering::Relaxed), 0);
    reply.send(Err(DiscoveryError::Invalidated)).unwrap();
    assert_eq!(joined(fixture).await, 1);
    let closed = timeout(Duration::from_secs(5), stream.read(&mut [0_u8; 1]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
}

#[tokio::test]
async fn pending_refresh_never_extends_an_expired_signed_offer() {
    let (reply, gate) = oneshot::channel();
    let mut fixture = fixture_with_replies(RefreshReplies::Latched(vec![gate])).await;
    assert_eq!(observe(&mut fixture).await, 1);
    let created = now() - 10;
    let expired = SignedProviderOffer::sign(
        &fixture.runtime.signer,
        fixture.endpoint.clone(),
        Validity {
            created,
            expires: created + 1,
        },
    )
    .unwrap()
    .verify(&fixture.runtime.signer.verifying_key(), created)
    .unwrap();
    let stream = TcpStream::connect(fixture.address).await.unwrap();
    assert!(matches!(
        tls::connect(stream, fixture.peer, &expired).await,
        Err(tls::ContentTlsError::Offer)
    ));
    assert_eq!(fixture.backend.0.load(Ordering::Relaxed), 0);
    timeout(Duration::from_secs(5), compute_exchange(&fixture))
        .await
        .unwrap();
    assert!(!reply.is_closed());
    fixture.stop.send(true).unwrap();
    assert_eq!(joined(fixture).await, 1);
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
