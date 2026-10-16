//! One signed FINALIZE through the production outer TLS/MPTCP adapter in an isolated netns.
//! The two signed relay grants are authorization fixtures, not deployed `WireGuard` paths.

use super::*;
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    env, fs,
    os::fd::AsRawFd,
    path::PathBuf,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    task::{Context, Poll},
};
use tokio::{
    io::{DuplexStream, ReadBuf},
    task::{JoinError, JoinSet},
    time::{Instant, timeout_at},
};
use volparossa_content::provider::{
    activity::{Observer, Stage},
    serve_publication_with_activity,
};
use volparossa_mptcp::MptcpStream;
use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol, VerifiedManifest};
use volparossa_protocol::{ReplayCache, TimePolicy, Transport};
use volparossa_tcp_proxy::{
    TcpAuthorizationScope, Tls13MptcpClient, Tls13MptcpServer, Tls13MptcpStream,
    VerifiedMptcpRoute, read_authorized_open_tcp, write_open_tcp,
};
use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};
use wire::begin_observation::{self, Phase};

const EXIT_NAME: &str = "exit.volparossa.invalid";
const PROVIDER_PORT: u16 = 18080;

struct Outer {
    route: VerifiedMptcpRoute,
    policy: VerifiedManifest,
    opening: Vec<u8>,
    client: Tls13MptcpClient,
    server: Tls13MptcpServer,
}

impl Outer {
    fn new() -> Self {
        let now = crate::unix_millis();
        let fixture = SignedRouteFixture::new(2, &[Transport::TcpMptcp], now).unwrap();
        let reservations = fixture
            .relay_reservations()
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let route = VerifiedMptcpRoute::verify(
            fixture.exit_reservation(),
            &reservations,
            now,
            TimePolicy::default(),
            &mut ReplayCache::new(16).unwrap(),
        )
        .unwrap();
        assert_eq!(route.path_count(), 2);
        let policy = verified_development_manifest(
            now,
            vec![
                DestinationRule::exact_domain(
                    HOSTNAME,
                    [ProtocolPort::new(TransportProtocol::Tcp, PROVIDER_PORT).unwrap()],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let opening = fixture
            .sign_open_tcp(policy.policy_hash(), HOSTNAME, PROVIDER_PORT, now)
            .unwrap();
        let certified = generate_simple_self_signed(vec![EXIT_NAME.into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        Self {
            route,
            policy,
            opening,
            client: Tls13MptcpClient::new(roots).unwrap(),
            server: Tls13MptcpServer::new(vec![certificate], private_key).unwrap(),
        }
    }
}

#[derive(Default)]
struct Proof {
    outer_handshakes: AtomicUsize,
    provider_stages: AtomicUsize,
    client_phases: AtomicUsize,
    receipt_verified: AtomicBool,
    close_started: AtomicUsize,
    dropped: AtomicUsize,
}

impl Proof {
    fn outer(&self, stream: &Tls13MptcpStream) {
        // Reobserve the same kernel socket after the production TLS entry point.
        assert!(stream.negotiation_info().unwrap().is_negotiated());
        self.outer_handshakes.fetch_add(1, SeqCst);
    }
}

impl Observer for Proof {
    fn enter(&self, stage: Stage) {
        let bit = match stage {
            Stage::StorageGrantReadVerify => 1,
            Stage::StorageChallengeWriteFlush => 2,
            Stage::StorageRequestReadVerify => 4,
            Stage::StorageOperation => 8,
            _ => 0,
        };
        self.provider_stages.fetch_or(bit, SeqCst);
    }
}

impl begin_observation::Observer for Proof {
    fn phase(&self, phase: Phase) {
        let bit = match phase {
            Phase::SelectorWriteFlush => 1,
            Phase::GrantWriteFlush => 2,
            Phase::ChallengeReadVerify => 4,
        };
        self.client_phases.fetch_or(bit, SeqCst);
    }
}

// Count owned endpoints without retaining a second FD or changing read/write/shutdown behavior.
struct Owned<S> {
    stream: S,
    proof: Arc<Proof>,
}

impl<S> Owned<S> {
    fn new(stream: S, proof: &Arc<Proof>) -> Self {
        Self {
            stream,
            proof: Arc::clone(proof),
        }
    }
}

impl<S> Drop for Owned<S> {
    fn drop(&mut self) {
        self.proof.dropped.fetch_add(1, SeqCst);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Owned<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, bytes)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Owned<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

enum Completed {
    Client(Box<StorageTransfer>),
    Provider,
    Proxy,
}

async fn client(
    fixture: Arc<Fixture>,
    outer: Arc<Outer>,
    stream: MptcpStream,
    target: StorageTarget,
    proof: Arc<Proof>,
    receipt: Arc<Barrier>,
) -> Completed {
    let mut transport = outer
        .client
        .connect_preconnected(
            &outer.route,
            stream,
            ServerName::try_from(EXIT_NAME).unwrap(),
            crate::unix_millis(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    proof.outer(&transport);
    write_open_tcp(&mut transport, &outer.opening, Duration::from_secs(10))
        .await
        .unwrap();
    let mut transport = Owned::new(transport, &proof);
    let mut inner = connect(
        &mut transport,
        fixture.provider_peer,
        &fixture.provider_offer,
    )
    .await
    .unwrap();
    let challenge = wire::begin_observed(&mut inner, &fixture.grant, proof.as_ref())
        .await
        .unwrap();
    let now = crate::content::now();
    let request = SignedStorageRequest::sign(
        &fixture.owner,
        &fixture.grant,
        &challenge,
        target,
        StorageOperation::Finalize,
        Validity {
            created: now,
            expires: (now + 60).min(challenge.validity().expires),
        },
    )
    .unwrap();
    let (mut owner, mut agent) = duplex(4096);
    let (received, bridged) = tokio::join!(
        wire::finish(&mut owner, &fixture.grant, &challenge, &request, &[]),
        wire::bridge(&mut agent, &mut inner, &fixture.grant, &challenge),
    );
    let received = received.unwrap();
    assert_eq!(received.receipt.encode(), bridged.unwrap().receipt.encode());
    assert_eq!(proof.close_started.load(SeqCst), 0);
    proof.receipt_verified.store(true, SeqCst);
    // No extra application write, TLS close, or kernel EOF can induce this receipt.
    receipt.wait().await;
    proof.close_started.fetch_add(1, SeqCst);
    finish(&mut inner).await.unwrap();
    drop(inner);
    finish(&mut transport).await.unwrap();
    Completed::Client(Box::new(received))
}

async fn provider(
    fixture: Arc<Fixture>,
    stream: Owned<DuplexStream>,
    proof: Arc<Proof>,
    receipt: Arc<Barrier>,
) -> Completed {
    let mut stream = fixture.provider_tls.accept(stream).await.unwrap();
    serve_publication_with_activity(
        &mut stream,
        &fixture.registry,
        TransferLimits::default(),
        &mut None,
        proof.as_ref(),
    )
    .await
    .unwrap();
    receipt.wait().await;
    assert!(proof.receipt_verified.load(SeqCst));
    proof.close_started.fetch_add(1, SeqCst);
    finish(&mut stream).await.unwrap();
    Completed::Provider
}

async fn proxy(
    outer: Arc<Outer>,
    stream: MptcpStream,
    mut forwarded: Owned<DuplexStream>,
    proof: Arc<Proof>,
) -> Completed {
    let mut stream = outer
        .server
        .accept(stream, Duration::from_secs(10))
        .await
        .unwrap();
    proof.outer(&stream);
    let scope = TcpAuthorizationScope::new(&outer.route, &outer.policy);
    let authorized = read_authorized_open_tcp(
        &mut stream,
        &scope,
        crate::unix_millis(),
        TimePolicy::default(),
        &mut ReplayCache::new(16).unwrap(),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(authorized.hostname(), Some(HOSTNAME));
    assert_eq!(authorized.port(), PROVIDER_PORT);
    let mut stream = Owned::new(stream, &proof);
    // The original helper checks the actual inner ClientHello and uses the production proxy.
    forward(&mut stream, &mut forwarded).await;
    Completed::Proxy
}

async fn prepared() -> (Arc<Fixture>, StorageTarget) {
    let fixture = Arc::new(Fixture::new());
    let bytes = b"kernel-signed-finalize";
    let mut target = StorageTarget {
        archive_id: [42; 32],
        lease_id: None,
        ciphertext_bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    };
    // Preparation is the existing signed in-memory fixture, not kernel-path evidence.
    let reserved = fixture
        .exchange(
            target,
            StorageOperation::Reserve {
                expires_at: crate::content::now() + 600,
            },
            &[],
        )
        .await;
    assert_eq!(reserved.receipt.result().state, ReceiptState::Reserved);
    target.lease_id = Some(reserved.receipt.result().lease_id);
    let appended = fixture
        .exchange(
            target,
            StorageOperation::Append {
                offset: 0,
                length: u32::try_from(bytes.len()).unwrap(),
                sha256: target.sha256,
            },
            bytes,
        )
        .await;
    assert_eq!(
        appended.receipt.result().stored_bytes,
        target.ciphertext_bytes
    );
    (fixture, target)
}

fn descriptor(stream: &MptcpStream) -> (PathBuf, PathBuf) {
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}",
        stream.as_tcp_stream().as_raw_fd()
    ));
    let identity = fs::read_link(&path).unwrap();
    (path, identity)
}

async fn drain(tasks: &mut JoinSet<Completed>) -> Vec<Result<Completed, JoinError>> {
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result);
    }
    results
}

fn require_isolation() {
    let parent = env::var_os("VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS")
        .expect("run only through the explicit disposable namespace harness");
    let parent_number = parent
        .to_str()
        .and_then(|value| value.strip_prefix("net:["))
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok());
    assert!(parent_number.is_some_and(|value| value > 0));
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
        parent
    );
    let enabled = fs::read_to_string("/proc/sys/net/mptcp/enabled").unwrap();
    assert_eq!(enabled.trim(), "1");
}

#[tokio::test]
#[ignore = "requires explicit hosted disposable net/PID namespaces and genuine Linux MPTCP"]
async fn signed_storage_finalize_over_kernel_mptcp_tls() {
    require_isolation();
    let (fixture, target) = Box::pin(prepared()).await;
    let outer = Arc::new(Outer::new());
    let proof = Arc::new(Proof::default());
    let receipt = Arc::new(Barrier::new(2));
    let deadline = Instant::now() + Duration::from_secs(10);
    let listener = volparossa_mptcp::listen("127.0.0.1:0".parse().unwrap(), 2).unwrap();
    let (client_stream, exit_stream) = timeout_at(deadline, async {
        let (client, server) = tokio::join!(
            volparossa_mptcp::connect(listener.local_addr().unwrap(), None, Duration::from_secs(2)),
            listener.accept(),
        );
        (client.unwrap(), server.unwrap().0)
    })
    .await
    .expect("original deadline includes actual MPTCP connection establishment");
    client_stream.require_negotiated().unwrap();
    exit_stream.require_negotiated().unwrap();
    let descriptors = [descriptor(&client_stream), descriptor(&exit_stream)];
    drop(listener);
    let (forwarded, provider_stream) = duplex(16);
    let mut tasks = JoinSet::new();
    tasks.spawn(Box::pin(client(
        Arc::clone(&fixture),
        Arc::clone(&outer),
        client_stream,
        target,
        Arc::clone(&proof),
        Arc::clone(&receipt),
    )));
    tasks.spawn(Box::pin(provider(
        fixture,
        Owned::new(provider_stream, &proof),
        Arc::clone(&proof),
        receipt,
    )));
    tasks.spawn(Box::pin(proxy(
        outer,
        exit_stream,
        Owned::new(forwarded, &proof),
        Arc::clone(&proof),
    )));
    let completed = timeout_at(deadline, drain(&mut tasks)).await;
    let observed = (
        proof.outer_handshakes.load(SeqCst),
        proof.client_phases.load(SeqCst),
        proof.provider_stages.load(SeqCst),
        proof.receipt_verified.load(SeqCst),
        proof.close_started.load(SeqCst),
        proof.dropped.load(SeqCst),
    );
    if completed.is_err() {
        tasks.abort_all();
        drain(&mut tasks).await;
    }
    // Check cleanup after all joins, including task panics and the original deadline path.
    assert!(tasks.is_empty());
    for (path, identity) in descriptors {
        assert_ne!(
            fs::read_link(path).ok(),
            Some(identity),
            "owned MPTCP FD survived join"
        );
    }
    assert!(
        completed.is_ok(),
        "same ten-second deadline; before cleanup (TLS, client phases, provider stages, receipt, close, dropped)={observed:?}"
    );
    let completed = completed.unwrap();
    assert_eq!(completed.len(), 3);
    assert_eq!(proof.outer_handshakes.load(SeqCst), 2);
    assert_eq!(proof.provider_stages.load(SeqCst), 15);
    assert_eq!(proof.client_phases.load(SeqCst), 7);
    assert!(proof.receipt_verified.load(SeqCst));
    assert_eq!(proof.close_started.load(SeqCst), 2);
    assert_eq!(proof.dropped.load(SeqCst), 4);
    assert_eq!(Arc::strong_count(&proof), 1);
    let mut receipts = 0;
    for result in completed {
        if let Completed::Client(transfer) = result.unwrap() {
            assert_eq!(transfer.receipt.result().state, ReceiptState::Committed);
            assert_eq!(
                transfer.receipt.result().stored_bytes,
                target.ciphertext_bytes
            );
            assert!(transfer.ciphertext.is_empty());
            receipts += 1;
        }
    }
    assert_eq!(receipts, 1);
}
