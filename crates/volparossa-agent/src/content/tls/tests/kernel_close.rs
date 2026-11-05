//! Signed RESERVE across real loopback TCP, nested TLS and negotiated kernel MPTCP.
//! Signed relay grants are fixtures, not deployed `WireGuard` paths or multipath proof.

use super::*;
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest as _, Sha256};
use std::{
    env, fs,
    future::Future,
    os::fd::AsRawFd,
    path::PathBuf,
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{AbortHandle, JoinSet},
    time::{Instant, timeout_at},
};
use volparossa_content::private_storage::{
    PrivateStorageStore, StorageLimits,
    protocol::{
        GrantLimits, ReceiptState, SignedStorageGrant, SignedStorageRequest, StorageOperation,
        StorageRights, StorageTarget, VerifiedStorageGrant,
    },
    provider::PrivateStorageProvider,
    wire::{self, StorageService},
};
use volparossa_mptcp::MptcpStream;
use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol, VerifiedManifest};
use volparossa_protocol::{ReplayCache, TimePolicy, Transport};
use volparossa_tcp_proxy::{
    StreamTransferLimits, TcpAuthorizationScope, Tls13MptcpClient, Tls13MptcpServer,
    Tls13MptcpStream, VerifiedMptcpRoute, proxy_bidirectional, read_authorized_open_tcp,
    write_open_tcp,
};
use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};

mod repeated_egress;

const EXIT_NAME: &str = "exit.volparossa.invalid";
const PROVIDER_PORT: u16 = 18080;
const SCENARIO_LIMIT: Duration = Duration::from_secs(10);

struct Fixture {
    _temporary: tempfile::TempDir,
    owner: SigningKey,
    grant: VerifiedStorageGrant,
    registry: PublicationRegistry,
    provider_peer: PeerId,
    provider_offer: VerifiedProviderOffer,
    provider_tls: ContentTlsServer,
}

impl Fixture {
    fn new() -> Self {
        let provider = identity::Keypair::generate_ed25519();
        let pair = provider.clone().try_into_ed25519().unwrap();
        let bytes = Zeroizing::new(pair.to_bytes());
        let signer = Arc::new(SigningKey::from_keypair_bytes(&bytes).unwrap());
        let owner = SigningKey::from_bytes(&[22; 32]);
        let now = crate::content::now();
        let grant = SignedStorageGrant::issue(
            &signer,
            &owner.verifying_key(),
            GrantLimits {
                max_payload_bytes: 4 * volparossa_content::CHUNK_BYTES as u64,
                max_leases: 4,
                rights: StorageRights::ALL,
                max_retention_seconds: 1800,
            },
            Validity {
                created: now,
                expires: now + 3600,
            },
        )
        .unwrap()
        .verify(&signer.verifying_key(), now)
        .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let store = PrivateStorageStore::create(
            &temporary.path().join("private"),
            StorageLimits {
                capacity_bytes: 4 * volparossa_content::CHUNK_BYTES as u64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let storage = PrivateStorageProvider::new(store, signer.verifying_key()).unwrap();
        let mut registry = PublicationRegistry::new();
        registry.set_private_storage(Arc::new(StorageService::new(signer, storage)));
        Self {
            _temporary: temporary,
            owner,
            grant,
            registry,
            provider_peer: provider.public().to_peer_id(),
            provider_offer: offer(&provider, HOSTNAME),
            provider_tls: ContentTlsServer::new(&provider, HOSTNAME).unwrap(),
        }
    }
}

struct Outer {
    signed: SignedRouteFixture,
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
            signed: fixture,
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
    receipt_verified: AtomicBool,
    inner_closed: AtomicBool,
    provider_closed: AtomicBool,
    proxy_closed: AtomicBool,
    dropped: AtomicUsize,
    close: Mutex<CloseObservation>,
}

impl Proof {
    fn outer(&self, stream: &Tls13MptcpStream) {
        assert!(stream.negotiation_info().unwrap().is_negotiated());
        self.outer_handshakes.fetch_add(1, SeqCst);
    }
}

// Observe ownership without retaining a duplicate descriptor or changing I/O.
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

// Only the outer server shutdown is gated. No bytes, EOF or errors are fabricated.
// In the negative case the proxy is aborted before its real TLS close_notify is queued.
struct ShutdownGate<S> {
    stream: S,
    reached: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
    released: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for ShutdownGate<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, bytes)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShutdownGate<S> {
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
        let this = self.get_mut();
        if let Some(reached) = this.reached.take() {
            let _ = reached.send(());
        }
        if !this.released {
            match Pin::new(&mut this.release).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => this.released = true,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum CloseStage {
    #[default]
    Unstarted,
    Shutdown,
    Read,
    Eof,
    Trailing,
}

#[derive(Clone, Copy, Debug, Default)]
struct CloseObservation {
    stage: CloseStage,
    io: Option<io::ErrorKind>,
}

struct CloseProbe<'a, S> {
    stream: &'a mut S,
    observation: &'a Mutex<CloseObservation>,
}

impl<S: AsyncRead + Unpin> AsyncRead for CloseProbe<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.observation.lock().unwrap().stage = CloseStage::Read;
        let before = bytes.filled().len();
        let result = Pin::new(&mut *this.stream).poll_read(cx, bytes);
        match &result {
            Poll::Ready(Ok(())) => {
                this.observation.lock().unwrap().stage = if bytes.filled().len() == before {
                    CloseStage::Eof
                } else {
                    CloseStage::Trailing
                };
            }
            Poll::Ready(Err(error)) => this.observation.lock().unwrap().io = Some(error.kind()),
            Poll::Pending => {}
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CloseProbe<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().stream).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.observation.lock().unwrap().stage = CloseStage::Shutdown;
        let result = Pin::new(&mut *this.stream).poll_shutdown(cx);
        if let Poll::Ready(Err(error)) = &result {
            this.observation.lock().unwrap().io = Some(error.kind());
        }
        result
    }
}

#[derive(Debug)]
struct ClientResult {
    clean: bool,
    observation: CloseObservation,
}

enum Completed {
    Client(ClientResult),
    Provider,
    Proxy,
}

struct ClientControl {
    inner_done: oneshot::Sender<()>,
    finish: oneshot::Receiver<()>,
}

async fn client(
    fixture: Arc<Fixture>,
    outer: Arc<Outer>,
    stream: MptcpStream,
    proof: Arc<Proof>,
    control: ClientControl,
) -> Completed {
    let mut transport = outer
        .client
        .connect_preconnected(
            &outer.route,
            stream,
            ServerName::try_from(EXIT_NAME).unwrap(),
            crate::unix_millis(),
            SCENARIO_LIMIT,
        )
        .await
        .unwrap();
    proof.outer(&transport);
    write_open_tcp(&mut transport, &outer.opening, SCENARIO_LIMIT)
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
    let challenge = wire::begin(&mut inner, &fixture.grant).await.unwrap();
    let now = crate::content::now();
    let request = SignedStorageRequest::sign(
        &fixture.owner,
        &fixture.grant,
        &challenge,
        StorageTarget {
            archive_id: [42; 32],
            lease_id: None,
            ciphertext_bytes: 19,
            sha256: Sha256::digest(b"public-reserve-only").into(),
        },
        StorageOperation::Reserve {
            expires_at: now + 600,
        },
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
    assert_eq!(received.receipt.result().state, ReceiptState::Reserved);
    proof.receipt_verified.store(true, SeqCst);
    finish(&mut inner).await.unwrap();
    drop(inner);
    proof.inner_closed.store(true, SeqCst);
    control.inner_done.send(()).unwrap();
    control.finish.await.unwrap();
    assert!(proof.provider_closed.load(SeqCst));
    assert!(proof.proxy_closed.load(SeqCst));
    assert_eq!(proof.dropped.load(SeqCst), 3);
    let clean = finish(&mut CloseProbe {
        stream: &mut transport,
        observation: &proof.close,
    })
    .await
    .is_ok();
    let observation = *proof.close.lock().unwrap();
    Completed::Client(ClientResult { clean, observation })
}

async fn provider(fixture: Arc<Fixture>, stream: Owned<TcpStream>, proof: Arc<Proof>) -> Completed {
    let mut stream = fixture.provider_tls.accept(stream).await.unwrap();
    serve_publication(&mut stream, &fixture.registry, TransferLimits::default())
        .await
        .unwrap();
    // No receipt barrier: the real provider closes immediately, just as production does.
    finish(&mut stream).await.unwrap();
    drop(stream);
    proof.provider_closed.store(true, SeqCst);
    Completed::Provider
}

async fn proxy(
    outer: Arc<Outer>,
    stream: MptcpStream,
    mut forwarded: Owned<TcpStream>,
    proof: Arc<Proof>,
    reached: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
) -> Completed {
    let mut stream = outer.server.accept(stream, SCENARIO_LIMIT).await.unwrap();
    proof.outer(&stream);
    let authorized = read_authorized_open_tcp(
        &mut stream,
        &TcpAuthorizationScope::new(&outer.route, &outer.policy),
        crate::unix_millis(),
        TimePolicy::default(),
        &mut ReplayCache::new(16).unwrap(),
        SCENARIO_LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(authorized.hostname(), Some(HOSTNAME));
    assert_eq!(authorized.port(), PROVIDER_PORT);
    let mut stream = ShutdownGate {
        stream: Owned::new(stream, &proof),
        reached: Some(reached),
        release,
        released: false,
    };
    // Preserve the existing fixture's real inner ClientHello inspection before proxying.
    let mut record = [0_u8; 5];
    stream.read_exact(&mut record).await.unwrap();
    assert_eq!(record[0], 0x16);
    let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
    assert!(length <= 16 * 1024);
    let mut hello = vec![0; length + record.len()];
    hello[..5].copy_from_slice(&record);
    stream.read_exact(&mut hello[5..]).await.unwrap();
    volparossa_exit::inspect_tls_client_hello(&hello, HOSTNAME).unwrap();
    forwarded.write_all(&hello).await.unwrap();
    let statistics = proxy_bidirectional(
        stream,
        forwarded,
        StreamTransferLimits::new(64 * 1024, 1024 * 1024, 1024 * 1024, SCENARIO_LIMIT).unwrap(),
    )
    .await
    .unwrap();
    assert!(statistics.client_to_exit_bytes > 0);
    assert!(statistics.exit_to_client_bytes > 0);
    Completed::Proxy
}

struct Sequence {
    inner_done: oneshot::Receiver<()>,
    reached: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    finish: oneshot::Sender<()>,
    proxy: AbortHandle,
    abrupt: bool,
}

async fn sequence(
    tasks: &mut JoinSet<Completed>,
    controls: Sequence,
    proof: &Proof,
) -> Result<ClientResult, &'static str> {
    controls
        .inner_done
        .await
        .map_err(|_| "inner close failed")?;
    controls
        .reached
        .await
        .map_err(|_| "proxy shutdown not reached")?;
    match tasks.join_next().await {
        Some(Ok(Completed::Provider)) => {}
        _ => return Err("provider did not finish and drop first"),
    }
    if controls.abrupt {
        controls.proxy.abort();
        match tasks.join_next().await {
            Some(Err(error)) if error.is_cancelled() => {}
            _ => return Err("abrupt proxy was not joined"),
        }
    } else {
        controls.release.send(()).map_err(|()| "proxy gate lost")?;
        match tasks.join_next().await {
            Some(Ok(Completed::Proxy)) => {}
            _ => return Err("normal proxy did not finish"),
        }
    }
    proof.proxy_closed.store(true, SeqCst);
    controls.finish.send(()).map_err(|()| "client gate lost")?;
    match tasks.join_next().await {
        Some(Ok(Completed::Client(result))) => Ok(result),
        _ => Err("client outer close did not finish"),
    }
}

fn descriptor(stream: &impl AsRawFd) -> (PathBuf, PathBuf) {
    let path = PathBuf::from(format!("/proc/self/fd/{}", stream.as_raw_fd()));
    let identity = fs::read_link(&path).unwrap();
    (path, identity)
}

fn require_isolation() {
    let parent = env::var_os("VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS")
        .expect("run only through the explicit disposable namespace harness");
    let number = parent
        .to_str()
        .and_then(|value| value.strip_prefix("net:["))
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok());
    assert!(number.is_some_and(|value| value > 0));
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
        parent
    );
    assert_eq!(
        fs::read_to_string("/proc/sys/net/mptcp/enabled")
            .unwrap()
            .trim(),
        "1"
    );
}

struct Sockets {
    client: MptcpStream,
    exit: MptcpStream,
    forwarded: TcpStream,
    provider: TcpStream,
    descriptors: [(PathBuf, PathBuf); 4],
}

async fn sockets(deadline: Instant) -> Sockets {
    let listener = volparossa_mptcp::listen("127.0.0.1:0".parse().unwrap(), 2).unwrap();
    let provider_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, PROVIDER_PORT))
        .await
        .unwrap();
    let (client_stream, exit_stream, forwarded, provider_stream) = timeout_at(deadline, async {
        let (client, exit, forwarded, provider) = tokio::join!(
            volparossa_mptcp::connect(listener.local_addr().unwrap(), None, Duration::from_secs(2)),
            listener.accept(),
            TcpStream::connect(provider_listener.local_addr().unwrap()),
            provider_listener.accept(),
        );
        (
            client.unwrap(),
            exit.unwrap().0,
            forwarded.unwrap(),
            provider.unwrap().0,
        )
    })
    .await
    .expect("the same ten-second deadline includes socket establishment");
    client_stream.require_negotiated().unwrap();
    exit_stream.require_negotiated().unwrap();
    let descriptors = [
        descriptor(client_stream.as_tcp_stream()),
        descriptor(exit_stream.as_tcp_stream()),
        descriptor(&forwarded),
        descriptor(&provider_stream),
    ];
    drop(listener);
    drop(provider_listener);
    Sockets {
        client: client_stream,
        exit: exit_stream,
        forwarded,
        provider: provider_stream,
        descriptors,
    }
}

async fn run(abrupt: bool) -> ClientResult {
    require_isolation();
    let deadline = Instant::now() + SCENARIO_LIMIT;
    let fixture = Arc::new(Fixture::new());
    let outer = Arc::new(Outer::new());
    let proof = Arc::new(Proof::default());
    let sockets = sockets(deadline).await;
    let (inner_done, inner_received) = oneshot::channel();
    let (finish, finish_received) = oneshot::channel();
    let (reached, reached_received) = oneshot::channel();
    let (release, release_received) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(Box::pin(client(
        Arc::clone(&fixture),
        Arc::clone(&outer),
        sockets.client,
        Arc::clone(&proof),
        ClientControl {
            inner_done,
            finish: finish_received,
        },
    )));
    tasks.spawn(Box::pin(provider(
        fixture,
        Owned::new(sockets.provider, &proof),
        Arc::clone(&proof),
    )));
    let proxy = tasks.spawn(Box::pin(proxy(
        outer,
        sockets.exit,
        Owned::new(sockets.forwarded, &proof),
        Arc::clone(&proof),
        reached,
        release_received,
    )));
    let result = timeout_at(
        deadline,
        sequence(
            &mut tasks,
            Sequence {
                inner_done: inner_received,
                reached: reached_received,
                release,
                finish,
                proxy,
                abrupt,
            },
            &proof,
        ),
    )
    .await;
    let observation = *proof.close.lock().unwrap();
    // Cleanup is unconditional, including failed assertions inside any spawned task.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    assert!(tasks.is_empty());
    for (path, identity) in sockets.descriptors {
        assert_ne!(
            fs::read_link(path).ok(),
            Some(identity),
            "owned socket survived join"
        );
    }
    assert!(
        result.is_ok(),
        "same ten-second deadline; close={observation:?}"
    );
    let result = result.unwrap().unwrap_or_else(|stage| {
        panic!("failed before outer close: {stage}; close={observation:?}")
    });
    assert_eq!(proof.outer_handshakes.load(SeqCst), 2);
    assert!(proof.receipt_verified.load(SeqCst));
    assert!(proof.inner_closed.load(SeqCst));
    assert!(proof.provider_closed.load(SeqCst));
    assert!(proof.proxy_closed.load(SeqCst));
    assert_eq!(proof.dropped.load(SeqCst), 4);
    assert_eq!(Arc::strong_count(&proof), 1);
    result
}

#[tokio::test]
#[ignore = "requires explicit hosted disposable net/PID namespaces and genuine Linux MPTCP"]
async fn signed_reserve_survives_tcp_provider_and_proxy_drop_before_outer_finish() {
    let result = Box::pin(run(false)).await;
    assert!(result.clean, "outer close after peer drop: {result:?}");
    assert_eq!(result.observation.stage, CloseStage::Eof);
    assert_eq!(result.observation.io, None);
}

#[tokio::test]
#[ignore = "requires explicit hosted disposable net/PID namespaces and genuine Linux MPTCP"]
async fn signed_reserve_rejects_abrupt_outer_drop_after_inner_finish() {
    let result = Box::pin(run(true)).await;
    assert!(!result.clean, "abrupt outer close must not be accepted");
    assert_eq!(result.observation.stage, CloseStage::Read);
    assert!(
        matches!(
            result.observation.io,
            Some(io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)
        ),
        "must reject actual read EOF/reset, not pass through a test timeout: {result:?}"
    );
}
