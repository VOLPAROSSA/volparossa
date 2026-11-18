//! Repeated real TLS/MPTCP exchanges through production SNI, DNS and TCP egress.
//! The signed route is a fixture: no deployed relay, route activation or multipath claim.

use super::*;
use std::{collections::BTreeSet, net::Ipv4Addr};
use volparossa_core::Bandwidth;
use volparossa_exit::{ExitService, ExitServiceConfig, TcpEgressLimits};
use volparossa_udp::ExitResolver;

const EXCHANGES: usize = 3;
// Assigned only to lo in the explicit disposable harness before privileges are dropped.
// There is no external interface/default route or relaxation of permitted_egress.
const PROVIDER_ADDRESS: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

#[derive(Default)]
struct Evidence {
    clients: AtomicUsize,
    providers: AtomicUsize,
    exits: AtomicUsize,
    dns_a: AtomicUsize,
    dns_aaaa: AtomicUsize,
    partial_reads: AtomicUsize,
    leases: Mutex<BTreeSet<Vec<u8>>>,
}

// No buffering, fake readiness or sleeps: expose at most seven original plaintext
// bytes per read to the production ClientHello inspector, then bound proxy writes.
struct Fragmented<S> {
    inner: S,
    evidence: Arc<Evidence>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Fragmented<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut bytes = [0_u8; 7];
        let capacity = output.remaining().min(bytes.len());
        let mut bounded = ReadBuf::new(&mut bytes[..capacity]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut bounded) {
            Poll::Ready(Ok(())) => {
                if !bounded.filled().is_empty() {
                    this.evidence.partial_reads.fetch_add(1, SeqCst);
                }
                output.put_slice(bounded.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmented<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, &bytes[..bytes.len().min(31)])
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn socket_identities() -> BTreeSet<PathBuf> {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| fs::read_link(entry.unwrap().path()).ok())
        .filter(|target| {
            target
                .as_os_str()
                .as_encoded_bytes()
                .starts_with(b"socket:[")
        })
        .collect()
}

// Minimal synthetic DNS wire responder, not an Unbound/DNSSEC implementation.
// It accepts only this fixture's exact A/AAAA question and echoes its transaction ID.
fn dns_answer(query: &[u8], evidence: &Evidence) -> Vec<u8> {
    assert!((12..=1024).contains(&query.len()));
    assert_eq!(&query[4..10], &[0, 1, 0, 0, 0, 0]);
    assert_eq!(query[2] & 0xf8, 0);
    let mut offset = 12;
    for label in HOSTNAME.split('.') {
        assert_eq!(usize::from(query[offset]), label.len());
        offset += 1;
        assert_eq!(&query[offset..offset + label.len()], label.as_bytes());
        offset += label.len();
    }
    assert_eq!(query[offset], 0);
    offset += 1;
    let kind = u16::from_be_bytes(query[offset..offset + 2].try_into().unwrap());
    assert!(matches!(kind, 1 | 28));
    assert_eq!(&query[offset + 2..offset + 4], &[0, 1]);
    offset += 4;
    let mut answer = query[..2].to_vec();
    answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, u8::from(kind == 1), 0, 0, 0, 0]);
    answer.extend_from_slice(&query[12..offset]);
    if kind == 1 {
        evidence.dns_a.fetch_add(1, SeqCst);
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        answer.extend_from_slice(&PROVIDER_ADDRESS.octets());
    } else {
        evidence.dns_aaaa.fetch_add(1, SeqCst);
    }
    answer
}

async fn dns_server(listener: TcpListener, evidence: Arc<Evidence>) {
    for _ in 0..2 * EXCHANGES {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = usize::from(stream.read_u16().await.unwrap());
        assert!((12..=1024).contains(&length));
        let mut query = vec![0; length];
        stream.read_exact(&mut query).await.unwrap();
        let answer = dns_answer(&query, &evidence);
        stream
            .write_u16(u16::try_from(answer.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&answer).await.unwrap();
        stream.shutdown().await.unwrap();
    }
}

async fn reserve(
    fixture: &Fixture,
    inner: &mut (impl AsyncRead + AsyncWrite + Unpin),
    index: u8,
) -> Vec<u8> {
    let challenge = wire::begin(inner, &fixture.grant).await.unwrap();
    let now = crate::content::now();
    let request = SignedStorageRequest::sign(
        &fixture.owner,
        &fixture.grant,
        &challenge,
        StorageTarget {
            archive_id: [index + 1; 32],
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
    let (mut owner, mut agent) = duplex(128);
    let (received, bridged) = tokio::join!(
        wire::finish(&mut owner, &fixture.grant, &challenge, &request, &[]),
        wire::bridge(&mut agent, inner, &fixture.grant, &challenge),
    );
    let received = received.unwrap();
    assert_eq!(received.receipt.encode(), bridged.unwrap().receipt.encode());
    assert_eq!(received.receipt.result().state, ReceiptState::Reserved);
    received.receipt.result().lease_id.as_bytes().to_vec()
}

async fn clients(
    endpoint: std::net::SocketAddr,
    fixture: Arc<Fixture>,
    outer: Arc<Outer>,
    evidence: Arc<Evidence>,
) {
    for index in 0..EXCHANGES {
        let socket = volparossa_mptcp::connect(endpoint, None, Duration::from_secs(2))
            .await
            .unwrap();
        socket.require_negotiated().unwrap();
        let mut transport = outer
            .client
            .connect_preconnected(
                &outer.route,
                socket,
                ServerName::try_from(EXIT_NAME).unwrap(),
                crate::unix_millis(),
                SCENARIO_LIMIT,
            )
            .await
            .unwrap();
        let opening = outer
            .signed
            .sign_open_tcp(
                outer.policy.policy_hash(),
                HOSTNAME,
                PROVIDER_PORT,
                crate::unix_millis(),
            )
            .unwrap();
        write_open_tcp(&mut transport, &opening, SCENARIO_LIMIT)
            .await
            .unwrap();
        let mut inner = connect(
            &mut transport,
            fixture.provider_peer,
            &fixture.provider_offer,
        )
        .await
        .unwrap();
        let lease = reserve(&fixture, &mut inner, u8::try_from(index).unwrap()).await;
        assert!(evidence.leases.lock().unwrap().insert(lease));
        finish(&mut inner).await.unwrap();
        drop(inner);
        finish(&mut transport).await.unwrap();
        drop(transport);
        evidence.clients.fetch_add(1, SeqCst);
    }
}

async fn providers(listener: TcpListener, fixture: Arc<Fixture>, evidence: Arc<Evidence>) {
    for _ in 0..EXCHANGES {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = fixture.provider_tls.accept(socket).await.unwrap();
        serve_publication(&mut stream, &fixture.registry, TransferLimits::default())
            .await
            .unwrap();
        finish(&mut stream).await.unwrap();
        drop(stream);
        evidence.providers.fetch_add(1, SeqCst);
    }
}

async fn exits(
    listener: volparossa_mptcp::MptcpListener,
    service: ExitService,
    outer: Arc<Outer>,
    evidence: Arc<Evidence>,
) {
    let mut replay = ReplayCache::new(16).unwrap();
    // DNS/connect/ClientHello deadlines match production, as does its 60s stream-idle
    // limit. Only directional buffers and byte bounds are reduced for this fixture.
    let limits = TcpEgressLimits::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
        StreamTransferLimits::new(128, 1024 * 1024, 1024 * 1024, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    for index in 0..EXCHANGES {
        let (socket, _) = listener.accept().await.unwrap();
        socket.require_negotiated().unwrap();
        let mut stream = outer.server.accept(socket, SCENARIO_LIMIT).await.unwrap();
        let authorized = read_authorized_open_tcp(
            &mut stream,
            &TcpAuthorizationScope::new(&outer.route, &outer.policy),
            crate::unix_millis(),
            TimePolicy::default(),
            &mut replay,
            SCENARIO_LIMIT,
        )
        .await
        .unwrap();
        assert_eq!(authorized.hostname(), Some(HOSTNAME));
        assert_eq!(authorized.port(), PROVIDER_PORT);
        assert_eq!(evidence.dns_a.load(SeqCst), index);
        assert_eq!(evidence.dns_aaaa.load(SeqCst), index);
        let reads_before = evidence.partial_reads.load(SeqCst);
        let statistics = service
            .run_tcp_egress(
                &authorized,
                Fragmented {
                    inner: stream,
                    evidence: Arc::clone(&evidence),
                },
                crate::unix_millis(),
                limits,
            )
            .await
            .unwrap();
        assert!(statistics.client_to_exit_bytes > 0);
        assert!(statistics.exit_to_client_bytes > 0);
        assert_eq!(evidence.dns_a.load(SeqCst), index + 1);
        assert_eq!(evidence.dns_aaaa.load(SeqCst), index + 1);
        assert!(evidence.partial_reads.load(SeqCst) > reads_before + 2);
        evidence.exits.fetch_add(1, SeqCst);
    }
    let counts = service.dns_resolver().counts();
    assert_eq!(counts.trusted_fallback, u64::try_from(EXCHANGES).unwrap());
    assert_eq!(
        counts.local_validated + counts.peer_validated + counts.upstream_validated,
        0
    );
}

#[tokio::test]
#[ignore = "requires exact hosted disposable content-egress namespace and genuine Linux MPTCP"]
async fn three_signed_reserves_use_reusable_production_egress_and_fragmented_hello() {
    require_isolation();
    let before = socket_identities();
    let fixture = Arc::new(Fixture::new());
    let outer = Arc::new(Outer::new());
    let evidence = Arc::new(Evidence::default());
    let listener = volparossa_mptcp::listen("127.0.0.1:0".parse().unwrap(), 4).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let provider = TcpListener::bind((PROVIDER_ADDRESS, PROVIDER_PORT))
        .await
        .unwrap();
    let dns = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let resolver = ExitResolver::default()
        .with_cache_enabled(false)
        .with_unbound_fallback(dns.local_addr().unwrap())
        .unwrap();
    let mut service = ExitService::new(
        ExitServiceConfig::enabled(
            outer.signed.exit_node_id(),
            Bandwidth::new(100, 100).unwrap(),
            4,
            300,
            30,
            128,
        ),
        outer.policy.clone(),
        None,
    )
    .unwrap();
    service.set_dns_resolver(Arc::new(resolver));
    let mut tasks = JoinSet::new();
    tasks.spawn(Box::pin(dns_server(dns, Arc::clone(&evidence))));
    tasks.spawn(Box::pin(providers(
        provider,
        Arc::clone(&fixture),
        Arc::clone(&evidence),
    )));
    tasks.spawn(Box::pin(exits(
        listener,
        service,
        Arc::clone(&outer),
        Arc::clone(&evidence),
    )));
    tasks.spawn(Box::pin(clients(
        endpoint,
        fixture,
        outer,
        Arc::clone(&evidence),
    )));
    let result = timeout(SCENARIO_LIMIT, async {
        while let Some(completed) = tasks.join_next().await {
            completed?;
        }
        Ok::<_, tokio::task::JoinError>(())
    })
    .await;
    // Task assertions/timeouts cannot bypass joining, including the synthetic DNS server.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    assert!(tasks.is_empty());
    assert_eq!(
        socket_identities(),
        before,
        "owned socket survived task cleanup"
    );
    assert!(
        matches!(result, Ok(Ok(()))),
        "production egress exchange failed: {result:?}"
    );
    for count in [
        &evidence.clients,
        &evidence.providers,
        &evidence.exits,
        &evidence.dns_a,
        &evidence.dns_aaaa,
    ] {
        assert_eq!(count.load(SeqCst), EXCHANGES);
    }
    assert_eq!(evidence.leases.lock().unwrap().len(), EXCHANGES);
    assert!(evidence.partial_reads.load(SeqCst) > EXCHANGES);
    assert_eq!(Arc::strong_count(&evidence), 1);
}
