//! A real isolated MPTCP/TLS EOF regression, not a complete relay/datapath proof.

use std::{
    env, fs,
    net::{Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
    process::Command,
    time::{Duration, Instant},
};

use nix::sys::{
    epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags},
    socket::{Shutdown, SockaddrIn6, getpeername, getsockname, shutdown},
    stat::fstat,
};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::{Tls13MptcpClient, Tls13MptcpServer, Tls13MptcpStream, TlsMptcpIo};

#[test]
fn tls_close_notify_preserves_kernel_mptcp_for_remaining_download() {
    const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";
    const TEST: &str =
        "tls::half_close::tls_close_notify_preserves_kernel_mptcp_for_remaining_download";
    if let Some(parent) = env::var_os(MARKER) {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
            parent
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(Duration::from_secs(10), scenario()).await.unwrap();
            });
        return;
    }
    let output = Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/run-isolated-test.sh"
    ))
    .arg(env::current_exe().unwrap())
    .args([TEST, MARKER, "loopback"])
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "isolated TLS/MPTCP EOF failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[derive(Debug, Eq, PartialEq)]
struct SocketIdentity {
    descriptor: i32,
    device: u64,
    inode: u64,
    local: String,
    remote: String,
}

fn transport(stream: &Tls13MptcpStream) -> &TlsMptcpIo {
    match stream {
        Tls13MptcpStream::Client(tls) => tls.get_ref().0,
        Tls13MptcpStream::Server(tls) => tls.get_ref().0,
    }
}

fn identity(stream: &Tls13MptcpStream) -> SocketIdentity {
    assert!(stream.negotiation_info().unwrap().is_negotiated());
    let fd = transport(stream);
    let stat = fstat(fd).unwrap();
    assert_ne!(stat.st_ino, 0);
    SocketIdentity {
        descriptor: fd.as_fd().as_raw_fd(),
        device: stat.st_dev,
        inode: stat.st_ino,
        local: getsockname::<SockaddrIn6>(fd.as_fd().as_raw_fd())
            .unwrap()
            .to_string(),
        remote: getpeername::<SockaddrIn6>(fd.as_fd().as_raw_fd())
            .unwrap()
            .to_string(),
    }
}

fn eof_observer(client: &Tls13MptcpStream, server: &Tls13MptcpStream) -> Epoll {
    let observer = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    for (id, stream) in [(0, client), (1, server)] {
        observer
            .add(
                transport(stream),
                EpollEvent::new(
                    EpollFlags::EPOLLRDHUP | EpollFlags::EPOLLHUP | EpollFlags::EPOLLERR,
                    id,
                ),
            )
            .unwrap();
    }
    observer
}

fn sockets_without_transport_eof(
    client: &Tls13MptcpStream,
    server: &Tls13MptcpStream,
) -> [SocketIdentity; 2] {
    // MPTCP's SOL_TCP/TCP_INFO exposes a subflow state, not the meta state. Likewise
    // a capless namespace-wide ss dump may be empty even for our live sockets.
    // Observe DATA_FIN/read shutdown directly on these two still-owned meta FDs.
    let identities = [identity(client), identity(server)];
    assert_ne!(identities[0].inode, identities[1].inode);
    assert_eq!(identities[0].local, identities[1].remote);
    assert_eq!(identities[0].remote, identities[1].local);
    let mut events = [EpollEvent::empty(); 2];
    assert_eq!(
        eof_observer(client, server)
            .wait(&mut events, 20_u16)
            .unwrap(),
        0,
        "TLS close_notify must not prematurely half-close either MPTCP transport"
    );
    identities
}

fn assert_real_data_fin_is_observed(client: &Tls13MptcpStream, server: &Tls13MptcpStream) {
    let observer = eof_observer(client, server);
    for stream in [client, server] {
        shutdown(transport(stream).as_fd().as_raw_fd(), Shutdown::Write).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut seen = [false; 2];
    while seen != [true; 2] {
        assert!(
            Instant::now() < deadline,
            "real DATA_FIN was not observed at both peers"
        );
        let mut events = [EpollEvent::empty(); 2];
        let count = observer.wait(&mut events, 20_u16).unwrap();
        for event in &events[..count] {
            assert!(event.events().contains(EpollFlags::EPOLLRDHUP));
            assert!(!event.events().contains(EpollFlags::EPOLLERR));
            seen[usize::try_from(event.data()).unwrap()] = true;
        }
    }
}

async fn protected_pair(
    listener: &volparossa_mptcp::MptcpListener,
    client_config: &Tls13MptcpClient,
    server_config: &Tls13MptcpServer,
) -> (Tls13MptcpStream, Tls13MptcpStream) {
    let (client, server) = tokio::join!(
        volparossa_mptcp::connect(listener.local_addr().unwrap(), None, Duration::from_secs(2)),
        listener.accept(),
    );
    let client = client.unwrap();
    let (server, _) = server.unwrap();
    client.require_negotiated().unwrap();
    server.require_negotiated().unwrap();
    let (client, server) = tokio::join!(
        client_config.connector.connect(
            ServerName::try_from("exit.volparossa.invalid")
                .unwrap()
                .to_owned(),
            TlsMptcpIo::new(client.into_inner()),
        ),
        server_config.accept(server, Duration::from_secs(2)),
    );
    (Tls13MptcpStream::Client(client.unwrap()), server.unwrap())
}

async fn scenario() {
    let certified = generate_simple_self_signed(vec!["exit.volparossa.invalid".into()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let client_config = Tls13MptcpClient::new(roots).unwrap();
    let server_config = Tls13MptcpServer::new(vec![certificate], private_key).unwrap();
    let listener = volparossa_mptcp::listen(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), 2).unwrap();
    let (mut client, mut server) = protected_pair(&listener, &client_config, &server_config).await;
    assert!(client.negotiation_info().unwrap().is_negotiated());
    assert!(server.negotiation_info().unwrap().is_negotiated());
    let original = sockets_without_transport_eof(&client, &server);

    client
        .write_all(b"download after authenticated EOF")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut request = Vec::new();
    server.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"download after authenticated EOF");
    assert_eq!(sockets_without_transport_eof(&client, &server), original);

    let payload = vec![0x5a; 1024 * 1024];
    let mut response = Vec::new();
    let (sent, received) = tokio::join!(
        async {
            server.write_all(&payload).await?;
            server.shutdown().await
        },
        client.read_to_end(&mut response),
    );
    sent.unwrap();
    assert_eq!(received.unwrap(), payload.len());
    assert_eq!(response, payload);
    assert_eq!(sockets_without_transport_eof(&client, &server), original);
    // Negative control: these exact FDs must detect actual kernel DATA_FIN. This
    // prevents an unsupported or disconnected observer from making the test green.
    assert_real_data_fin_is_observed(&client, &server);
    let client_fd = original[0].descriptor;
    let server_fd = original[1].descriptor;
    drop(client);
    drop(server);
    assert!(fs::read_link(format!("/proc/self/fd/{client_fd}")).is_err());
    assert!(fs::read_link(format!("/proc/self/fd/{server_fd}")).is_err());

    // The adapter must not turn an abrupt TCP close into an authenticated TLS EOF.
    let (mut client, mut server) = protected_pair(&listener, &client_config, &server_config).await;
    server.write_all(b"truncated response").await.unwrap();
    server.flush().await.unwrap();
    drop(server);
    let mut truncated = Vec::new();
    let error = client.read_to_end(&mut truncated).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}
