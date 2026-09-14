//! A real isolated MPTCP/TLS EOF regression, not a complete relay/datapath proof.

use std::{
    env, fs,
    net::{Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
    process::Command,
    time::Duration,
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

fn established_meta_sockets(port: u16) -> Vec<String> {
    let output = Command::new("ss")
        .args([
            "-HOnMie",
            &format!("( sport = :{port} or dport = :{port} )"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let mut identities = text
        .lines()
        .map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            assert_eq!(
                fields[0], "ESTAB",
                "TLS EOF must not send premature MPTCP DATA_FIN: {line}"
            );
            let cookie = fields
                .iter()
                .find(|field| field.starts_with("sk:"))
                .unwrap();
            let token = fields
                .iter()
                .find(|field| field.starts_with("token:"))
                .unwrap();
            format!("{} {} {cookie} {token}", fields[3], fields[4])
        })
        .collect::<Vec<_>>();
    assert_eq!(
        identities.len(),
        2,
        "exactly the two original real MPTCP sockets remain"
    );
    identities.sort();
    identities
}

fn descriptor(stream: &Tls13MptcpStream) -> i32 {
    match stream {
        Tls13MptcpStream::Client(tls) => tls.get_ref().0.as_fd().as_raw_fd(),
        Tls13MptcpStream::Server(tls) => tls.get_ref().0.as_fd().as_raw_fd(),
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
    let address = listener.local_addr().unwrap();
    let (mut client, mut server) = protected_pair(&listener, &client_config, &server_config).await;
    assert!(client.negotiation_info().unwrap().is_negotiated());
    assert!(server.negotiation_info().unwrap().is_negotiated());
    let original = established_meta_sockets(address.port());

    client
        .write_all(b"download after authenticated EOF")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut request = Vec::new();
    server.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"download after authenticated EOF");
    assert_eq!(established_meta_sockets(address.port()), original);

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
    assert_eq!(established_meta_sockets(address.port()), original);
    let client_fd = descriptor(&client);
    let server_fd = descriptor(&server);
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
