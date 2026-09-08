//! Unprivileged bounded-streaming tests for the TCP proxy.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use volparossa_tcp_proxy::{StreamTransferLimits, TcpProxyError, proxy_bidirectional};

#[tokio::test]
async fn tls_backpressure_flushes_last_request_without_another_write_or_eof() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified =
        rcgen::generate_simple_self_signed(vec!["exit.volparossa.invalid".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key = rustls_pki_types::PrivateKeyDer::from(
        rustls_pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let client_configuration = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_configuration = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_configuration));
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_configuration));
    // The handshake fits, but the last 8 KiB application write does not. Actual rustls
    // accepts plaintext before every encrypted byte can enter this bounded transport.
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server_name = rustls_pki_types::ServerName::try_from("exit.volparossa.invalid").unwrap();
    let (client_tls, server_tls) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            connector.connect(server_name, client_io),
            acceptor.accept(server_io)
        )
    })
    .await
    .expect("bounded real TLS handshake");
    let (mut application, proxy_client) = tokio::io::duplex(8192);
    let limits = StreamTransferLimits::new(8192, 8192, 8192, Duration::from_secs(2)).unwrap();
    let proxy = tokio::spawn(proxy_bidirectional(
        proxy_client,
        client_tls.unwrap(),
        limits,
    ));
    let mut destination = server_tls.unwrap();
    let request = [0x5a; 8192];
    application.write_all(&request).await.unwrap();
    let mut received = [0_u8; 8192];
    let delivered = tokio::time::timeout(
        Duration::from_millis(250),
        destination.read_exact(&mut received),
    )
    .await;
    if delivered.is_err() {
        proxy.abort();
        let _ = proxy.await;
        panic!("TLS request remained buffered until another write/EOF instead of reaching peer");
    }
    delivered.unwrap().unwrap();
    assert_eq!(received, request);
    destination.write_all(b"reply").await.unwrap();
    destination.flush().await.unwrap();
    let mut reply = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(1), application.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"reply");
    application.shutdown().await.unwrap();
    destination.shutdown().await.unwrap();
    let statistics = tokio::time::timeout(Duration::from_secs(1), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(statistics.client_to_exit_bytes, 8192);
    assert_eq!(statistics.exit_to_client_bytes, 5);
}

#[tokio::test]
async fn forwards_each_direction_without_waiting_for_eof() {
    let (mut application, proxy_client) = tokio::io::duplex(128);
    let (proxy_exit, mut exit) = tokio::io::duplex(128);
    let limits = StreamTransferLimits::new(8, 128, 128, Duration::from_secs(2)).unwrap();
    let task = tokio::spawn(proxy_bidirectional(proxy_client, proxy_exit, limits));

    application.write_all(b"request").await.unwrap();
    let mut request = [0_u8; 7];
    exit.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"request");

    exit.write_all(b"reply").await.unwrap();
    let mut reply = [0_u8; 5];
    application.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");

    application.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
    let statistics = task.await.unwrap().unwrap();
    assert_eq!(statistics.client_to_exit_bytes, 7);
    assert_eq!(statistics.exit_to_client_bytes, 5);
}

#[tokio::test]
async fn directional_byte_limit_fails_closed() {
    let (mut application, proxy_client) = tokio::io::duplex(64);
    let (proxy_exit, _exit) = tokio::io::duplex(64);
    let limits = StreamTransferLimits::new(8, 3, 64, Duration::from_secs(2)).unwrap();
    let task = tokio::spawn(proxy_bidirectional(proxy_client, proxy_exit, limits));

    application.write_all(b"four").await.unwrap();
    let error = task.await.unwrap().unwrap_err();
    assert!(matches!(error, TcpProxyError::ByteLimit));
}

#[test]
fn transfer_limits_are_bounded() {
    assert!(StreamTransferLimits::new(0, 1, 1, Duration::from_secs(1)).is_err());
    assert!(StreamTransferLimits::new(65_537, 1, 1, Duration::from_secs(1)).is_err());
    assert!(StreamTransferLimits::new(1, 0, 1, Duration::from_secs(1)).is_err());
    assert!(StreamTransferLimits::new(1, 1, 1, Duration::ZERO).is_err());
}
