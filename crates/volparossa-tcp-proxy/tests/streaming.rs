//! Unprivileged bounded-streaming tests for the TCP proxy.

use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use volparossa_tcp_proxy::{StreamTransferLimits, TcpProxyError, proxy_bidirectional};

fn tls_configuration() -> (tokio_rustls::TlsConnector, tokio_rustls::TlsAcceptor) {
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
    (
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_configuration)),
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_configuration)),
    )
}

#[tokio::test]
async fn tls_backpressure_flushes_last_request_without_another_write_or_eof() {
    let (connector, acceptor) = tls_configuration();
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
async fn simultaneous_backpressure_does_not_block_the_opposite_direction() {
    let (mut application, proxy_client) = tokio::io::duplex(256);
    let (proxy_exit, mut destination) = tokio::io::duplex(64);
    let limits = StreamTransferLimits::new(256, 128, 128, Duration::from_secs(1)).unwrap();
    application.write_all(&[0x31; 128]).await.unwrap();
    let mut proxy = Box::pin(proxy_bidirectional(proxy_client, proxy_exit, limits));
    // Only the request is readable. This poll fills the 64-byte destination
    // buffer and leaves its remaining write pending, before any response exists.
    let readiness = poll_fn(|cx| Poll::Ready(proxy.as_mut().poll(cx))).await;
    assert!(readiness.is_pending());
    let (statistics, (), ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            proxy,
            async {
                let mut response = [0_u8; 128];
                application.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [0x72; 128]);
                application.shutdown().await.unwrap();
            },
            async {
                // Write before reading: the proxy must drain the opposite
                // direction to allow this bounded writer to start reading.
                destination.write_all(&[0x72; 128]).await.unwrap();
                let mut request = [0_u8; 128];
                destination.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [0x31; 128]);
                destination.shutdown().await.unwrap();
            },
        )
    })
    .await
    .expect("both directions must progress without a sleep, retry or larger buffer");
    let statistics = statistics.unwrap();
    assert_eq!(statistics.client_to_exit_bytes, 128);
    assert_eq!(statistics.exit_to_client_bytes, 128);
}

#[tokio::test]
async fn nested_tls_flushes_both_requests_and_reverse_traffic_under_backpressure() {
    let (connector, acceptor) = tls_configuration();
    let server_name = rustls_pki_types::ServerName::try_from("exit.volparossa.invalid").unwrap();
    let (outer_client_io, outer_exit_io) = tokio::io::duplex(256);
    let (outer_client, outer_exit) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            connector.connect(server_name.clone(), outer_client_io),
            acceptor.accept(outer_exit_io)
        )
    })
    .await
    .unwrap();
    let (proxy_exit, provider_io) = tokio::io::duplex(128);
    let limits =
        StreamTransferLimits::new(512, 64 * 1024, 64 * 1024, Duration::from_secs(1)).unwrap();
    let proxy = tokio::spawn(proxy_bidirectional(outer_exit.unwrap(), proxy_exit, limits));
    let exchanged = tokio::time::timeout(Duration::from_secs(3), async {
        // Both handshake futures must return before either application starts.
        // These are real nested TLS streams, not a Storage protocol emulator or
        // a claim about authenticated provider grants or genuine MPTCP.
        let mut outer_client = outer_client.unwrap();
        let (client, provider) = tokio::join!(
            connector.connect(server_name, &mut outer_client),
            acceptor.accept(provider_io)
        );
        let mut client = client.unwrap();
        let mut provider = provider.unwrap();
        tokio::join!(
            async {
                for byte in [0x31, 0x32] {
                    client.write_all(&[byte; 512]).await.unwrap();
                    client.flush().await.unwrap();
                }
                // No additional write or EOF may be needed to deliver either
                // flushed request or the independently buffered response.
                let mut greeting = [0_u8; 128];
                client.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [0x61; 128]);
                assert_eq!(client.read_u8().await.unwrap(), 0x79);
                client.shutdown().await.unwrap();
                assert_eq!(client.read(&mut [0_u8; 1]).await.unwrap(), 0);
            },
            async {
                provider.write_all(&[0x61; 128]).await.unwrap();
                provider.flush().await.unwrap();
                for byte in [0x31, 0x32] {
                    let mut request = [0_u8; 512];
                    provider.read_exact(&mut request).await.unwrap();
                    assert_eq!(request, [byte; 512]);
                }
                provider.write_all(&[0x79]).await.unwrap();
                provider.flush().await.unwrap();
                provider.shutdown().await.unwrap();
                assert_eq!(provider.read(&mut [0_u8; 1]).await.unwrap(), 0);
            },
        );
        drop(client);
        // Inner TLS shutdown has already sent the outer directional close.
        // Consume the outer peer's own close_notify before dropping its stream.
        outer_client.shutdown().await.unwrap();
        assert_eq!(outer_client.read(&mut [0_u8; 1]).await.unwrap(), 0);
    })
    .await;
    if exchanged.is_err() {
        proxy.abort();
        let _ = proxy.await;
        panic!("nested TLS stopped progressing under bounded bidirectional backpressure");
    }
    let statistics = tokio::time::timeout(Duration::from_secs(2), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(statistics.client_to_exit_bytes >= 1024);
    assert!(statistics.exit_to_client_bytes >= 129);
}

#[tokio::test]
async fn request_half_close_keeps_the_response_direction_usable() {
    let (mut application, proxy_client) = tokio::io::duplex(64);
    let (proxy_exit, mut destination) = tokio::io::duplex(64);
    let limits = StreamTransferLimits::new(8, 7, 5, Duration::from_secs(1)).unwrap();
    let task = tokio::spawn(proxy_bidirectional(proxy_client, proxy_exit, limits));
    application.write_all(b"request").await.unwrap();
    application.shutdown().await.unwrap();
    let mut request = Vec::new();
    destination.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    destination.write_all(b"reply").await.unwrap();
    destination.shutdown().await.unwrap();
    let mut response = Vec::new();
    application.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"reply");
    let statistics = task.await.unwrap().unwrap();
    assert_eq!(statistics.client_to_exit_bytes, 7);
    assert_eq!(statistics.exit_to_client_bytes, 5);
}

#[tokio::test]
async fn cancelling_a_backpressured_proxy_drops_both_owned_directions() {
    let (mut application, proxy_client) = tokio::io::duplex(256);
    let (proxy_exit, mut destination) = tokio::io::duplex(64);
    let limits = StreamTransferLimits::new(256, 128, 128, Duration::from_secs(1)).unwrap();
    application.write_all(&[0x31; 128]).await.unwrap();
    let mut proxy = Box::pin(proxy_bidirectional(proxy_client, proxy_exit, limits));
    let readiness = poll_fn(|cx| Poll::Ready(proxy.as_mut().poll(cx))).await;
    assert!(readiness.is_pending());
    drop(proxy);
    let mut delivered = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        destination.read_to_end(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered, [0x31; 64]);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), application.read(&mut [0_u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn read_idle_and_backpressured_writes_remain_bounded() {
    for blocked_write in [false, true] {
        let (mut application, proxy_client) = tokio::io::duplex(256);
        let (proxy_exit, _destination) = tokio::io::duplex(64);
        if blocked_write {
            application.write_all(&[0x31; 128]).await.unwrap();
        }
        let limits = StreamTransferLimits::new(256, 128, 128, Duration::from_millis(50)).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            proxy_bidirectional(proxy_client, proxy_exit, limits),
        )
        .await
        .expect("neither a stalled read nor a stalled write may outlive its existing bound");
        assert!(matches!(result, Err(TcpProxyError::IdleTimeout)));
    }
}

#[tokio::test]
async fn reverse_traffic_resets_shared_read_idle_while_forward_is_silent() {
    let (mut application, proxy_client) = tokio::io::duplex(64);
    let (proxy_exit, mut destination) = tokio::io::duplex(64);
    let idle_timeout = Duration::from_millis(500);
    let limits = StreamTransferLimits::new(8, 1, 11, idle_timeout).unwrap();
    let started = tokio::time::Instant::now();
    // This isolated crate has no Tokio test-util feature. The explicitly bounded
    // wall-clock trial leaves five heartbeat periods before the idle deadline.
    let (statistics, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            proxy_bidirectional(proxy_client, proxy_exit, limits),
            async {
                let mut heartbeat = tokio::time::interval(Duration::from_millis(100));
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                for byte in 0_u8..11 {
                    heartbeat.tick().await;
                    destination.write_all(&[byte]).await.unwrap();
                    assert_eq!(application.read_u8().await.unwrap(), byte);
                }
                assert!(started.elapsed() > idle_timeout);
                application.shutdown().await.unwrap();
                destination.shutdown().await.unwrap();
            },
        )
    })
    .await
    .expect("a silent forward reader must not expire an active whole flow");
    let statistics = statistics.unwrap();
    assert_eq!(statistics.client_to_exit_bytes, 0);
    assert_eq!(statistics.exit_to_client_bytes, 11);
}

#[tokio::test]
async fn reverse_traffic_does_not_extend_a_blocked_forward_write() {
    let (mut application, proxy_client) = tokio::io::duplex(256);
    let (proxy_exit, mut destination) = tokio::io::duplex(64);
    let limits = StreamTransferLimits::new(256, 128, 128, Duration::from_millis(500)).unwrap();
    application.write_all(&[0x31; 128]).await.unwrap();
    let mut proxy = Box::pin(proxy_bidirectional(proxy_client, proxy_exit, limits));
    let readiness = poll_fn(|cx| Poll::Ready(proxy.as_mut().poll(cx))).await;
    assert!(readiness.is_pending());
    // The destination never reads the pending request. Reverse heartbeats must
    // remain possible, but must not renew the original forward write/flush bound.
    // A failed outer timeout drops both owned futures, not a detached proxy task.
    let (result, reverse_bytes) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(proxy, async {
            let mut heartbeat = tokio::time::interval(Duration::from_millis(100));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut reverse_bytes = 0;
            loop {
                heartbeat.tick().await;
                if destination.write_all(&[0x72]).await.is_err() {
                    break;
                }
                match application.read_u8().await {
                    Ok(byte) => {
                        assert_eq!(byte, 0x72);
                        reverse_bytes += 1;
                    }
                    Err(_) => break,
                }
            }
            reverse_bytes
        })
    })
    .await
    .expect("reverse progress must not keep a blocked write alive");
    assert!(matches!(result, Err(TcpProxyError::IdleTimeout)));
    assert!(reverse_bytes >= 2);
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

#[tokio::test]
async fn reverse_directional_byte_limit_fails_closed() {
    let (_application, proxy_client) = tokio::io::duplex(64);
    let (proxy_exit, mut exit) = tokio::io::duplex(64);
    let limits = StreamTransferLimits::new(8, 64, 3, Duration::from_secs(2)).unwrap();
    let task = tokio::spawn(proxy_bidirectional(proxy_client, proxy_exit, limits));
    exit.write_all(b"four").await.unwrap();
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
