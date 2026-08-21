//! Unprivileged bounded-streaming tests for the TCP proxy.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use volparossa_tcp_proxy::{StreamTransferLimits, TcpProxyError, proxy_bidirectional};

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
