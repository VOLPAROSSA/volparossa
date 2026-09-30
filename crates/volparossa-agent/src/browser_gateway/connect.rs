//! CONNECT is only a tunnel acknowledgement, not proof that Exit-origin TLS succeeded.
//! Errors never authorize a direct retry. The browser retains end-to-origin TLS validation.

use std::{future::Future, time::Duration};

use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    sync::watch,
    time::{Instant, timeout},
};

use super::{GatewayError, Scope};
use crate::{
    control::ControlContext,
    route_setup::{ClientRouteConnectError, ClientRouteControl, ClientRouteProgress},
    unix_millis,
};

const MAX_HEADER: usize = 8192;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// Control-plane route admission precedes the browser's HTTP CONNECT/TLS timers.
pub(super) const PREPARE_TIMEOUT: Duration = Duration::from_secs(90);

// Opt-in closed diagnostics: no authority, capability, partition, route, address
// or application bytes. Only this target is enabled by the disposable fixture.
fn observe(stage: &'static str, code: &'static str) {
    tracing::debug!(stage, code, "browser_gateway_observation");
}

fn observe_route_error(stage: &'static str, code: ClientRouteConnectError) {
    tracing::debug!(stage, code = ?code, "browser_gateway_observation");
}

/// The route controller retains its bootstrap owner when this waiter is cancelled. The
/// attachment's existing retire path joins it; this function never detaches new cleanup work.
pub(super) async fn prepare<F>(
    bootstrap: &mut UnixStream,
    shutdown: &mut watch::Receiver<bool>,
    deadline: Instant,
    route: F,
) -> Result<(), GatewayError>
where
    F: Future<Output = Result<ClientRouteProgress, ClientRouteConnectError>>,
{
    // A newly polled Tokio timer may still be pending within its clock tick.
    // Do not poll route admission at all for an already-expired capability.
    if Instant::now() >= deadline {
        observe("attachment_route", "timeout");
        return Err(GatewayError::Unavailable);
    }
    observe("attachment_route", "preparing");
    let mut unexpected = [0; 1];
    tokio::select! {
        biased;
        () = crate::wait_for_shutdown(shutdown) => {
            observe("attachment_route", "shutdown");
            Err(GatewayError::Unavailable)
        }
        _ = bootstrap.read(&mut unexpected) => {
            // EOF, read error or any post-bootstrap input revokes this exact attachment.
            observe("attachment_route", "revoked");
            Err(GatewayError::Unavailable)
        }
        () = tokio::time::sleep_until(deadline) => {
            observe("attachment_route", "timeout");
            Err(GatewayError::Unavailable)
        }
        result = route => match result {
            Ok(ClientRouteProgress::TransportActive) => {
                // The route future can become ready after the biased timer/shutdown
                // checks were polled. Revalidate before publishing readiness.
                if Instant::now() >= deadline {
                    observe("attachment_route", "timeout");
                    return Err(GatewayError::Unavailable);
                }
                if *shutdown.borrow() || shutdown.has_changed().is_err() {
                    observe("attachment_route", "shutdown");
                    return Err(GatewayError::Unavailable);
                }
                observe("attachment_route", "ready");
                Ok(())
            }
            Ok(ClientRouteProgress::UdpRouteReady) => {
                observe_route_error("attachment_route", ClientRouteConnectError::InvalidProfile);
                Err(GatewayError::Unavailable)
            }
            Err(error) => {
                observe_route_error("attachment_route", error);
                Err(GatewayError::Unavailable)
            }
        }
    }
}

pub(super) async fn proxy(
    mut application: TcpStream,
    scope: &Scope,
    routes: &ClientRouteControl,
    context: &ControlContext,
    secret: &[u8; 32],
) {
    observe("connect_header", "received");
    let header = timeout(
        HEADER_TIMEOUT,
        read_connect(&mut application, scope, secret),
    )
    .await;
    if !matches!(&header, Ok(Ok(()))) {
        observe(
            "connect_header",
            if header.is_err() {
                "timeout"
            } else {
                "invalid"
            },
        );
        reject(
            &mut application,
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        return;
    }
    observe("connect_header", "accepted");
    if scope.policy(context).await.is_err() {
        observe("policy_before_route", "denied");
        return;
    }
    if let Err(error) =
        Box::pin(routes.connect_tcp(&context.config, &context.discovery, &context.helper)).await
    {
        observe_route_error("route", error);
        reject(
            &mut application,
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        return;
    }
    observe("route", "ready");
    let Ok(policy) = scope.policy(context).await else {
        observe("policy_before_flow", "denied");
        return;
    };
    let flow = match Box::pin(routes.open_content_stream(
        &policy,
        &scope.hostname,
        scope.port,
        unix_millis(),
    ))
    .await
    {
        Ok(flow) => flow,
        Err(error) => {
            observe_route_error("flow", error);
            reject(
                &mut application,
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            return;
        }
    };
    // Recheck after asynchronous setup, before forwarding any browser payload.
    if scope.policy(context).await.is_err() {
        observe("policy_after_flow", "denied");
        flow.shutdown();
        return;
    }
    if !matches!(
        timeout(
            HEADER_TIMEOUT,
            application.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        )
        .await,
        Ok(Ok(()))
    ) {
        observe("acknowledgement", "write_failed");
        flow.shutdown();
        return;
    }
    observe("acknowledgement", "forwarding_started");
    let _ = flow.proxy_application(application).await;
}

async fn reject(stream: &mut TcpStream, response: &[u8]) {
    let _ = timeout(HEADER_TIMEOUT, stream.write_all(response)).await;
}

async fn read_connect(
    stream: &mut TcpStream,
    scope: &Scope,
    secret: &[u8; 32],
) -> Result<(), GatewayError> {
    let mut header = Vec::with_capacity(512);
    // Read through exactly CRLFCRLF. Never consume or lose coalesced TLS ClientHello bytes.
    while header.len() < MAX_HEADER {
        header.push(stream.read_u8().await.map_err(|_| GatewayError::Invalid)?);
        if header.ends_with(b"\r\n\r\n") {
            return validate(&header, scope, secret);
        }
    }
    Err(GatewayError::Invalid)
}

fn validate(header: &[u8], scope: &Scope, secret: &[u8; 32]) -> Result<(), GatewayError> {
    let text = std::str::from_utf8(header).map_err(|_| GatewayError::Invalid)?;
    if header.len() > MAX_HEADER || !text.ends_with("\r\n\r\n") {
        return Err(GatewayError::Invalid);
    }
    let authority = format!("{}:{}", scope.hostname, scope.port);
    let mut lines = text[..text.len() - 4].split("\r\n");
    if lines.next() != Some(format!("CONNECT {authority} HTTP/1.1").as_str()) {
        return Err(GatewayError::Invalid);
    }
    let mut authenticated = false;
    let mut host_seen = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(GatewayError::Invalid)?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'-')
            || value.bytes().any(|byte| !(b' '..=b'~').contains(&byte))
        {
            return Err(GatewayError::Invalid);
        }
        let value = value.trim_matches(' ');
        if name.eq_ignore_ascii_case("proxy-authorization") {
            let expected = format!("Bearer {}", hex::encode(secret));
            if authenticated || !bool::from(value.as_bytes().ct_eq(expected.as_bytes())) {
                return Err(GatewayError::Invalid);
            }
            authenticated = true;
        } else if name.eq_ignore_ascii_case("host") {
            if host_seen || value != authority {
                return Err(GatewayError::Invalid);
            }
            host_seen = true;
        } else if !["user-agent", "proxy-connection", "connection"]
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
        {
            // No body framing, forwarding headers, alternate destination, or protocol upgrade.
            return Err(GatewayError::Invalid);
        }
    }
    if authenticated {
        Ok(())
    } else {
        Err(GatewayError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attachment_prepare_waits_for_active_route_before_ready() {
        let (mut bootstrap, _peer) = UnixStream::pair().expect("bootstrap pair");
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (route_tx, route_rx) = tokio::sync::oneshot::channel();
        let mut preparation = Box::pin(prepare(
            &mut bootstrap,
            &mut shutdown,
            Instant::now() + PREPARE_TIMEOUT,
            async { route_rx.await.expect("route completion") },
        ));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                preparation.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        route_tx
            .send(Ok(ClientRouteProgress::TransportActive))
            .expect("preparation still owns route waiter");
        assert!(preparation.await.is_ok());
    }

    #[tokio::test]
    async fn attachment_prepare_rejects_wrong_transport_and_route_failure() {
        for result in [
            Ok(ClientRouteProgress::UdpRouteReady),
            Err(ClientRouteConnectError::PreselectionUnavailable),
        ] {
            let (mut bootstrap, _peer) = UnixStream::pair().expect("bootstrap pair");
            let (_shutdown_tx, mut shutdown) = watch::channel(false);
            assert!(
                prepare(
                    &mut bootstrap,
                    &mut shutdown,
                    Instant::now() + PREPARE_TIMEOUT,
                    std::future::ready(result),
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn attachment_prepare_expiry_and_shutdown_win_over_ready_route() {
        for expired in [true, false] {
            let (mut bootstrap, _peer) = UnixStream::pair().expect("bootstrap pair");
            let (_shutdown_tx, mut shutdown) = watch::channel(!expired);
            let deadline = if expired {
                Instant::now()
            } else {
                Instant::now() + PREPARE_TIMEOUT
            };
            assert!(
                prepare(
                    &mut bootstrap,
                    &mut shutdown,
                    deadline,
                    std::future::ready(Ok(ClientRouteProgress::TransportActive)),
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn attachment_prepare_expired_deadline_does_not_poll_route() {
        let (mut bootstrap, _peer) = UnixStream::pair().expect("bootstrap pair");
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let mut polled = false;
        let route = async {
            polled = true;
            Ok(ClientRouteProgress::TransportActive)
        };
        assert!(
            prepare(&mut bootstrap, &mut shutdown, Instant::now(), route)
                .await
                .is_err()
        );
        assert!(!polled);
    }

    #[tokio::test]
    async fn attachment_prepare_rechecks_expiry_and_shutdown_after_route_poll() {
        for expiry in [true, false] {
            let (mut bootstrap, _peer) = UnixStream::pair().expect("bootstrap pair");
            let (shutdown_tx, mut shutdown) = watch::channel(false);
            let deadline = Instant::now() + Duration::from_millis(10);
            let route = async {
                if expiry {
                    // Model one route poll doing synchronous work across its deadline.
                    std::thread::sleep(Duration::from_millis(20));
                } else {
                    shutdown_tx.send(true).expect("live shutdown receiver");
                }
                Ok(ClientRouteProgress::TransportActive)
            };
            assert!(
                prepare(&mut bootstrap, &mut shutdown, deadline, route)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn attachment_prepare_revocation_drops_waiter_without_detached_task() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for eof in [true, false] {
            let (mut bootstrap, mut peer) = UnixStream::pair().expect("bootstrap pair");
            let (_shutdown_tx, mut shutdown) = watch::channel(false);
            let dropped = Arc::new(AtomicBool::new(false));
            let guard = Dropped(Arc::clone(&dropped));
            let route = async move {
                let _guard = guard;
                std::future::pending().await
            };
            let mut preparation = Box::pin(prepare(
                &mut bootstrap,
                &mut shutdown,
                Instant::now() + PREPARE_TIMEOUT,
                route,
            ));
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    preparation.as_mut().poll(cx).is_pending()
                ))
                .await
            );
            if eof {
                drop(peer);
            } else {
                peer.write_all(b"x").await.expect("unexpected input");
            }
            assert!(preparation.await.is_err());
            assert!(dropped.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn connect_binds_exact_authority_and_capability_without_proxy_escape() {
        let scope = super::super::tests::scope(1);
        let secret = [7; 32];
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            hex::encode(secret)
        );
        assert!(validate(request.as_bytes(), &scope, &secret).is_ok());
        for bad in [
            request.replace("CONNECT example.com", "CONNECT other.com"),
            request.replace("CONNECT example.com", "CONNECT 127.0.0.1"),
            request.replace("CONNECT example.com", "CONNECT https://example.com"),
            request.replace("CONNECT", "GET"),
            request.replace("Host: example.com", "Host: other.com"),
            request.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\n"),
            request.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
            request.replace("\r\nHost:", "\r\n Host:"),
            request.replace(
                "Proxy-Authorization:",
                "Proxy-Authorization:\r\nProxy-Authorization:",
            ),
        ] {
            assert!(validate(bad.as_bytes(), &scope, &secret).is_err());
        }
        assert!(validate(request.as_bytes(), &scope, &[8; 32]).is_err());
    }
}
