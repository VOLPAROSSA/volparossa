//! CONNECT is only a tunnel acknowledgement, not proof that Exit-origin TLS succeeded.
//! Errors never authorize a direct retry. The browser retains end-to-origin TLS validation.

use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{GatewayError, Scope};
use crate::{
    control::ControlContext,
    route_setup::{ClientRouteConnectError, ClientRouteControl},
    unix_millis,
};

const MAX_HEADER: usize = 8192;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

// Opt-in closed diagnostics: no authority, capability, partition, route, address
// or application bytes. Only this target is enabled by the disposable fixture.
fn observe(stage: &'static str, code: &'static str) {
    tracing::debug!(stage, code, "browser_gateway_observation");
}

fn observe_route_error(stage: &'static str, code: ClientRouteConnectError) {
    tracing::debug!(stage, code = ?code, "browser_gateway_observation");
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
