//! Bounded real HTTP/3 fixture for the disposable A06/A07 KVM topology.

#![forbid(unsafe_code)]

use std::{
    env,
    error::Error,
    fs,
    io::Write as _,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Buf as _, Bytes};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};
use http::{Method, StatusCode, Version};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::time::{sleep, timeout};

const TLS_SERVER_NAME: &str = "destination.volparossa.test";
const H3_ALPN: &[u8] = b"h3";
const REQUEST_BYTES: usize = 4 * 1024 * 1024;
const A06_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const A07_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const CHUNK_BYTES: usize = 16 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(180);
const RELEASE_DEADLINE: Duration = Duration::from_secs(90);

type FixtureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptanceCase {
    A06,
    A07,
}

impl AcceptanceCase {
    fn parse(value: &str) -> FixtureResult<Self> {
        match value {
            "a06" => Ok(Self::A06),
            "a07" => Ok(Self::A07),
            _ => Err("case must be a06 or a07".into()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::A06 => "a06",
            Self::A07 => "a07",
        }
    }

    const fn response_bytes(self) -> usize {
        match self {
            Self::A06 => A06_RESPONSE_BYTES,
            Self::A07 => A07_RESPONSE_BYTES,
        }
    }
}

#[tokio::main]
async fn main() -> FixtureResult<()> {
    install_crypto_provider()?;
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("server") => {
            let listen = parse_socket(&argument(&mut arguments, "listen address")?)?;
            let certificate = absolute_path(argument(&mut arguments, "certificate path")?)?;
            let ready = absolute_path(argument(&mut arguments, "ready path")?)?;
            let coordination = absolute_path(argument(&mut arguments, "coordination directory")?)?;
            let run_id = parse_run_id(&argument(&mut arguments, "run ID")?)?;
            reject_extra(arguments)?;
            run_server(listen, &certificate, &ready, &coordination, run_id).await
        }
        Some("client") => {
            let case = AcceptanceCase::parse(&argument(&mut arguments, "case")?)?;
            let bind = parse_socket(&argument(&mut arguments, "bind address")?)?;
            let remote = parse_socket(&argument(&mut arguments, "remote address")?)?;
            let certificate = absolute_path(argument(&mut arguments, "certificate path")?)?;
            let run_id = parse_run_id(&argument(&mut arguments, "run ID")?)?;
            let output = absolute_path(argument(&mut arguments, "output path")?)?;
            reject_extra(arguments)?;
            run_client(case, bind, remote, &certificate, run_id, &output).await
        }
        _ => Err("usage: http3-acceptance-fixture {server|client} ...".into()),
    }
}

fn install_crypto_provider() -> FixtureResult<()> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _installation = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err("rustls cryptography provider is unavailable".into());
    }
    Ok(())
}

fn argument(arguments: &mut impl Iterator<Item = String>, name: &str) -> FixtureResult<String> {
    arguments
        .next()
        .ok_or_else(|| format!("missing {name}").into())
}

fn reject_extra(mut arguments: impl Iterator<Item = String>) -> FixtureResult<()> {
    if arguments.next().is_some() {
        return Err("unexpected fixture argument".into());
    }
    Ok(())
}

fn parse_socket(value: &str) -> FixtureResult<SocketAddr> {
    value.parse().map_err(Into::into)
}

fn absolute_path(value: String) -> FixtureResult<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("fixture paths must be absolute".into());
    }
    Ok(path)
}

fn parse_run_id(value: &str) -> FixtureResult<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("run ID must be 32 lowercase hexadecimal characters".into());
    }
    let decoded = hex::decode(value)?;
    decoded
        .try_into()
        .map_err(|_| "run ID must contain 16 bytes".into())
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear, bounded server transaction keeps A06/A07 evidence together"
)]
async fn run_server(
    listen: SocketAddr,
    certificate_path: &Path,
    ready_path: &Path,
    coordination: &Path,
    run_id: [u8; 16],
) -> FixtureResult<()> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![TLS_SERVER_NAME.to_owned()])?;
    let certificate = cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)?;
    tls.alpn_protocols = vec![H3_ALPN.to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_millis(500)));
    transport.max_idle_timeout(Some(Duration::from_secs(120).try_into()?));
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    server.transport = Arc::new(transport);
    let endpoint = quinn::Endpoint::server(server, listen)?;

    write_new(certificate_path, certificate.as_ref())?;
    write_new(ready_path, b"http3=ready\nalpn=h3\n")?;

    for case in [AcceptanceCase::A06, AcceptanceCase::A07] {
        let incoming = timeout(IO_DEADLINE, endpoint.accept())
            .await
            .map_err(|_| "timed out waiting for HTTP/3 connection")?
            .ok_or("HTTP/3 endpoint closed before both cases")?;
        let connection = timeout(IO_DEADLINE, incoming)
            .await
            .map_err(|_| "timed out accepting HTTP/3 connection")??;
        let peer = connection.remote_address();
        let alpn = negotiated_alpn(&connection)?;
        if alpn.as_slice() != H3_ALPN {
            return Err("server did not negotiate h3".into());
        }
        let mut h3_connection =
            h3::server::Connection::new(h3_quinn::Connection::new(connection.clone())).await?;
        let resolver = timeout(IO_DEADLINE, h3_connection.accept())
            .await
            .map_err(|_| "timed out waiting for HTTP/3 request")??
            .ok_or("HTTP/3 peer closed before request")?;
        let (request, mut stream) = timeout(IO_DEADLINE, resolver.resolve_request())
            .await
            .map_err(|_| "timed out resolving HTTP/3 request")??;

        let expected_path = format!("/{}/{}", case.label(), hex::encode(run_id));
        if request.method() != Method::POST
            || request.version() != Version::HTTP_3
            || request.uri().path() != expected_path
        {
            return Err("unexpected HTTP/3 request metadata".into());
        }

        let request_seed = payload_seed(case, run_id, b"request");
        let mut request_hash = Sha256::new();
        let mut request_bytes = 0_usize;
        while let Some(mut data) = timeout(IO_DEADLINE, stream.recv_data())
            .await
            .map_err(|_| "timed out receiving HTTP/3 request body")??
        {
            while data.has_remaining() {
                let chunk = data.chunk();
                request_bytes = request_bytes
                    .checked_add(chunk.len())
                    .ok_or("HTTP/3 request length overflow")?;
                if request_bytes > REQUEST_BYTES {
                    return Err("HTTP/3 request exceeded its bound".into());
                }
                request_hash.update(chunk);
                let consumed = chunk.len();
                data.advance(consumed);
            }
        }
        let expected_request_hash = payload_sha256(&request_seed, REQUEST_BYTES);
        if request_bytes != REQUEST_BYTES
            || request_hash.finalize().as_slice() != expected_request_hash
        {
            return Err("HTTP/3 request payload was incomplete or substituted".into());
        }

        let release_observed = if case == AcceptanceCase::A07 {
            let active_path = coordination.join("a07-active.ready");
            let release_path = coordination.join("a07.release");
            write_new(&active_path, b"request-body-complete\n")?;
            let release_deadline = Instant::now() + RELEASE_DEADLINE;
            loop {
                if release_path.try_exists()? {
                    break true;
                }
                if Instant::now() >= release_deadline {
                    return Err("A07 relay-removal release was not observed".into());
                }
                sleep(Duration::from_millis(50)).await;
            }
        } else {
            false
        };

        let response = http::Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_3)
            .header("content-type", "application/octet-stream")
            .header("content-length", case.response_bytes())
            .header("x-volparossa-acceptance", case.label())
            .body(())?;
        stream.send_response(response).await?;

        let response_seed = payload_seed(case, run_id, b"response");
        let mut response_hash = Sha256::new();
        let mut offset = 0_usize;
        while offset < case.response_bytes() {
            let length = CHUNK_BYTES.min(case.response_bytes() - offset);
            let chunk = payload_chunk(&response_seed, offset, length);
            response_hash.update(&chunk);
            stream.send_data(chunk).await?;
            offset += length;
            if case == AcceptanceCase::A07 {
                sleep(Duration::from_millis(2)).await;
            }
        }
        stream.finish().await?;
        // Give the peer's H3 stream driver time to observe FIN before the bounded
        // connection-level H3_NO_ERROR close below.
        sleep(Duration::from_millis(100)).await;

        let evidence = json!({
            "schema_version": 1,
            "case": case.label(),
            "protocol": "HTTP/3",
            "http_version": "HTTP/3",
            "negotiated_alpn": "h3",
            "hostname": TLS_SERVER_NAME,
            "listen": {"ip": listen.ip().to_string(), "port": listen.port()},
            "source": {"ip": peer.ip().to_string(), "port": peer.port()},
            "request_bytes": request_bytes,
            "request_sha256": hex::encode(expected_request_hash),
            "response_bytes": case.response_bytes(),
            "response_sha256": hex::encode(response_hash.finalize()),
            "release_observed": release_observed,
        });
        write_json_new(
            &coordination.join(format!("server-{}.json", case.label())),
            &evidence,
        )?;
        connection.close(quinn::VarInt::from_u32(0x100), b"HTTP/3 case complete");
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"acceptance complete");
    timeout(Duration::from_secs(5), endpoint.wait_idle())
        .await
        .map_err(|_| "HTTP/3 server did not become idle")?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear, bounded HTTP/3 exchange keeps payload evidence together"
)]
async fn run_client(
    case: AcceptanceCase,
    bind: SocketAddr,
    remote: SocketAddr,
    certificate_path: &Path,
    run_id: [u8; 16],
    output: &Path,
) -> FixtureResult<()> {
    let metadata = fs::symlink_metadata(certificate_path)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CERTIFICATE_BYTES
    {
        return Err("unsafe HTTP/3 fixture certificate".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(fs::read(certificate_path)?))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![H3_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_millis(500)));
    transport.max_idle_timeout(Some(Duration::from_secs(120).try_into()?));
    client.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(client);
    let local = endpoint.local_addr()?;
    let connection = timeout(IO_DEADLINE, endpoint.connect(remote, TLS_SERVER_NAME)?)
        .await
        .map_err(|_| "timed out connecting HTTP/3 client")??;
    let alpn = negotiated_alpn(&connection)?;
    if alpn.as_slice() != H3_ALPN {
        return Err("client did not negotiate h3".into());
    }

    let (mut driver, mut sender) =
        h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
    let request_path = format!(
        "https://{TLS_SERVER_NAME}/{}/{}",
        case.label(),
        hex::encode(run_id)
    );
    let request = http::Request::builder()
        .method(Method::POST)
        .uri(request_path)
        .version(Version::HTTP_3)
        .header("content-type", "application/octet-stream")
        .header("content-length", REQUEST_BYTES)
        .body(())?;

    let exchange_connection = connection.clone();
    let exchange = async move {
        let started = Instant::now();
        let mut stream = sender.send_request(request).await?;
        let request_seed = payload_seed(case, run_id, b"request");
        let mut offset = 0_usize;
        while offset < REQUEST_BYTES {
            let length = CHUNK_BYTES.min(REQUEST_BYTES - offset);
            stream
                .send_data(payload_chunk(&request_seed, offset, length))
                .await?;
            offset += length;
        }
        stream.finish().await?;

        let response = timeout(IO_DEADLINE, stream.recv_response())
            .await
            .map_err(|_| "timed out receiving HTTP/3 response headers")??;
        if response.status() != StatusCode::OK
            || response.version() != Version::HTTP_3
            || response
                .headers()
                .get("x-volparossa-acceptance")
                .and_then(|value| value.to_str().ok())
                != Some(case.label())
        {
            return Err::<Value, Box<dyn Error + Send + Sync>>(
                "unexpected HTTP/3 response metadata".into(),
            );
        }

        let response_seed = payload_seed(case, run_id, b"response");
        let expected_hash = payload_sha256(&response_seed, case.response_bytes());
        let mut received_hash = Sha256::new();
        let mut received_bytes = 0_usize;
        let mut first_byte = None;
        loop {
            let received = timeout(IO_DEADLINE, stream.recv_data())
                .await
                .map_err(|_| "timed out receiving HTTP/3 response body")?;
            let Some(mut data) = (match received {
                Ok(data) => data,
                Err(error) if error.is_h3_no_error() && received_bytes == case.response_bytes() => {
                    None
                }
                Err(error) => return Err(error.into()),
            }) else {
                break;
            };
            if first_byte.is_none() {
                first_byte = Some(Instant::now());
            }
            while data.has_remaining() {
                let chunk = data.chunk();
                received_bytes = received_bytes
                    .checked_add(chunk.len())
                    .ok_or("HTTP/3 response length overflow")?;
                if received_bytes > case.response_bytes() {
                    return Err("HTTP/3 response exceeded its bound".into());
                }
                received_hash.update(chunk);
                let consumed = chunk.len();
                data.advance(consumed);
            }
        }
        let completed = Instant::now();
        let received_hash = received_hash.finalize();
        if received_bytes != case.response_bytes() || received_hash.as_slice() != expected_hash {
            return Err("HTTP/3 response payload was incomplete or substituted".into());
        }
        let first_byte = first_byte.ok_or("HTTP/3 response contained no data")?;
        let duration = completed.saturating_duration_since(first_byte);
        if duration.is_zero() {
            return Err("HTTP/3 response duration was zero".into());
        }
        exchange_connection.close(quinn::VarInt::from_u32(0), b"HTTP/3 request complete");
        Ok(json!({
            "schema_version": 1,
            "case": case.label(),
            "protocol": "HTTP/3",
            "http_version": "HTTP/3",
            "negotiated_alpn": "h3",
            "hostname": TLS_SERVER_NAME,
            "application": {"ip": local.ip().to_string(), "port": local.port()},
            "destination": {"ip": remote.ip().to_string(), "port": remote.port()},
            "request_bytes": REQUEST_BYTES,
            "request_sha256": hex::encode(payload_sha256(&request_seed, REQUEST_BYTES)),
            "response_bytes": received_bytes,
            "response_sha256": hex::encode(received_hash),
            "response_duration_ns": u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX),
            "transfer_elapsed_ns": u64::try_from(completed.saturating_duration_since(started).as_nanos())
                .unwrap_or(u64::MAX),
        }))
    };
    let drive = async move {
        let closed = std::future::poll_fn(|context| driver.poll_close(context)).await;
        if closed.is_h3_no_error() {
            Ok(())
        } else {
            Err::<(), Box<dyn Error + Send + Sync>>(
                format!("HTTP/3 driver closed: {closed}").into(),
            )
        }
    };
    let (exchange_result, drive_result) = tokio::join!(exchange, drive);
    let evidence = exchange_result?;
    drive_result?;
    write_json_new(output, &evidence)?;
    timeout(Duration::from_secs(5), endpoint.wait_idle())
        .await
        .map_err(|_| "HTTP/3 client endpoint did not become idle")?;
    Ok(())
}

fn negotiated_alpn(connection: &quinn::Connection) -> FixtureResult<Vec<u8>> {
    let handshake = connection
        .handshake_data()
        .ok_or("QUIC handshake data was absent")?;
    let handshake = handshake
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| "QUIC handshake was not provided by rustls")?;
    handshake
        .protocol
        .ok_or_else(|| "QUIC ALPN was absent".into())
}

fn payload_seed(case: AcceptanceCase, run_id: [u8; 16], direction: &[u8]) -> Vec<u8> {
    let mut seed = b"volparossa-http3:".to_vec();
    seed.extend_from_slice(case.label().as_bytes());
    seed.push(b':');
    seed.extend_from_slice(direction);
    seed.push(b':');
    seed.extend_from_slice(&run_id);
    seed
}

fn payload_chunk(seed: &[u8], offset: usize, length: usize) -> Bytes {
    let mut chunk = Vec::with_capacity(length);
    for index in 0..length {
        chunk.push(seed[(offset + index) % seed.len()]);
    }
    Bytes::from(chunk)
}

fn payload_sha256(seed: &[u8], length: usize) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut offset = 0_usize;
    while offset < length {
        let chunk_length = CHUNK_BYTES.min(length - offset);
        hash.update(payload_chunk(seed, offset, chunk_length));
        offset += chunk_length;
    }
    hash.finalize().into()
}

fn write_json_new(path: &Path, value: &Value) -> FixtureResult<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> FixtureResult<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
