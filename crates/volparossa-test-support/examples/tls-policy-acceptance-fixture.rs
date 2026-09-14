//! Bounded real TLS fixture for disposable A08-A10 policy acceptance.

#![forbid(unsafe_code)]

use std::{
    env,
    error::Error,
    fs,
    io::{self, Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const SERVER_NAME: &str = "destination.volparossa.test";
const ALPN: &[u8] = b"volparossa-a08/1";
const PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;
const SERVER_DEADLINE: Duration = Duration::from_secs(300);
const CONNECTION_DEADLINE: Duration = Duration::from_secs(20);
const ALLOWED_CLIENT_IO_DEADLINE: Duration = Duration::from_secs(90);

type FixtureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DenialCase {
    UnlistedDomain,
    RawIpServerName,
    MissingServerName,
    MismatchedDestination,
    ForbiddenPort,
    Ech,
    Unverifiable,
}

impl DenialCase {
    fn parse(value: &str) -> FixtureResult<Self> {
        match value {
            "unlisted-domain" => Ok(Self::UnlistedDomain),
            "raw-ip-server-name" => Ok(Self::RawIpServerName),
            "missing-server-name" => Ok(Self::MissingServerName),
            "mismatched-destination" => Ok(Self::MismatchedDestination),
            "forbidden-port" => Ok(Self::ForbiddenPort),
            "ech" => Ok(Self::Ech),
            "unverifiable" => Ok(Self::Unverifiable),
            _ => Err("unknown denial case".into()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::UnlistedDomain => "unlisted-domain",
            Self::RawIpServerName => "raw-ip-server-name",
            Self::MissingServerName => "missing-server-name",
            Self::MismatchedDestination => "mismatched-destination",
            Self::ForbiddenPort => "forbidden-port",
            Self::Ech => "ech",
            Self::Unverifiable => "unverifiable",
        }
    }

    const fn server_name(self) -> Option<&'static str> {
        match self {
            Self::UnlistedDomain => Some("unlisted.volparossa.test"),
            Self::RawIpServerName => Some("47.163.4.2"),
            Self::MissingServerName | Self::Unverifiable => None,
            Self::MismatchedDestination | Self::ForbiddenPort | Self::Ech => Some(SERVER_NAME),
        }
    }
}

#[derive(Debug, Default)]
struct ServerEvidence {
    accepted_connections: u64,
    successful_exchanges: u64,
    failed_connections: u64,
    request_bytes: u64,
    request_sha256: Option<String>,
    response_bytes: u64,
    response_sha256: Option<String>,
    last_source: Option<SocketAddr>,
}

fn main() -> FixtureResult<()> {
    install_crypto_provider()?;
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("server") => {
            let listen = parse_socket(&argument(&mut arguments, "listen address")?)?;
            let certificate = absolute_path(argument(&mut arguments, "certificate path")?)?;
            let ready = absolute_path(argument(&mut arguments, "ready path")?)?;
            let evidence = absolute_path(argument(&mut arguments, "evidence path")?)?;
            let stop = absolute_path(argument(&mut arguments, "stop path")?)?;
            let run_id = parse_run_id(&argument(&mut arguments, "run ID")?)?;
            reject_extra(arguments)?;
            run_server(listen, &certificate, &ready, &evidence, &stop, run_id)
        }
        Some("allowed") => {
            let remote = parse_socket(&argument(&mut arguments, "remote address")?)?;
            let certificate = absolute_path(argument(&mut arguments, "certificate path")?)?;
            let run_id = parse_run_id(&argument(&mut arguments, "run ID")?)?;
            let output = absolute_path(argument(&mut arguments, "output path")?)?;
            reject_extra(arguments)?;
            run_allowed(remote, &certificate, run_id, &output)
        }
        Some("denied") => {
            let case = DenialCase::parse(&argument(&mut arguments, "denial case")?)?;
            let remote = parse_socket(&argument(&mut arguments, "remote address")?)?;
            let run_id = parse_run_id(&argument(&mut arguments, "run ID")?)?;
            let output = absolute_path(argument(&mut arguments, "output path")?)?;
            reject_extra(arguments)?;
            run_denied(case, remote, run_id, &output)
        }
        _ => Err("usage: tls-policy-acceptance-fixture {server|allowed|denied} ...".into()),
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
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "run ID must contain 16 bytes")?)
}

fn run_server(
    listen: SocketAddr,
    certificate_path: &Path,
    ready_path: &Path,
    evidence_path: &Path,
    stop_path: &Path,
    run_id: [u8; 16],
) -> FixtureResult<()> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![SERVER_NAME.to_owned()])?;
    let certificate = cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let mut configuration =
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)?;
    configuration.alpn_protocols = vec![ALPN.to_vec()];
    let configuration = Arc::new(configuration);
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;

    write_new(certificate_path, certificate.as_ref())?;
    let mut evidence = ServerEvidence::default();
    write_server_evidence(evidence_path, listen, &evidence)?;
    write_new(ready_path, b"tls=ready\nname=destination.volparossa.test\n")?;

    let deadline = Instant::now() + SERVER_DEADLINE;
    while !stop_path.try_exists()? && Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, source)) => {
                evidence.accepted_connections = evidence.accepted_connections.saturating_add(1);
                evidence.last_source = Some(source);
                match handle_server_connection(stream, Arc::clone(&configuration), run_id) {
                    Ok((bytes, hash)) => {
                        evidence.successful_exchanges =
                            evidence.successful_exchanges.saturating_add(1);
                        evidence.request_bytes = bytes;
                        evidence.response_bytes = bytes;
                        evidence.request_sha256 = Some(hash.clone());
                        evidence.response_sha256 = Some(hash);
                    }
                    Err(error) => {
                        evidence.failed_connections = evidence.failed_connections.saturating_add(1);
                        eprintln!("rejected destination connection: {error}");
                    }
                }
                write_server_evidence(evidence_path, listen, &evidence)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error.into()),
        }
    }
    if !stop_path.try_exists()? {
        return Err("TLS policy server did not receive its bounded stop signal".into());
    }
    write_server_evidence(evidence_path, listen, &evidence)
}

fn handle_server_connection(
    stream: TcpStream,
    configuration: Arc<ServerConfig>,
    run_id: [u8; 16],
) -> FixtureResult<(u64, String)> {
    stream.set_read_timeout(Some(CONNECTION_DEADLINE))?;
    stream.set_write_timeout(Some(CONNECTION_DEADLINE))?;
    let connection = ServerConnection::new(configuration)?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut length = [0_u8; 4];
    tls.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    if length != PAYLOAD_BYTES {
        return Err("unexpected A08 request length".into());
    }
    let mut request_payload = vec![0_u8; length];
    tls.read_exact(&mut request_payload)?;
    let expected = payload(run_id);
    if request_payload != expected {
        return Err("A08 request payload was substituted".into());
    }
    if tls.conn.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || tls.conn.alpn_protocol() != Some(ALPN)
    {
        return Err("destination did not negotiate exact TLS 1.3 ALPN".into());
    }
    tls.write_all(&u32::try_from(length)?.to_be_bytes())?;
    tls.write_all(&request_payload)?;
    tls.flush()?;
    tls.sock.shutdown(Shutdown::Write)?;
    Ok((
        u64::try_from(length)?,
        hex::encode(Sha256::digest(&request_payload)),
    ))
}

fn run_allowed(
    remote: SocketAddr,
    certificate_path: &Path,
    run_id: [u8; 16],
    output_path: &Path,
) -> FixtureResult<()> {
    let metadata = fs::metadata(certificate_path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CERTIFICATE_BYTES {
        return Err("fixture certificate is unavailable or oversized".into());
    }
    let certificate = CertificateDer::from(fs::read(certificate_path)?);
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let mut configuration =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    configuration.alpn_protocols = vec![ALPN.to_vec()];
    let server_name = ServerName::try_from(SERVER_NAME.to_owned())?;
    let connection = ClientConnection::new(Arc::new(configuration), server_name)?;
    let stream = TcpStream::connect_timeout(&remote, CONNECTION_DEADLINE)?;
    stream.set_read_timeout(Some(ALLOWED_CLIENT_IO_DEADLINE))?;
    stream.set_write_timeout(Some(ALLOWED_CLIENT_IO_DEADLINE))?;
    let application = stream.local_addr()?;
    let mut tls = StreamOwned::new(connection, stream);
    let request = payload(run_id);
    tls.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
    tls.write_all(&request)?;
    tls.flush()?;
    let mut length = [0_u8; 4];
    tls.read_exact(&mut length)?;
    if usize::try_from(u32::from_be_bytes(length))? != request.len() {
        return Err("unexpected A08 response length".into());
    }
    let mut response = vec![0_u8; request.len()];
    tls.read_exact(&mut response)?;
    if response != request {
        return Err("A08 response payload was substituted".into());
    }
    if tls.conn.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || tls.conn.alpn_protocol() != Some(ALPN)
    {
        return Err("client did not negotiate exact TLS 1.3 ALPN".into());
    }
    let digest = hex::encode(Sha256::digest(&request));
    write_json_new(
        output_path,
        &json!({
            "schema_version": 1,
            "case": "allowed-domain",
            "hostname": SERVER_NAME,
            "application": {"ip": application.ip().to_string(), "port": application.port()},
            "destination": {"ip": remote.ip().to_string(), "port": remote.port()},
            "tls_version": "TLSv1.3",
            "negotiated_alpn": "volparossa-a08/1",
            "request_bytes": request.len(),
            "request_sha256": digest,
            "response_bytes": response.len(),
            "response_sha256": hex::encode(Sha256::digest(&response)),
        }),
    )
}

fn run_denied(
    case: DenialCase,
    remote: SocketAddr,
    run_id: [u8; 16],
    output_path: &Path,
) -> FixtureResult<()> {
    let client_hello = match case {
        DenialCase::Unverifiable => vec![23, 3, 3, 0, 1, 0],
        _ => client_hello(case.server_name(), case == DenialCase::Ech, run_id)?,
    };
    let mut connected = false;
    let mut sent_bytes = 0_usize;
    let mut peer_closed = false;
    let mut error_kind = None;
    match TcpStream::connect_timeout(&remote, CONNECTION_DEADLINE) {
        Ok(mut stream) => {
            connected = true;
            stream.set_read_timeout(Some(CONNECTION_DEADLINE))?;
            stream.set_write_timeout(Some(CONNECTION_DEADLINE))?;
            match stream.write_all(&client_hello) {
                Ok(()) => sent_bytes = client_hello.len(),
                Err(error) if is_closed_error(&error) => {
                    peer_closed = true;
                    error_kind = Some(format!("{:?}", error.kind()));
                }
                Err(error) => return Err(error.into()),
            }
            let _ = stream.shutdown(Shutdown::Write);
            if !peer_closed {
                let mut response = [0_u8; 1];
                match stream.read(&mut response) {
                    Ok(0) => peer_closed = true,
                    Ok(_) => return Err("denied TLS flow received destination bytes".into()),
                    Err(error) if is_closed_error(&error) => {
                        peer_closed = true;
                        error_kind = Some(format!("{:?}", error.kind()));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) =>
        {
            peer_closed = true;
            error_kind = Some(format!("{:?}", error.kind()));
        }
        Err(error) => return Err(error.into()),
    }
    if !peer_closed {
        return Err("denied TLS flow did not fail closed".into());
    }
    write_json_new(
        output_path,
        &json!({
            "schema_version": 1,
            "case": case.label(),
            "destination": {"ip": remote.ip().to_string(), "port": remote.port()},
            "server_name": case.server_name(),
            "connected_to_ingress": connected,
            "client_hello_bytes": sent_bytes,
            "peer_closed_without_payload": peer_closed,
            "socket_error_kind": error_kind,
            "destination_response_bytes": 0,
        }),
    )
}

fn is_closed_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn client_hello(server_name: Option<&str>, ech: bool, run_id: [u8; 16]) -> FixtureResult<Vec<u8>> {
    let mut extensions = Vec::new();
    if let Some(server_name) = server_name {
        let name = server_name.as_bytes();
        let name_length = u16::try_from(name.len())?;
        let list_length = name_length.checked_add(3).ok_or("SNI length overflow")?;
        let mut data = Vec::with_capacity(usize::from(list_length) + 2);
        data.extend_from_slice(&list_length.to_be_bytes());
        data.push(0);
        data.extend_from_slice(&name_length.to_be_bytes());
        data.extend_from_slice(name);
        append_extension(&mut extensions, 0, &data)?;
    }
    append_extension(&mut extensions, 43, &[2, 3, 4])?;
    append_extension(&mut extensions, 13, &[0, 4, 4, 3, 8, 4])?;
    if ech {
        append_extension(&mut extensions, 0xfe0d, &[0, 1, 0, 0])?;
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[3, 3]);
    body.extend_from_slice(&run_id);
    body.extend_from_slice(&run_id);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&u16::try_from(extensions.len())?.to_be_bytes());
    body.extend_from_slice(&extensions);

    let body_length = u32::try_from(body.len())?;
    if body_length > 0x00ff_ffff {
        return Err("ClientHello is oversized".into());
    }
    let length_bytes = body_length.to_be_bytes();
    let mut handshake = vec![1, length_bytes[1], length_bytes[2], length_bytes[3]];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&u16::try_from(handshake.len())?.to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}

fn append_extension(output: &mut Vec<u8>, extension_type: u16, data: &[u8]) -> FixtureResult<()> {
    output.extend_from_slice(&extension_type.to_be_bytes());
    output.extend_from_slice(&u16::try_from(data.len())?.to_be_bytes());
    output.extend_from_slice(data);
    Ok(())
}

fn payload(run_id: [u8; 16]) -> Vec<u8> {
    let seed = [b"volparossa-a08:".as_slice(), run_id.as_slice()].concat();
    seed.iter().copied().cycle().take(PAYLOAD_BYTES).collect()
}

fn write_server_evidence(
    path: &Path,
    listen: SocketAddr,
    evidence: &ServerEvidence,
) -> FixtureResult<()> {
    write_json_replace(
        path,
        &json!({
            "schema_version": 1,
            "listen": {"ip": listen.ip().to_string(), "port": listen.port()},
            "hostname": SERVER_NAME,
            "accepted_connections": evidence.accepted_connections,
            "successful_exchanges": evidence.successful_exchanges,
            "failed_connections": evidence.failed_connections,
            "request_bytes": evidence.request_bytes,
            "request_sha256": evidence.request_sha256,
            "response_bytes": evidence.response_bytes,
            "response_sha256": evidence.response_sha256,
            "last_source": evidence.last_source.map(|source| json!({
                "ip": source.ip().to_string(), "port": source.port()
            })),
        }),
    )
}

fn write_json_new(path: &Path, value: &Value) -> FixtureResult<()> {
    let bytes = serde_json::to_vec(value)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn write_json_replace(path: &Path, value: &Value) -> FixtureResult<()> {
    let temporary = path.with_extension("json.new");
    if temporary.try_exists()? {
        fs::remove_file(&temporary)?;
    }
    write_json_new(&temporary, value)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
