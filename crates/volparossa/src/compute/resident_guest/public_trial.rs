//! Public fixture requester. Fixed input, explicit guest certificate, no private admission.

#[cfg(test)]
mod tests;

use super::{ALPN, EXPORTER, digest, wire};
use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::SigningKey;
use prost::Message as _;
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
    time::{Instant, timeout_at},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use volparossa_content::provider::compute::resident_task::{
    GrantBackend, GrantLimits, GrantModel, GrantSpec, sign,
};
use x509_cert::der::{Decode as _, Encode as _};
use zeroize::Zeroizing;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Same-owner QEMU Unix channel in an existing private directory.
    #[arg(long)]
    socket: PathBuf,
    /// Exact owner-selected public fixture certificate; not attestation evidence.
    #[arg(long)]
    certificate: PathBuf,
    /// Ephemeral public-trial signing seed: exactly 32 raw bytes, owner mode 0600.
    #[arg(long)]
    requester_key: PathBuf,
    #[arg(long)]
    workload_sha256: String,
    /// Without this flag emit the fixed-input policy without connecting.
    #[arg(long)]
    execute: bool,
    /// Fixed attempt-stage diagnostics for this public fixture only; never raw errors.
    #[arg(long, requires = "execute")]
    diagnostic_stages: bool,
}

#[derive(Clone, Copy)]
enum Stage {
    Configuration,
    Socket,
    Certificate,
    Connect,
    Tls,
    TlsProfile,
    Challenge,
    Grant,
    Accepted,
    Turn1Submit,
    Turn1Admitted,
    Turn1Result,
    Turn2Submit,
    Turn2Admitted,
    Turn2Result,
    Close,
    Closed,
    Cleanup,
}

impl Stage {
    fn marker(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Socket => "socket",
            Self::Certificate => "certificate",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::TlsProfile => "tls_profile",
            Self::Challenge => "challenge",
            Self::Grant => "grant",
            Self::Accepted => "accepted",
            Self::Turn1Submit => "turn_1_submit",
            Self::Turn1Admitted => "turn_1_admitted",
            Self::Turn1Result => "turn_1_result",
            Self::Turn2Submit => "turn_2_submit",
            Self::Turn2Admitted => "turn_2_admitted",
            Self::Turn2Result => "turn_2_result",
            Self::Close => "close",
            Self::Closed => "closed",
            Self::Cleanup => "cleanup",
        }
    }
}

fn observe_stage(enabled: bool, stage: Stage, mut output: impl std::io::Write) {
    if enabled {
        // Best effort only: a broken diagnostic sink cannot change protocol or
        // cleanup behavior. This marks entry, never successful stage completion.
        let _ = writeln!(output, "VP_PUBLIC_REQUESTER_STAGE_V1 {}", stage.marker());
    }
}

fn stage(enabled: bool, value: Stage) {
    if enabled {
        observe_stage(true, value, std::io::stderr().lock());
    }
}

// Failed preflight only, at the original rejection point. Neither this marker
// nor its enclosing stage establishes a connection, native execution or cleanup.
const MAX_SOCKET_DIAGNOSTIC: usize = 512;

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SocketCondition {
    ParentValidation,
    SocketMetadata,
    NotSocket,
    OwnerMismatch,
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SocketIoKind {
    None,
    NotFound,
    PermissionDenied,
    Interrupted,
    InvalidInput,
    InvalidData,
    Other,
}

fn socket_io_kind(error: &anyhow::Error) -> SocketIoKind {
    match error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
    {
        None => SocketIoKind::None,
        Some(std::io::ErrorKind::NotFound) => SocketIoKind::NotFound,
        Some(std::io::ErrorKind::PermissionDenied) => SocketIoKind::PermissionDenied,
        Some(std::io::ErrorKind::Interrupted) => SocketIoKind::Interrupted,
        Some(std::io::ErrorKind::InvalidInput) => SocketIoKind::InvalidInput,
        Some(std::io::ErrorKind::InvalidData) => SocketIoKind::InvalidData,
        Some(_) => SocketIoKind::Other,
    }
}

fn observe_socket_failure(
    enabled: bool,
    condition: SocketCondition,
    error: &anyhow::Error,
    mut output: impl std::io::Write,
) {
    if enabled {
        let value = json!({"version":1,"condition":condition,"io_kind":socket_io_kind(error)});
        let body = value.to_string();
        if body.len() <= MAX_SOCKET_DIAGNOSTIC {
            let _ = writeln!(output, "VP_PUBLIC_REQUESTER_SOCKET_FAILURE_V1 {body}");
        }
    }
}

// A separate failure-only observation after preflight, never a connection,
// authentication, execution or cleanup success receipt.
const MAX_CONNECT_DIAGNOSTIC: usize = 512;

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConnectCondition {
    ConnectDeadline,
    ConnectIo,
    PeerCredentialIo,
    PeerUidMismatch,
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConnectIoKind {
    None,
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    TimedOut,
    Interrupted,
    WouldBlock,
    InvalidInput,
    InvalidData,
    Other,
}

fn connect_io_kind(error: Option<&std::io::Error>) -> ConnectIoKind {
    match error.map(std::io::Error::kind) {
        None => ConnectIoKind::None,
        Some(std::io::ErrorKind::NotFound) => ConnectIoKind::NotFound,
        Some(std::io::ErrorKind::PermissionDenied) => ConnectIoKind::PermissionDenied,
        Some(std::io::ErrorKind::ConnectionRefused) => ConnectIoKind::ConnectionRefused,
        Some(std::io::ErrorKind::ConnectionReset) => ConnectIoKind::ConnectionReset,
        Some(std::io::ErrorKind::ConnectionAborted) => ConnectIoKind::ConnectionAborted,
        Some(std::io::ErrorKind::NotConnected) => ConnectIoKind::NotConnected,
        Some(std::io::ErrorKind::AddrInUse) => ConnectIoKind::AddrInUse,
        Some(std::io::ErrorKind::AddrNotAvailable) => ConnectIoKind::AddrNotAvailable,
        Some(std::io::ErrorKind::TimedOut) => ConnectIoKind::TimedOut,
        Some(std::io::ErrorKind::Interrupted) => ConnectIoKind::Interrupted,
        Some(std::io::ErrorKind::WouldBlock) => ConnectIoKind::WouldBlock,
        Some(std::io::ErrorKind::InvalidInput) => ConnectIoKind::InvalidInput,
        Some(std::io::ErrorKind::InvalidData) => ConnectIoKind::InvalidData,
        Some(_) => ConnectIoKind::Other,
    }
}

fn observe_connect_failure(
    enabled: bool,
    condition: ConnectCondition,
    error: Option<&std::io::Error>,
    mut output: impl std::io::Write,
) {
    if enabled {
        let value = json!({"version":1,"condition":condition,"io_kind":connect_io_kind(error)});
        let body = value.to_string();
        if body.len() <= MAX_CONNECT_DIAGNOSTIC {
            let _ = writeln!(output, "VP_PUBLIC_REQUESTER_CONNECT_FAILURE_V1 {body}");
        }
    }
}

fn check_peer_uid(
    credential: std::io::Result<u32>,
    owner: u32,
    mut observe: impl FnMut(ConnectCondition, Option<&std::io::Error>),
) -> Result<()> {
    let uid =
        credential.inspect_err(|error| observe(ConnectCondition::PeerCredentialIo, Some(error)))?;
    if uid != owner {
        observe(ConnectCondition::PeerUidMismatch, None);
    }
    ensure!(uid == owner, "resident_socket_peer");
    Ok(())
}

async fn connect_socket(
    socket: &Path,
    deadline: Instant,
    mut observe: impl FnMut(ConnectCondition, Option<&std::io::Error>),
) -> Result<UnixStream> {
    let stream = timeout_at(deadline, UnixStream::connect(socket))
        .await
        .inspect_err(|_| observe(ConnectCondition::ConnectDeadline, None))?
        .inspect_err(|error| observe(ConnectCondition::ConnectIo, Some(error)))?;
    check_peer_uid(
        stream.peer_cred().map(|credential| credential.uid()),
        nix::unistd::geteuid().as_raw(),
        observe,
    )?;
    Ok(stream)
}

fn socket_preflight(
    socket: &Path,
    owner: u32,
    mut observe: impl FnMut(SocketCondition, &anyhow::Error),
) -> Result<()> {
    let parent = socket.parent().context("resident_socket_parent");
    let parent = parent.inspect_err(|error| observe(SocketCondition::ParentValidation, error))?;
    crate::compute::private_directory(parent)
        .inspect_err(|error| observe(SocketCondition::ParentValidation, error))?;
    let info = std::fs::symlink_metadata(socket)
        .map_err(anyhow::Error::from)
        .inspect_err(|error| observe(SocketCondition::SocketMetadata, error))?;
    // Keep the original combined guard and its error. The observation uses the
    // same metadata, without another filesystem read or a weaker owner check.
    socket_metadata(&info, owner).inspect_err(|error| {
        observe(
            if info.file_type().is_socket() {
                SocketCondition::OwnerMismatch
            } else {
                SocketCondition::NotSocket
            },
            error,
        );
    })
}

fn socket_metadata(info: &std::fs::Metadata, owner: u32) -> Result<()> {
    ensure!(
        info.file_type().is_socket() && info.uid() == owner,
        "resident_socket_owner"
    );
    Ok(())
}

pub(super) fn inputs() -> Result<[Vec<u8>; 2]> {
    let turn = |question| {
        serde_json::to_vec(&json!({
            "version":1,"visibility":"private_local",
            "instructions":"Follow the public test instruction. Give only the requested answer.",
            "history":[{"type":"message","role":"user","text":question}],
            "tools":[],"generation_policy":"greedy_v1"
        }))
    };
    // private_local is the worker's internal schema, not permission to export
    // private data. There is deliberately no input-path or prompt CLI option.
    Ok([
        turn("Reply with the single word READY.")?,
        turn("What is 2 + 2? Reply with the digit only.")?,
    ])
}

fn policy(key: &SigningKey, workload: [u8; 32]) -> Result<Value> {
    Ok(json!({"version":1,"visibility":"public_fixture",
        "requester_key":hex::encode(key.verifying_key().to_bytes()),
        "workload_sha256":hex::encode(workload),
        "public_input_sha256":inputs()?.map(|bytes| hex::encode(Sha256::digest(bytes)))}))
}

fn client_config(certificate: Vec<u8>) -> Result<(TlsConnector, [u8; 32])> {
    ensure!(certificate.len() <= 8192, "resident_certificate_size");
    let parsed = x509_cert::Certificate::from_der(&certificate)?;
    let spki = Sha256::digest(parsed.tbs_certificate.subject_public_key_info.to_der()?).into();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate))?;
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = false;
    Ok((TlsConnector::from(Arc::new(config)), spki))
}

pub(in crate::compute) async fn run(options: Options) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2400);
    let diagnostics = options.diagnostic_stages && options.execute;
    stage(diagnostics, Stage::Configuration);
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let workload = digest(&options.workload_sha256)?;
    let info = std::fs::symlink_metadata(&options.requester_key)?;
    ensure!(info.mode() & 0o777 == 0o600, "resident_requester_key_mode");
    let seed = Zeroizing::new(crate::compute::read_file(&options.requester_key, 32)?);
    let key = SigningKey::from_bytes(
        seed.as_slice()
            .try_into()
            .context("resident_requester_key")?,
    );
    if !options.execute {
        println!("{}", policy(&key, workload)?);
        return Ok(());
    }
    stage(diagnostics, Stage::Socket);
    socket_preflight(
        &options.socket,
        nix::unistd::geteuid().as_raw(),
        |condition, error| {
            if diagnostics {
                observe_socket_failure(true, condition, error, std::io::stderr().lock());
            }
        },
    )?;
    stage(diagnostics, Stage::Certificate);
    let (connector, spki) = client_config(crate::compute::read_file(&options.certificate, 8192)?)?;
    stage(diagnostics, Stage::Connect);
    let stream = connect_socket(&options.socket, deadline, |condition, error| {
        if diagnostics {
            observe_connect_failure(true, condition, error, std::io::stderr().lock());
        }
    })
    .await?;
    stage(diagnostics, Stage::Tls);
    let tls = timeout_at(
        deadline.min(Instant::now() + Duration::from_secs(30)),
        connector.connect("resident.test".try_into()?, stream),
    )
    .await??;
    let report = exchange(tls, &key, workload, spki, deadline, diagnostics).await?;
    println!("{report}");
    Ok(())
}

fn grant(
    challenge: &wire::Frame,
    key: &SigningKey,
    workload: [u8; 32],
    spki: [u8; 32],
    exporter: [u8; 32],
    now_ms: u64,
    deadline: Instant,
) -> Result<Vec<u8>> {
    ensure!(
        challenge.kind == wire::CHALLENGE && challenge.sequence == 0,
        "resident_challenge_frame"
    );
    let value = wire::Challenge::decode(challenge.body.as_slice())?;
    ensure!(
        value.encode_to_vec() == challenge.body,
        "resident_challenge_canonical"
    );
    ensure!(
        value.issued_at_ms.abs_diff(now_ms) <= 30_000
            && value.maximum_expires_at_ms > now_ms
            && value
                .maximum_expires_at_ms
                .checked_sub(value.issued_at_ms)
                .is_some_and(|d| (1..=2_400_000).contains(&d)),
        "resident_challenge_time"
    );
    let remaining = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )?;
    ensure!(remaining > 0, "resident_requester_deadline");
    // The guest anchors before sending its challenge. Adding only the remaining
    // parent duration to that earlier anchor is conservative even with clock skew.
    let expires_at_ms = value.maximum_expires_at_ms.min(
        value
            .issued_at_ms
            .checked_add(remaining)
            .context("resident_requester_deadline")?,
    );
    Ok(sign(
        key,
        &GrantSpec {
            requester_key: key.verifying_key().to_bytes(),
            guest_tls_spki_sha256: spki,
            workload_sha256: workload,
            model: GrantModel::Qwen3FourBInstruct2507,
            backend: GrantBackend::LlamaCppBf16V1,
            nonce: value
                .nonce
                .try_into()
                .map_err(|_| anyhow::anyhow!("resident_challenge_nonce"))?,
            tls_exporter: exporter,
            issued_at_ms: value.issued_at_ms,
            expires_at_ms,
            limits: GrantLimits {
                maximum_requests: 2,
                maximum_turn_seconds: 600,
                threads: 2,
            },
            public_input_sha256: inputs()?.map(|bytes| Sha256::digest(bytes).into()),
        },
    )?)
}

async fn expected<S: AsyncRead + Unpin>(
    stream: &mut S,
    kind: u32,
    sequence: u32,
    deadline: Instant,
) -> Result<wire::Frame> {
    let frame = wire::read(stream, deadline).await?;
    ensure!(
        frame.kind == kind && frame.sequence == sequence,
        "resident_reply_order"
    );
    Ok(frame)
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultFailure {
    ReadDeadline,
    ReadBound,
    ReadFrame,
    ReadEof,
    ReadIo,
    ReadOther,
    ReplyOrder,
    FailureFrame,
    GuestFailure,
    ResultJson,
    ResultCompletion,
    ResultProfile,
    ResultOutput,
    ResultAnswer,
    ResultTokens,
    ResultCleanup,
}

impl std::fmt::Display for ResultFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("resident_public_trial_result")
    }
}
impl std::error::Error for ResultFailure {}

fn observe_result_failure(
    enabled: bool,
    sequence: u32,
    category: ResultFailure,
    guest: Option<&Value>,
    mut output: impl std::io::Write,
) {
    if enabled && (1..=2).contains(&sequence) {
        let value = json!({"version":1,"turn":sequence,"category":category,"guest":guest});
        // Every field is locally closed or a validated public-fixture frame.
        // Sink errors never replace the execution error or trigger another exchange.
        let _ = writeln!(output, "VP_PUBLIC_REQUESTER_FAILURE_V1 {value}");
    }
}

fn result_failure(enabled: bool, sequence: u32, category: ResultFailure, guest: Option<&Value>) {
    if enabled {
        observe_result_failure(true, sequence, category, guest, std::io::stderr().lock());
    }
}

fn read_failure(error: &anyhow::Error) -> ResultFailure {
    if let Some(error) = error.downcast_ref::<wire::ReadFailure>() {
        return match error {
            wire::ReadFailure::Deadline => ResultFailure::ReadDeadline,
            wire::ReadFailure::Bound => ResultFailure::ReadBound,
            wire::ReadFailure::Encoding => ResultFailure::ReadFrame,
        };
    }
    match error.downcast_ref::<std::io::Error>() {
        Some(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => ResultFailure::ReadEof,
        Some(_) => ResultFailure::ReadIo,
        None => ResultFailure::ReadOther,
    }
}

async fn turn_result<S: AsyncRead + Unpin>(
    stream: &mut S,
    sequence: u32,
    deadline: Instant,
    diagnostics: bool,
) -> Result<wire::Frame> {
    let frame = wire::read(stream, deadline).await.inspect_err(|error| {
        result_failure(diagnostics, sequence, read_failure(error), None);
    })?;
    if frame.kind == wire::FAILURE {
        match wire::failure_body(&frame, sequence) {
            Ok(value) => result_failure(
                diagnostics,
                sequence,
                ResultFailure::GuestFailure,
                Some(&value),
            ),
            Err(_) => result_failure(diagnostics, sequence, ResultFailure::FailureFrame, None),
        }
        anyhow::bail!("resident_public_trial_guest_failed");
    }
    if frame.kind != wire::RESULT || frame.sequence != sequence {
        result_failure(diagnostics, sequence, ResultFailure::ReplyOrder, None);
        anyhow::bail!("resident_reply_order");
    }
    Ok(frame)
}

fn result(frame: &wire::Frame, expected_text: &str) -> Result<Value> {
    let value = crate::compute::private_conversation::decode_worker_message(&frame.body)
        .map_err(|_| ResultFailure::ResultJson)?;
    ensure!(
        value["version"] == 2
            && value["execution_complete"] == true
            && value["turn_complete"] == true,
        ResultFailure::ResultCompletion
    );
    ensure!(
        value["model_profile"] == "qwen3-4b-instruct-2507-v1",
        ResultFailure::ResultProfile
    );
    ensure!(
        value["output"]["type"] == "assistant",
        ResultFailure::ResultOutput
    );
    ensure!(
        value["output"]["text"]
            .as_str()
            .is_some_and(|text| text.trim() == expected_text),
        ResultFailure::ResultAnswer
    );
    ensure!(
        value["prompt_tokens"]
            .as_u64()
            .is_some_and(|count| (1..=12_288).contains(&count))
            && value["generated_tokens"]
                .as_u64()
                .is_some_and(|count| (1..=1024).contains(&count)),
        ResultFailure::ResultTokens
    );
    ensure!(
        value["cleanup"]
            == json!({"version":2,"request_files_removed":true,
        "session_closed":false,"session_private_state_retained":true}),
        ResultFailure::ResultCleanup
    );
    // Original public success projection and predicates remain unchanged.
    Ok(
        json!({"sequence":frame.sequence,"answer":value["output"]["text"],
        "prompt_tokens":value["prompt_tokens"],"generated_tokens":value["generated_tokens"],
        "per_turn_cleanup":value["cleanup"]}),
    )
}

fn check_peer_key(certificate: &[u8], expected: [u8; 32]) -> Result<()> {
    let leaf = x509_cert::Certificate::from_der(certificate)
        .map_err(|_| anyhow::anyhow!("resident_peer_certificate_decode"))?;
    let public_key = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| anyhow::anyhow!("resident_peer_spki_encode"))?;
    let actual: [u8; 32] = Sha256::digest(public_key).into();
    ensure!(actual == expected, "resident_peer_key_pin");
    Ok(())
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut tls: TlsStream<S>,
    key: &SigningKey,
    workload: [u8; 32],
    spki: [u8; 32],
    deadline: Instant,
    diagnostics: bool,
) -> Result<Value> {
    stage(diagnostics, Stage::TlsProfile);
    ensure!(
        tls.get_ref().1.alpn_protocol() == Some(ALPN)
            && tls.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3),
        "resident_tls_profile"
    );
    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .context("resident_peer_certificate")?;
    check_peer_key(peer.as_ref(), spki)?;
    let exporter = tls
        .get_ref()
        .1
        .export_keying_material([0; 32], EXPORTER, None)?;
    let admission = deadline.min(Instant::now() + Duration::from_secs(30));
    stage(diagnostics, Stage::Challenge);
    let challenge = wire::read(&mut tls, admission).await?;
    stage(diagnostics, Stage::Grant);
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let signed = grant(&challenge, key, workload, spki, exporter, now_ms, deadline)?;
    wire::write(&mut tls, wire::frame(wire::GRANT, 0, signed), admission).await?;
    stage(diagnostics, Stage::Accepted);
    ensure!(
        expected(&mut tls, wire::ACCEPTED, 0, admission)
            .await?
            .body
            .is_empty(),
        "resident_accept_payload"
    );
    let mut results = Vec::with_capacity(2);
    for (index, input) in inputs()?.into_iter().enumerate() {
        let sequence = u32::try_from(index + 1)?;
        let [submit, admitted, result_stage] = [
            [Stage::Turn1Submit, Stage::Turn1Admitted, Stage::Turn1Result],
            [Stage::Turn2Submit, Stage::Turn2Admitted, Stage::Turn2Result],
        ][index];
        stage(diagnostics, submit);
        wire::write(
            &mut tls,
            wire::frame(wire::SUBMIT, sequence, input),
            deadline,
        )
        .await?;
        stage(diagnostics, admitted);
        ensure!(
            expected(&mut tls, wire::ADMITTED, sequence, deadline)
                .await?
                .body
                .is_empty(),
            "resident_admitted_payload"
        );
        stage(diagnostics, result_stage);
        let frame = turn_result(&mut tls, sequence, deadline, diagnostics).await?;
        let value = result(&frame, ["READY", "4"][index]).inspect_err(|error| {
            let category = error
                .downcast_ref::<ResultFailure>()
                .copied()
                .unwrap_or(ResultFailure::ResultJson);
            result_failure(diagnostics, sequence, category, None);
        })?;
        results.push(value);
    }
    stage(diagnostics, Stage::Close);
    wire::write(&mut tls, wire::frame(wire::CLOSE, 3, vec![]), deadline).await?;
    stage(diagnostics, Stage::Closed);
    let closed = expected(&mut tls, wire::CLOSED, 3, deadline).await?;
    stage(diagnostics, Stage::Cleanup);
    let cleanup = crate::compute::private_conversation::decode_worker_message(&closed.body)?;
    ensure!(
        cleanup == json!({"version":1,"child_reaped":true,"private_state_removed":true}),
        "resident_cleanup_unconfirmed"
    );
    Ok(
        json!({"version":1,"kind":"public_resident_requester","public_fixture_only":true,
        "workload_sha256":hex::encode(workload),"tls_spki_sha256":hex::encode(spki),
        "turns":results,"final_cleanup":cleanup,"private_inputs":false,
        "hardware_attestation":false,"guest_key_origin_proven":false,"production_approval":false}),
    )
}
