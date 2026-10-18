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
    path::PathBuf,
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
    crate::compute::private_directory(options.socket.parent().context("resident_socket_parent")?)?;
    let info = std::fs::symlink_metadata(&options.socket)?;
    ensure!(
        info.file_type().is_socket() && info.uid() == nix::unistd::geteuid().as_raw(),
        "resident_socket_owner"
    );
    let (connector, spki) = client_config(crate::compute::read_file(&options.certificate, 8192)?)?;
    let stream = timeout_at(deadline, UnixStream::connect(&options.socket)).await??;
    ensure!(
        stream.peer_cred()?.uid() == nix::unistd::geteuid().as_raw(),
        "resident_socket_peer"
    );
    let tls = timeout_at(
        deadline.min(Instant::now() + Duration::from_secs(30)),
        connector.connect("resident.test".try_into()?, stream),
    )
    .await??;
    let report = exchange(tls, &key, workload, spki, deadline).await?;
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

fn result(frame: &wire::Frame, expected_text: &str) -> Result<Value> {
    let value = crate::compute::private_conversation::decode_worker_message(&frame.body)?;
    ensure!(
        value["version"] == 2
            && value["execution_complete"] == true
            && value["turn_complete"] == true
            && value["model_profile"] == "qwen3-4b-instruct-2507-v1"
            && value["output"]["type"] == "assistant"
            && value["output"]["text"]
                .as_str()
                .is_some_and(|text| text.trim() == expected_text)
            && value["prompt_tokens"]
                .as_u64()
                .is_some_and(|count| (1..=12_288).contains(&count))
            && value["generated_tokens"]
                .as_u64()
                .is_some_and(|count| (1..=1024).contains(&count))
            && value["cleanup"]
                == json!({"version":2,"request_files_removed":true,"session_closed":false,"session_private_state_retained":true}),
        "resident_public_trial_result"
    );
    // Project only fixed public answers and counters, not a claim of general model
    // quality, hardware attestation or confidentiality from the guest operator.
    Ok(
        json!({"sequence":frame.sequence,"answer":value["output"]["text"],
        "prompt_tokens":value["prompt_tokens"],"generated_tokens":value["generated_tokens"],
        "per_turn_cleanup":value["cleanup"]}),
    )
}

fn check_peer_key(certificate: &[u8], expected: [u8; 32]) -> Result<()> {
    let leaf = x509_cert::Certificate::from_der(certificate)?;
    let actual: [u8; 32] =
        Sha256::digest(leaf.tbs_certificate.subject_public_key_info.to_der()?).into();
    ensure!(actual == expected, "resident_peer_key_pin");
    Ok(())
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut tls: TlsStream<S>,
    key: &SigningKey,
    workload: [u8; 32],
    spki: [u8; 32],
    deadline: Instant,
) -> Result<Value> {
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
    let challenge = wire::read(&mut tls, admission).await?;
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let signed = grant(&challenge, key, workload, spki, exporter, now_ms, deadline)?;
    wire::write(&mut tls, wire::frame(wire::GRANT, 0, signed), admission).await?;
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
        wire::write(
            &mut tls,
            wire::frame(wire::SUBMIT, sequence, input),
            deadline,
        )
        .await?;
        ensure!(
            expected(&mut tls, wire::ADMITTED, sequence, deadline)
                .await?
                .body
                .is_empty(),
            "resident_admitted_payload"
        );
        let frame = expected(&mut tls, wire::RESULT, sequence, deadline).await?;
        results.push(result(&frame, ["READY", "4"][index])?);
    }
    wire::write(&mut tls, wire::frame(wire::CLOSE, 3, vec![]), deadline).await?;
    let closed = expected(&mut tls, wire::CLOSED, 3, deadline).await?;
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
