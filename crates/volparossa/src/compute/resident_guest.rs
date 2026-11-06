//! Public-input fixture on a guest-terminated TLS session and a finite signed grant.
//! This does not appraise a TEE, attest key origin, or admit private peer inputs.

mod port;
pub(super) mod public_trial;
mod session;
#[cfg(test)]
mod tests;
mod wire;

use anyhow::{Result, ensure};
use clap::Args;
use prost::Message as _;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use volparossa_content::provider::compute::resident_task::{
    GrantBackend, GrantExpectations, GrantLimits, GrantModel, GrantVerifier,
};
use x509_cert::der::{Decode as _, Encode as _};

use super::{ModelProfile, native_cpu, private_task, supervise::native_session};

const ALPN: &[u8] = b"volparossa-public-resident/1";
const EXPORTER: &[u8] = b"EXPORTER-VOLPAROSSA-PUBLIC-RESIDENT-V1";

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[arg(long)]
    runtime_root: PathBuf,
    #[arg(long)]
    model_root: PathBuf,
    #[arg(long)]
    work_parent: PathBuf,
    #[command(flatten)]
    native_backend: native_cpu::Options,
    /// Owner-approved public fixture policy, never a peer-supplied policy.
    #[arg(long)]
    public_policy: PathBuf,
    #[arg(long)]
    certificate: PathBuf,
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    execute: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u8,
    visibility: String,
    requester_key: String,
    workload_sha256: String,
    public_input_sha256: [String; 2],
}

impl Policy {
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 4096, "resident_policy_size");
        let policy: Self =
            serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("resident_policy"))?;
        ensure!(
            policy.version == 1 && policy.visibility == "public_fixture",
            "resident_policy_scope"
        );
        for value in [
            &policy.requester_key,
            &policy.workload_sha256,
            &policy.public_input_sha256[0],
            &policy.public_input_sha256[1],
        ] {
            digest(value)?;
        }
        Ok(policy)
    }
    fn expectations(&self, spki: [u8; 32], exporter: [u8; 32]) -> Result<GrantExpectations> {
        Ok(GrantExpectations {
            requester_key: digest(&self.requester_key)?,
            guest_tls_spki_sha256: spki,
            workload_sha256: digest(&self.workload_sha256)?,
            model: GrantModel::Qwen3FourBInstruct2507,
            backend: GrantBackend::LlamaCppBf16V1,
            tls_exporter: exporter,
            limits: GrantLimits {
                maximum_requests: 2,
                maximum_turn_seconds: 600,
                threads: 2,
            },
            public_input_sha256: [
                digest(&self.public_input_sha256[0])?,
                digest(&self.public_input_sha256[1])?,
            ],
        })
    }
}

fn digest(value: &str) -> Result<[u8; 32]> {
    ensure!(super::is_hex(value, 64), "resident_digest");
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)?;
    Ok(bytes)
}

fn tls_config(certificate: Vec<u8>, private_key: Vec<u8>) -> Result<(TlsAcceptor, [u8; 32])> {
    ensure!(
        certificate.len() <= 8192 && private_key.len() <= 8192,
        "resident_tls_size"
    );
    let parsed = x509_cert::Certificate::from_der(&certificate)
        .map_err(|_| anyhow::anyhow!("resident_certificate"))?;
    let spki = Sha256::digest(parsed.tbs_certificate.subject_public_key_info.to_der()?).into();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate)],
                PrivateKeyDer::try_from(private_key)
                    .map_err(|_| anyhow::anyhow!("resident_private_key"))?,
            )?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    Ok((TlsAcceptor::from(Arc::new(config)), spki))
}

pub(super) async fn run(options: Options) -> Result<()> {
    run_inner(options)
        .await
        .map_err(|_| anyhow::anyhow!("resident_public_guest_failed"))
}

async fn run_inner(options: Options) -> Result<()> {
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let policy = Policy::decode(&super::read_file(&options.public_policy, 4096)?)?;
    if !options.execute {
        println!(
            "{}",
            serde_json::json!({"version":1,"execute":false,"scope":"public_fixture_only","private_peer_admission":false,"maximum_requests":2})
        );
        return Ok(());
    }
    // Owner-readable secret only. read_file also rejects links/nonregular files.
    ensure!(
        std::fs::symlink_metadata(&options.private_key)?
            .permissions()
            .mode()
            & 0o777
            == 0o600,
        "resident_private_key_mode"
    );
    let (acceptor, spki) = tls_config(
        super::read_file(&options.certificate, 8192)?,
        super::read_file(&options.private_key, 8192)?,
    )?;
    let config = private_task::ExecutionConfig {
        runtime_root: options.runtime_root,
        model_root: options.model_root,
        work_parent: options.work_parent,
        model_profile: ModelProfile::Qwen4bInstruct2507,
        native_backend: options.native_backend,
        threads: 2,
        max_seconds: 600,
    };
    let stream = port::Port::open()?;
    serve(
        stream,
        acceptor,
        spki,
        policy,
        config,
        native_session::run_bounded,
    )
    .await
}

async fn serve<S, F, Fut>(
    stream: S,
    acceptor: TlsAcceptor,
    spki: [u8; 32],
    policy: Policy,
    mut config: private_task::ExecutionConfig,
    run: F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(
        Arc<private_task::ExecutionConfig>,
        tokio::sync::mpsc::Receiver<native_session::Command>,
        tokio::sync::mpsc::Sender<native_session::Event>,
        tokio::sync::watch::Receiver<bool>,
        native_session::SessionBudget,
    ) -> Fut,
    Fut: Future<Output = Result<serde_json::Value>> + Send + 'static,
{
    let admission_deadline = Instant::now() + Duration::from_secs(30);
    let mut tls = timeout_at(admission_deadline, acceptor.accept(stream)).await??;
    ensure!(
        tls.get_ref().1.alpn_protocol() == Some(ALPN)
            && tls.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3),
        "resident_tls_profile"
    );
    let exporter = tls
        .get_ref()
        .1
        .export_keying_material([0; 32], EXPORTER, None)?;
    let verifier = GrantVerifier::new(policy.expectations(spki, exporter)?)?;
    let challenge = wire::Challenge {
        nonce: verifier.nonce().to_vec(),
        issued_at_ms: verifier.issued_at_ms(),
        maximum_expires_at_ms: verifier.maximum_expires_at_ms(),
    };
    wire::write(
        &mut tls,
        wire::frame(wire::CHALLENGE, 0, challenge.encode_to_vec()),
        admission_deadline,
    )
    .await?;
    let grant = wire::read(&mut tls, admission_deadline).await?;
    ensure!(
        grant.kind == wire::GRANT && grant.sequence == 0,
        "resident_grant_frame"
    );
    let allowance = verifier.verify(&grant.body)?;
    let limits = allowance.limits();
    config.threads = limits.threads;
    config.max_seconds = limits.maximum_turn_seconds;
    let budget = native_session::SessionBudget::new(allowance.deadline(), limits.maximum_requests)?;
    // No worker can start before the authenticated acceptance is written.
    wire::write(
        &mut tls,
        wire::frame(wire::ACCEPTED, 0, vec![]),
        allowance.deadline(),
    )
    .await?;
    session::execute(tls, Arc::new(config), allowance, budget, run).await
}
