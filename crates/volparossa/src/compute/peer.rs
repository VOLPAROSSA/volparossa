//! Explicit public tasks on independently selected peers, never private prompt offload.

mod batch;

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use volparossa_content::provider::compute::dataset::verify_source;
use volparossa_local_control::{
    ComputeAttachRequest, ComputeRemoteRequest, compute as rpc, control_request::Operation,
    control_response::Payload,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Explicitly advertise a provisioned local broker via the existing policy-protected service.
    Attach(Attach),
    /// Ask a selected peer for its current fixed model and available worker slot.
    Capabilities(Provider),
    /// Submit selected rows from an independently authenticated public dataset.
    Submit(Submit),
    /// Read a job using its retained full binding, not merely an identifier.
    Poll(Handle),
    /// Request cancellation; only a terminal response proves that the worker stopped.
    Cancel(Handle),
    /// Execute independent public questions concurrently across selected compatible peers.
    Distribute(batch::Options),
}

#[derive(Debug, Args)]
pub(crate) struct Attach {
    #[arg(long)]
    broker_socket: PathBuf,
    #[arg(long)]
    bind: std::net::SocketAddr,
    #[arg(long)]
    advertised_hostname: String,
    /// Explicit trust, never adopted from a peer's submitted source.
    #[arg(long, required = true, value_parser = parse_key)]
    trusted_dataset_publisher: Vec<VerifyingKey>,
}

#[derive(Debug, Args)]
pub(crate) struct Provider {
    /// Independently authenticated provider identity, not an arbitrary destination address.
    #[arg(long, value_parser = parse_key)]
    provider_key: VerifyingKey,
}

#[derive(Debug, Args)]
struct Source {
    #[arg(long)]
    dataset: PathBuf,
    #[arg(long)]
    dataset_manifest: PathBuf,
    #[arg(long, value_parser = parse_key)]
    publisher_key: VerifyingKey,
}

#[derive(Debug, Args)]
pub(crate) struct Submit {
    #[command(flatten)]
    provider: Provider,
    #[command(flatten)]
    source: Source,
    /// Increasing original inference row indices (zero based); repeated flag.
    #[arg(long, required = true)]
    row: Vec<u16>,
    /// New handle, saved before admission so a lost reply can be polled safely.
    #[arg(long)]
    handle: PathBuf,
    /// Bound for this worker lease, not for future multi-step workflows.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Without this flag only inspect the source and preview the exact rows to export.
    #[arg(long)]
    execute: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Handle {
    #[arg(long)]
    handle: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobHandle {
    version: u32,
    provider_key: String,
    binding: rpc::JobBinding,
    capabilities: rpc::Capabilities,
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = match command {
        Command::Attach(args) => {
            ensure!(
                args.broker_socket.is_absolute(),
                "compute_peer_broker_absolute_path"
            );
            crate::print_response(
                crate::control::request(
                    socket,
                    Operation::ComputeAttach(ComputeAttachRequest {
                        broker_socket: args
                            .broker_socket
                            .to_str()
                            .context("compute_peer_socket_utf8")?
                            .into(),
                        bind_address: args.bind.to_string(),
                        advertised_hostname: args.advertised_hostname,
                        trusted_dataset_publishers: args
                            .trusted_dataset_publisher
                            .iter()
                            .map(|key| key.to_bytes().to_vec())
                            .collect(),
                    }),
                )
                .await?,
            )?;
            return Ok(());
        }
        Command::Capabilities(provider) => {
            serde_json::to_value(capabilities(socket, &provider.provider_key).await?)?
        }
        Command::Submit(args) => submit(socket, &args).await?,
        Command::Poll(args) => poll_or_cancel(socket, &args, false).await?,
        Command::Cancel(args) => poll_or_cancel(socket, &args, true).await?,
        Command::Distribute(args) => return batch::run(&args, socket).await,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn source(
    args: &Source,
) -> Result<(
    rpc::PublicDataset,
    volparossa_content::provider::compute::dataset::VerifiedPublicDataset,
)> {
    let manifest = read_file(&args.dataset_manifest, 64 * 1024)?;
    let dataset_json = String::from_utf8(read_file(&args.dataset, rpc::MAX_DATASET_BYTES)?)?;
    let verified = verify_source(&manifest, &args.publisher_key, &dataset_json, now()?)?;
    Ok((
        rpc::PublicDataset {
            publisher_key: hex::encode(args.publisher_key.to_bytes()),
            manifest_hex: hex::encode(manifest),
            dataset_json,
        },
        verified,
    ))
}

async fn submit(socket: &Path, args: &Submit) -> Result<serde_json::Value> {
    let (publication, source) = source(&args.source)?;
    let dataset_json = source.derive(&args.row)?;
    if !args.execute {
        return Ok(
            serde_json::json!({"operation":"compute_peer_submit_plan","execute":false,
            "dataset_manifest_id":hex::encode(source.manifest_id()),"row_indices":args.row,
            "private_data_supported":false,"new_handle":args.handle}),
        );
    }
    let caps = capabilities(socket, &args.provider.provider_key).await?;
    ensure!(caps.accepting_work, "compute_peer_busy");
    let binding = binding(
        &source,
        args.row.clone(),
        &dataset_json,
        &caps,
        u64::from(args.max_seconds),
    )?;
    let handle = JobHandle {
        version: 1,
        provider_key: hex::encode(args.provider.provider_key.to_bytes()),
        binding: binding.clone(),
        capabilities: caps,
    };
    save_new(&args.handle, &handle)?;
    let outcome = exchange(
        socket,
        &args.provider.provider_key,
        rpc::Operation::Submit(rpc::Submit {
            binding,
            dataset_json,
            publication,
        }),
    )
    .await?;
    let status = job(outcome, &handle)?;
    Ok(serde_json::to_value(status)?)
}

async fn poll_or_cancel(socket: &Path, args: &Handle, cancel: bool) -> Result<serde_json::Value> {
    let handle: JobHandle = serde_json::from_slice(&read_file(&args.handle, 16 * 1024)?)?;
    ensure!(handle.version == 1, "compute_peer_handle_version");
    let provider = parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
    let operation = if cancel {
        rpc::Operation::Cancel(handle.binding.clone())
    } else {
        rpc::Operation::Poll(handle.binding.clone())
    };
    Ok(serde_json::to_value(job(
        exchange(socket, &provider, operation).await?,
        &handle,
    )?)?)
}

fn binding(
    source: &volparossa_content::provider::compute::dataset::VerifiedPublicDataset,
    rows: Vec<u16>,
    data: &str,
    caps: &rpc::Capabilities,
    max_seconds: u64,
) -> Result<rpc::JobBinding> {
    let time = now()?;
    let expires = source
        .expires()
        .min(time.saturating_add(max_seconds.min(caps.max_job_seconds)));
    ensure!(expires > time, "compute_peer_source_expired");
    Ok(rpc::JobBinding {
        job_id: nonce()?,
        dataset_manifest_id: hex::encode(source.manifest_id()),
        dataset_sha256: sha(data.as_bytes()),
        model_fingerprint: caps.model_fingerprint.clone(),
        row_indices: rows,
        expires_unix_seconds: expires,
    })
}

async fn capabilities(socket: &Path, provider: &VerifyingKey) -> Result<rpc::Capabilities> {
    use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
    let rpc::Outcome::Capabilities(caps) =
        exchange(socket, provider, rpc::Operation::Capabilities).await?
    else {
        anyhow::bail!("compute_peer_capabilities_unavailable");
    };
    ensure!(
        caps.public_inference_only
            && caps.runtime_slots == 1
            && caps.max_threads <= 2
            && (1..=600).contains(&caps.max_job_seconds)
            && (1..=4).contains(&caps.max_rows)
            && caps.model.model_id == MODEL_ID
            && caps.model.model_revision == MODEL_REVISION
            && caps.model.base_weights.sha256 == hex::encode(BASE_MODEL_SHA256)
            && caps.model_fingerprint == sha(&serde_json::to_vec(&caps.model)?),
        "compute_peer_profile"
    );
    Ok(caps)
}

async fn exchange(
    socket: &Path,
    provider: &VerifyingKey,
    operation: rpc::Operation,
) -> Result<rpc::Outcome> {
    timeout(Duration::from_secs(150), async {
        let (mut stream, id, response) = crate::control::begin_request(
            socket,
            Operation::ComputeRemote(ComputeRemoteRequest {
                provider_key: provider.to_bytes().to_vec(),
            }),
        )
        .await?;
        ensure!(
            response.diagnostic_code == "COMPUTE_RPC_READY",
            "compute_peer_readiness"
        );
        let Some(Payload::ComputeReady(ready)) = response.payload else {
            anyhow::bail!("compute_peer_readiness_payload")
        };
        ensure!(
            ready.provider_key == provider.as_bytes(),
            "compute_peer_readiness_provider"
        );
        let request = rpc::Request {
            version: rpc::VERSION,
            request_id: nonce()?,
            requester_key: hex::encode(ready.requester_key),
            operation,
        };
        request.validate(now()?)?;
        rpc::write_request(&mut stream, &request).await?;
        let result = rpc::read_response(&mut stream, &request.request_id).await?;
        let final_response = crate::control::finish_request(&mut stream, &id).await?;
        ensure!(
            final_response.diagnostic_code == "COMPUTE_RPC_OK"
                && matches!(final_response.payload, Some(Payload::Ack(_))),
            "compute_peer_final_handoff"
        );
        Ok(result.outcome)
    })
    .await
    .context("compute_peer_exchange_timeout")?
}

fn job(outcome: rpc::Outcome, handle: &JobHandle) -> Result<rpc::JobStatus> {
    let rpc::Outcome::Job(status) = outcome else {
        anyhow::bail!("compute_peer_job_rejected")
    };
    ensure!(status.binding == handle.binding, "compute_peer_job_binding");
    if status.state == rpc::JobState::Complete {
        let json = status
            .report_json
            .as_ref()
            .context("compute_peer_missing_report")?;
        ensure!(
            json.len() <= rpc::MAX_REPORT_BYTES
                && status.report_sha256.as_deref() == Some(sha(json.as_bytes()).as_str()),
            "compute_peer_report_hash"
        );
        let report: serde_json::Value = serde_json::from_str(json)?;
        super::broker::checked_report(&report, &handle.binding, &handle.capabilities)?;
    } else {
        ensure!(
            status.report_json.is_none() && status.report_sha256.is_none(),
            "compute_peer_noncomplete_report"
        );
    }
    Ok(status)
}

fn parse_key(value: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| "compute_public_key_hex")?
        .try_into()
        .map_err(|_| "compute_public_key_length")?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "compute_public_key_invalid".into())
}

fn nonce() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("compute_peer_randomness"))?;
    Ok(hex::encode(bytes))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "compute_peer_regular_bounded_file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "compute_peer_file_bound");
    Ok(bytes)
}

fn save_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("compute_peer_output_parent")?;
    super::private_directory(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut file, value)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|error| error.error)
        .context("compute_peer_new_handle_required")?;
    Ok(())
}
