//! Publisher-local name resolution is not HTTPS authority or a globally latest version proof.

use std::{os::unix::fs::PermissionsExt as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use tokio::time::{Instant, timeout, timeout_at};
use volparossa_content::{
    SignedManifest, VerifiedManifest,
    provider::named::NameQuery,
    transfer::{TransferLimits, TransferProgress, pull_to_writer},
};
use volparossa_local_control::{
    ContentFetchNameRequest, ContentReceipt, control_request::Operation, control_response::Payload,
};

use super::{FetchName, absolute_path, ensure_new_output, now_seconds, output_parent};

pub(super) async fn run(args: &FetchName, socket: &Path) -> Result<()> {
    ensure_new_output(&args.local_output)?;
    let download = prepare(args, socket, output_parent(&args.local_output)).await?;
    let mut report = download.report();
    report["cache"] = serde_json::to_value(&args.cache)?;
    report["local_output"] = serde_json::to_value(&args.local_output)?;
    download.check_live()?;
    download
        .temporary
        .persist_noclobber(&args.local_output)
        .map_err(|error| error.error)
        .context("cannot publish named output without overwriting an existing entry")?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Created only after publisher/name validation, complete bytes and correlated final receipt.
pub(super) struct VerifiedNamedDownload {
    temporary: tempfile::NamedTempFile,
    manifest: VerifiedManifest,
    receipt: ContentReceipt,
    expires: u64,
    authority_deadline: Instant,
    cache_only: bool,
}

impl VerifiedNamedDownload {
    pub(super) fn as_file(&self) -> &std::fs::File {
        self.temporary.as_file()
    }

    pub(super) fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }

    pub(super) fn receipt(&self) -> &ContentReceipt {
        &self.receipt
    }

    pub(super) fn report(&self) -> serde_json::Value {
        let mut report = report(self.receipt(), self.manifest());
        report["cache_only"] = self.cache_only.into();
        report
    }

    pub(super) fn expires(&self) -> u64 {
        self.expires
    }

    pub(super) fn authority_deadline(&self) -> Instant {
        self.authority_deadline
    }

    pub(super) fn check_live(&self) -> Result<()> {
        if Instant::now() >= self.authority_deadline() || now_seconds()? >= self.expires() {
            bail!("publication expired before local output publication");
        }
        Ok(())
    }
}

pub(super) async fn prepare(
    args: &FetchName,
    socket: &Path,
    private_parent: &Path,
) -> Result<VerifiedNamedDownload> {
    timeout(
        Duration::from_secs(600),
        download(args, socket, private_parent),
    )
    .await
    .context("named download deadline exceeded; verified agent cache chunks may remain")?
}

async fn download(
    args: &FetchName,
    socket: &Path,
    private_parent: &Path,
) -> Result<VerifiedNamedDownload> {
    let query = NameQuery::new(
        args.publisher_key.to_bytes(),
        &args.name,
        args.min_revision.unwrap_or(0),
    )?;
    let request = ContentFetchNameRequest {
        publisher_key: args.publisher_key.to_bytes().to_vec(),
        name: args.name.clone(),
        min_revision: args.min_revision,
        cache: absolute_path(&args.cache)?,
        limits: Some(args.limits.wire_limits()),
        reuse_cache: args.reuse_cache,
        cache_only: args.cache_only,
    };
    let (mut stream, request_id, response) =
        crate::control::begin_request(socket, Operation::ContentFetchName(request)).await?;
    if response.diagnostic_code != "NAMED_CONTENT_TRANSFER_READY" {
        bail!("expected explicit publisher/name stream readiness");
    }
    let Some(Payload::NamedContentTransferReady(ready)) = response.payload else {
        bail!("expected same-operation named readiness");
    };
    if ready.cache_only != args.cache_only {
        bail!("named readiness changed the requested cache-only mode");
    }
    let manifest =
        query.verify_candidate(&SignedManifest::decode(&ready.manifest)?, now_seconds()?)?;
    let expires = manifest.validity().expires;
    let authority_observed_at = Instant::now();
    let remaining = expires
        .checked_sub(now_seconds()?)
        .filter(|seconds| *seconds > 0)
        .context("named publication expired before local delivery")?;
    let authority_deadline = authority_observed_at + Duration::from_secs(remaining);
    let deadline = authority_deadline.min(authority_observed_at + Duration::from_secs(30));
    let mut temporary = tempfile::NamedTempFile::new_in(private_parent)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let (progress, final_response) = timeout_at(deadline, async {
        let progress = pull_to_writer(
            &mut stream,
            &manifest,
            temporary.as_file_mut(),
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(30),
                max_requests: manifest.chunks().len().max(1),
                max_bytes: manifest.length().max(1),
            },
        )
        .await?;
        let response = crate::control::finish_request(&mut stream, &request_id).await?;
        Ok::<_, anyhow::Error>((progress, response))
    })
    .await
    .context("local named delivery expired or stalled")??;
    let Some(Payload::Content(receipt)) = final_response.payload else {
        bail!("missing final named delivery receipt");
    };
    validate_completion(
        &final_response.diagnostic_code,
        &receipt,
        &manifest,
        progress,
        args.cache_only,
    )?;
    let download = VerifiedNamedDownload {
        temporary,
        manifest,
        receipt,
        expires,
        authority_deadline,
        cache_only: args.cache_only,
    };
    download.as_file().sync_all()?;
    if Instant::now() >= deadline {
        bail!("publication expired before local output publication");
    }
    download.check_live()?;
    Ok(download)
}

fn validate_completion(
    code: &str,
    receipt: &ContentReceipt,
    manifest: &VerifiedManifest,
    progress: TransferProgress,
    cache_only: bool,
) -> Result<()> {
    if cache_only
        && (receipt.peer_bytes != 0
            || receipt.providers_used != 0
            || !receipt.provider_peer_ids.is_empty()
            || !receipt.control_relay_peer_id.is_empty())
    {
        bail!("cache-only named delivery reported network or provider activity");
    }
    if code != "CONTENT_OK"
        || receipt.origin_authenticated
        || receipt.origin_body_bytes != 0
        || receipt.origin_range_requests != 0
        || receipt.bytes != manifest.length()
        || receipt.chunks as usize != manifest.chunks().len()
        || progress.bytes != manifest.length()
        || progress.chunks != manifest.chunks().len()
        || progress.missing != 0
    {
        bail!("named local delivery did not complete with the exact publisher-authorized object");
    }
    Ok(())
}

fn report(receipt: &ContentReceipt, manifest: &VerifiedManifest) -> serde_json::Value {
    serde_json::json!({
        "operation":"named_content_download", "bytes":receipt.bytes, "chunks":receipt.chunks,
        "publisher_key":hex::encode(manifest.publisher()), "name":manifest.metadata().name,
        "revision":manifest.metadata().revision, "manifest_id":hex::encode(manifest.manifest_id()),
        "publication_expires_unix_seconds":manifest.validity().expires,
        "sha256":hex::encode(manifest.object_sha256()),
        "local_delivery":true, "output_mode":"0600",
        "ownership_changed":false, "origin_authenticated":false, "globally_latest":false,
        "peer_bytes":receipt.peer_bytes, "providers_used":receipt.providers_used,
        "origin_body_bytes":receipt.origin_body_bytes, "origin_range_requests":receipt.origin_range_requests,
        "provider_peer_ids":receipt.provider_peer_ids,
        "control_relay_peer_id":receipt.control_relay_peer_id,
    })
}
