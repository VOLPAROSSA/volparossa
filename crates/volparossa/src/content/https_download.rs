//! Deliver one freshly origin-authorized operation to the caller's own output file.
//! Readiness is trusted only on this configured local control socket/request, never from peers.

use std::{os::unix::fs::PermissionsExt as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::VerifyingKey;
use tokio::time::{Instant, timeout, timeout_at};
use volparossa_content::{
    SignedManifest, VerifiedManifest,
    transfer::{TransferLimits, pull_to_writer},
};
use volparossa_local_control::{
    ContentReceipt, HttpsContentTransferReady, control_request::Operation,
    control_response::Payload,
};

use super::{FetchHttps, ensure_new_output, https_fetch_request, now_seconds, output_parent};

pub(super) async fn run(args: &FetchHttps, socket: &Path, output: &Path) -> Result<()> {
    ensure_new_output(output)?;
    let receipt = timeout(Duration::from_secs(600), download(args, socket, output))
        .await
        .context("HTTPS download deadline exceeded; verified agent cache chunks may remain")??;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

async fn download(args: &FetchHttps, socket: &Path, output: &Path) -> Result<serde_json::Value> {
    let request = https_fetch_request(args)?;
    if !request.output.is_empty() {
        bail!("local HTTPS output must not be sent to the agent");
    }
    let (mut stream, request_id, response) =
        crate::control::begin_request(socket, Operation::ContentDownloadHttps(request)).await?;
    if response.diagnostic_code != "HTTPS_CONTENT_TRANSFER_READY" {
        bail!("expected explicit HTTPS stream readiness");
    }
    let Some(Payload::HttpsContentTransferReady(ready)) = response.payload else {
        bail!("expected same-operation HTTPS readiness, not a native export");
    };
    let manifest = verified_ready(&ready, &args.url)?;
    let remaining = ready
        .expires_unix_seconds
        .checked_sub(now_seconds()?)
        .filter(|seconds| *seconds > 0)
        .context("HTTPS authority expired before local delivery")?;
    let lifetime = Duration::from_secs(remaining);
    let deadline = Instant::now() + lifetime.min(Duration::from_secs(30));
    let mut temporary = tempfile::NamedTempFile::new_in(output_parent(output))?;
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
    .context("local HTTPS delivery expired or stalled")??;
    let Some(Payload::Content(receipt)) = final_response.payload else {
        bail!("missing final HTTPS delivery receipt");
    };
    if final_response.diagnostic_code != "CONTENT_OK"
        || !receipt.origin_authenticated
        || receipt.bytes != manifest.length()
        || receipt.chunks as usize != manifest.chunks().len()
        || progress.bytes != manifest.length()
        || progress.chunks != manifest.chunks().len()
        || progress.missing != 0
    {
        bail!("HTTPS local delivery did not complete with the exact authorized object");
    }
    temporary.as_file().sync_all()?;
    if Instant::now() >= deadline || now_seconds()? >= ready.expires_unix_seconds {
        bail!("HTTPS authorization expired before local output publication");
    }
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .context("cannot publish local HTTPS output without overwriting an existing entry")?;
    Ok(report(&receipt, output, &args.cache, &manifest))
}

fn verified_ready(ready: &HttpsContentTransferReady, resource: &str) -> Result<VerifiedManifest> {
    let now = now_seconds()?;
    if ready.resource_url != resource || ready.expires_unix_seconds <= now {
        bail!("local HTTPS readiness names a different or expired resource");
    }
    let publisher = VerifyingKey::from_bytes(
        &ready
            .publisher_key
            .as_slice()
            .try_into()
            .context("invalid origin-authorized publisher key length")?,
    )?;
    let manifest = SignedManifest::decode(&ready.manifest)?.verify(&publisher, now)?;
    if manifest.metadata().content_type != "application/octet-stream"
        || ready.expires_unix_seconds > manifest.validity().expires
    {
        bail!("local HTTPS readiness exceeds the supported representation or native lifetime");
    }
    Ok(manifest)
}

fn report(
    receipt: &ContentReceipt,
    output: &Path,
    cache: &Path,
    manifest: &VerifiedManifest,
) -> serde_json::Value {
    serde_json::json!({
        "operation":"https_content_download", "bytes":receipt.bytes, "chunks":receipt.chunks,
        "sha256":hex::encode(manifest.object_sha256()), "local_output":output, "cache":cache,
        "local_delivery":true, "output_mode":"0600", "ownership_changed":false,
        "origin_authenticated":true, "origin_authority_persisted":false,
        "peer_bytes":receipt.peer_bytes, "origin_body_bytes":receipt.origin_body_bytes,
        "origin_range_requests":receipt.origin_range_requests, "providers_used":receipt.providers_used,
        "provider_peer_ids":receipt.provider_peer_ids, "control_relay_peer_id":receipt.control_relay_peer_id,
    })
}
