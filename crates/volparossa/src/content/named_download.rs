//! Publisher-local name resolution is not HTTPS authority or a globally latest version proof.

use std::{os::unix::fs::PermissionsExt as _, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use tokio::time::{Instant, timeout, timeout_at};
use volparossa_content::{
    SignedManifest, VerifiedManifest,
    provider::named::NameQuery,
    transfer::{TransferLimits, pull_to_writer},
};
use volparossa_local_control::{
    ContentFetchNameRequest, ContentReceipt, control_request::Operation, control_response::Payload,
};

use super::{FetchName, absolute_path, ensure_new_output, now_seconds, output_parent};

pub(super) async fn run(args: &FetchName, socket: &Path) -> Result<()> {
    ensure_new_output(&args.local_output)?;
    let report = timeout(Duration::from_secs(600), download(args, socket))
        .await
        .context("named download deadline exceeded; verified agent cache chunks may remain")??;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

async fn download(args: &FetchName, socket: &Path) -> Result<serde_json::Value> {
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
    };
    let (mut stream, request_id, response) =
        crate::control::begin_request(socket, Operation::ContentFetchName(request)).await?;
    if response.diagnostic_code != "NAMED_CONTENT_TRANSFER_READY" {
        bail!("expected explicit publisher/name stream readiness");
    }
    let Some(Payload::NamedContentTransferReady(ready)) = response.payload else {
        bail!("expected same-operation named readiness");
    };
    let manifest =
        query.verify_candidate(&SignedManifest::decode(&ready.manifest)?, now_seconds()?)?;
    let remaining = manifest
        .validity()
        .expires
        .checked_sub(now_seconds()?)
        .filter(|seconds| *seconds > 0)
        .context("named publication expired before local delivery")?;
    let deadline = Instant::now() + Duration::from_secs(remaining.min(30));
    let mut temporary = tempfile::NamedTempFile::new_in(output_parent(&args.local_output))?;
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
    if final_response.diagnostic_code != "CONTENT_OK"
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
    temporary.as_file().sync_all()?;
    if Instant::now() >= deadline || now_seconds()? >= manifest.validity().expires {
        bail!("publication expired before local output publication");
    }
    temporary
        .persist_noclobber(&args.local_output)
        .map_err(|error| error.error)
        .context("cannot publish named output without overwriting an existing entry")?;
    Ok(report(&receipt, args, &manifest))
}

fn report(
    receipt: &ContentReceipt,
    args: &FetchName,
    manifest: &VerifiedManifest,
) -> serde_json::Value {
    serde_json::json!({
        "operation":"named_content_download", "bytes":receipt.bytes, "chunks":receipt.chunks,
        "publisher_key":hex::encode(manifest.publisher()), "name":manifest.metadata().name,
        "revision":manifest.metadata().revision, "manifest_id":hex::encode(manifest.manifest_id()),
        "sha256":hex::encode(manifest.object_sha256()), "local_output":args.local_output,
        "cache":args.cache, "local_delivery":true, "output_mode":"0600",
        "ownership_changed":false, "origin_authenticated":false, "globally_latest":false,
        "peer_bytes":receipt.peer_bytes, "providers_used":receipt.providers_used,
        "provider_peer_ids":receipt.provider_peer_ids,
        "control_relay_peer_id":receipt.control_relay_peer_id,
    })
}
