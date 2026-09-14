//! Explicit publication handoff; agent configuration alone chooses its storage and listener.

use std::{path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use tokio::time::timeout;
use volparossa_content::{
    CacheLimits, ChunkStore, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE, transfer::serve_peer,
};
use volparossa_local_control::{ContentImportRequest, ContentReceipt, control_request::Operation};

pub(in crate::content) async fn run(
    signed: &SignedManifest,
    manifest: &VerifiedManifest,
    source: &Path,
    limits: CacheLimits,
    socket: &Path,
) -> Result<ContentReceipt> {
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        bail!("private messages cannot be admitted as public contributions");
    }
    let mut store =
        ChunkStore::open(source, limits).context("cannot reopen your owned source cache")?;
    super::verify_complete(manifest, &mut store)?;
    let operation = Operation::ContentImport(ContentImportRequest {
        manifest: signed.encode(),
        publisher_key: manifest.publisher().to_vec(),
        cache: String::new(),
        limits: None,
        allow_public_content: true,
        contribute: true,
    });
    timeout(Duration::from_secs(30), async {
        let (mut stream, request_id, ready) =
            crate::control::begin_request(socket, operation).await?;
        super::validate_ready(&ready, manifest, true)?;
        let progress = serve_peer(
            &mut stream,
            manifest,
            &mut store,
            super::transfer_limits(manifest),
        )
        .await?;
        super::validate_progress(manifest, progress)?;
        let complete = crate::control::finish_request(&mut stream, &request_id).await?;
        Ok::<_, anyhow::Error>(super::validate_complete(&complete, manifest, true)?.clone())
    })
    .await
    .context("public contribution handoff deadline exceeded")?
}
