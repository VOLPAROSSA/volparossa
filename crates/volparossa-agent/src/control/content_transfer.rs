//! Explicit local native-content handoff; private-message ciphertext remains the default.

#[cfg(test)]
mod tests;

use std::{path::Path, time::Duration};

use ed25519_dalek::VerifyingKey;
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::{
    CacheLimits, ChunkStore, SignedManifest, VerifiedManifest,
    private_message::{
        MAX_PRIVATE_MESSAGE_BYTES, PRIVATE_MESSAGE_CONTENT_TYPE, validate_private_message_envelope,
    },
    reassemble,
    transfer::{TransferLimits, pull_from_peer, serve_peer},
};
use volparossa_local_control::{
    ContentCacheLimits, ContentImportRequest, ContentReceipt, ContentTransferReady, ControlRequest,
    ControlResult, control_request::Operation, control_response::Payload, write_response,
};

use super::{ControlServerError, content_response, response};
use crate::{content::ContentError, control::ControlContext};

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

struct Scope {
    manifest: VerifiedManifest,
    store: ChunkStore,
    importing: bool,
}

/// The caller already accepted this stream through the protected control-socket filesystem ACL.
pub(super) async fn process(
    mut stream: UnixStream,
    request: ControlRequest,
    context: Option<&ControlContext>,
) -> Result<(), ControlServerError> {
    timeout(TRANSFER_TIMEOUT, async {
        if matches!(request.operation.as_ref(), Some(Operation::ContentImport(value)) if value.contribute) {
            return publication(stream, request, context).await;
        }
        let request_id = request.request_id;
        let mut scope = match prepare(request.operation) {
            Ok(scope) => scope,
            Err(error) => {
                return write_response(&mut stream, &content_response(request_id, Err(error)))
                    .await
                    .map_err(|_| ControlServerError::InvalidFrame);
            }
        };
        let complete = exchange(&mut stream, &request_id, &scope.manifest, &mut scope.store, scope.importing, false).await?;
        let result = if complete {
            Ok(ContentReceipt {
                bytes: scope.manifest.length(),
                chunks: u32::try_from(scope.manifest.chunks().len())
                    .map_err(|_| ControlServerError::InvalidFrame)?,
                ..ContentReceipt::default()
            })
        } else {
            Err(ContentError::Invalid)
        };
        write_response(&mut stream, &content_response(request_id, result))
            .await
            .map_err(|_| ControlServerError::InvalidFrame)
    })
    .await
    .map_err(|_| ControlServerError::Timeout)?
}

async fn exchange(
    stream: &mut UnixStream,
    request_id: &[u8],
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    importing: bool,
    contribute: bool,
) -> Result<bool, ControlServerError> {
    let ready = response(
        request_id.to_vec(),
        ControlResult::Ok,
        "CONTENT_TRANSFER_READY",
        Payload::ContentTransferReady(ContentTransferReady {
            manifest_id: manifest.manifest_id().to_vec(),
            bytes: manifest.length(),
            chunks: u32::try_from(manifest.chunks().len())
                .map_err(|_| ControlServerError::InvalidFrame)?,
            contribute,
        }),
    );
    write_response(stream, &ready)
        .await
        .map_err(|_| ControlServerError::InvalidFrame)?;
    // No control frame is inserted after a partial/failed stream exchange.
    let limits = transfer_limits(manifest);
    let progress = if importing {
        pull_from_peer(stream, manifest, store, limits).await
    } else {
        serve_peer(stream, manifest, store, limits).await
    }
    .map_err(|_| ControlServerError::InvalidFrame)?;
    let unique: std::collections::BTreeMap<_, _> = manifest
        .chunks()
        .iter()
        .map(|chunk| (*chunk.id(), u64::from(chunk.length())))
        .collect();
    Ok(progress.missing == 0
        && progress.bytes == unique.values().sum::<u64>()
        && progress.chunks == unique.len()
        && verify_complete(manifest, store).is_ok())
}

async fn publication(
    mut stream: UnixStream,
    request: ControlRequest,
    context: Option<&ControlContext>,
) -> Result<(), ControlServerError> {
    let request_id = request.request_id;
    let prepared = async {
        let Some(Operation::ContentImport(request)) = request.operation else {
            return Err(ContentError::Invalid);
        };
        let (signed, manifest) = publication_manifest(&request)?;
        let context = context.ok_or(ContentError::Unavailable)?;
        let admission = context
            .content
            .begin_publication(context, signed, manifest.clone())
            .await?;
        Ok((context, manifest, admission))
    }
    .await;
    let (context, manifest, mut admission) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return write_response(&mut stream, &content_response(request_id, Err(error)))
                .await
                .map_err(|_| ControlServerError::InvalidFrame);
        }
    };
    let mut stop = admission.stop_receiver();
    if *stop.borrow() {
        return Err(ControlServerError::InvalidFrame);
    }
    let complete = tokio::select! {
        biased;
        _ = stop.changed() => return Err(ControlServerError::InvalidFrame),
        result = exchange(&mut stream, &request_id, &manifest, admission.source(), true, true) => result?,
    };
    let result = if complete {
        admission.complete(context).await
    } else {
        drop(admission);
        Err(ContentError::Invalid)
    };
    write_response(&mut stream, &content_response(request_id, result))
        .await
        .map_err(|_| ControlServerError::InvalidFrame)
}

fn publication_manifest(
    request: &ContentImportRequest,
) -> Result<(SignedManifest, VerifiedManifest), ContentError> {
    if !request.contribute
        || !request.allow_public_content
        || !request.cache.is_empty()
        || request.limits.is_some()
    {
        return Err(ContentError::Invalid);
    }
    let manifest = handoff_manifest(&request.manifest, &request.publisher_key, true)?;
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        return Err(ContentError::Invalid);
    }
    let signed = SignedManifest::decode(&request.manifest).map_err(|_| ContentError::Invalid)?;
    Ok((signed, manifest))
}

fn prepare(operation: Option<Operation>) -> Result<Scope, ContentError> {
    let (encoded, key, cache, limits, importing, allow_public_content) = match operation {
        Some(Operation::ContentImport(request)) => (
            request.manifest,
            request.publisher_key,
            request.cache,
            request.limits,
            true,
            request.allow_public_content,
        ),
        Some(Operation::ContentExport(request)) => (
            request.manifest,
            request.publisher_key,
            request.cache,
            request.limits,
            false,
            request.allow_public_content,
        ),
        _ => return Err(ContentError::Invalid),
    };
    let manifest = handoff_manifest(&encoded, &key, allow_public_content)?;
    let cache_limits = cache_limits(limits, &manifest)?;
    let mut store = if importing {
        ChunkStore::create(Path::new(&cache), cache_limits)
    } else {
        ChunkStore::open(Path::new(&cache), cache_limits)
    }
    .map_err(|_| ContentError::Invalid)?;
    if !importing {
        verify_complete(&manifest, &mut store)?;
    }
    Ok(Scope {
        manifest,
        store,
        importing,
    })
}

fn handoff_manifest(
    encoded: &[u8],
    key: &[u8],
    allow_public_content: bool,
) -> Result<VerifiedManifest, ContentError> {
    let key = VerifyingKey::from_bytes(&key.try_into().map_err(|_| ContentError::Invalid)?)
        .map_err(|_| ContentError::Invalid)?;
    let manifest = SignedManifest::decode(encoded)
        .and_then(|signed| signed.verify(&key, now()))
        .map_err(|_| ContentError::Invalid)?;
    let metadata = manifest.metadata();
    if metadata.content_type != PRIVATE_MESSAGE_CONTENT_TYPE {
        return if allow_public_content {
            Ok(manifest)
        } else {
            Err(ContentError::Invalid)
        };
    }
    // Public opt-in never downgrades the exact private-message profile or envelope checks.
    if metadata.revision != 1
        || metadata.name.len() != 64
        || !metadata
            .name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !(54..=MAX_PRIVATE_MESSAGE_BYTES as u64 + 64).contains(&manifest.length())
        || !(1..=17).contains(&manifest.chunks().len())
    {
        return Err(ContentError::Invalid);
    }
    Ok(manifest)
}

fn verify_complete(
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
) -> Result<(), ContentError> {
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        validate_private_message_envelope(manifest, &mut [store], now())
            .map_err(|_| ContentError::Invalid)?;
    } else {
        // Bounded chunk-at-a-time reassembly checks the signed whole hash without buffering
        // the complete (at most 256 MiB) publication or persisting another object copy.
        reassemble(manifest, &mut [store], now(), &mut std::io::sink())
            .map_err(|_| ContentError::Invalid)?;
    }
    Ok(())
}

fn cache_limits(
    value: Option<ContentCacheLimits>,
    manifest: &VerifiedManifest,
) -> Result<CacheLimits, ContentError> {
    let value = value.ok_or(ContentError::Invalid)?;
    let max_entries = usize::try_from(value.max_entries).map_err(|_| ContentError::Invalid)?;
    if value.quota_bytes < manifest.length() || max_entries < manifest.chunks().len() {
        return Err(ContentError::Invalid);
    }
    Ok(CacheLimits {
        max_bytes: value.quota_bytes,
        max_entries,
        min_free_bytes: value.min_free_bytes,
    })
}

fn transfer_limits(manifest: &VerifiedManifest) -> TransferLimits {
    TransferLimits {
        exchange_timeout: Duration::from_secs(5),
        session_timeout: TRANSFER_TIMEOUT,
        // An empty native object still sends the normal finish frame; its allowed chunk
        // map is empty, so these nonzero protocol configuration bounds permit no body.
        max_requests: manifest.chunks().len().max(1),
        max_bytes: manifest.length().max(1),
    }
}

fn now() -> u64 {
    crate::unix_millis() / 1000
}
