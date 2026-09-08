//! Explicit local ciphertext handoff; no ownership relaxation, plaintext, or recipient keys.

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
    transfer::{TransferLimits, pull_from_peer, serve_peer},
};
use volparossa_local_control::{
    ContentCacheLimits, ContentReceipt, ContentTransferReady, ControlRequest, ControlResult,
    control_request::Operation, control_response::Payload, write_response,
};

use super::{ControlServerError, content_response, response};
use crate::content::ContentError;

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
) -> Result<(), ControlServerError> {
    timeout(TRANSFER_TIMEOUT, async {
        let request_id = request.request_id;
        let mut scope = match prepare(request.operation) {
            Ok(scope) => scope,
            Err(error) => {
                return write_response(&mut stream, &content_response(request_id, Err(error)))
                    .await
                    .map_err(|_| ControlServerError::InvalidFrame);
            }
        };
        let ready = response(
            request_id.clone(),
            ControlResult::Ok,
            "CONTENT_TRANSFER_READY",
            Payload::ContentTransferReady(ContentTransferReady {
                manifest_id: scope.manifest.manifest_id().to_vec(),
                bytes: scope.manifest.length(),
                chunks: u32::try_from(scope.manifest.chunks().len())
                    .map_err(|_| ControlServerError::InvalidFrame)?,
            }),
        );
        write_response(&mut stream, &ready)
            .await
            .map_err(|_| ControlServerError::InvalidFrame)?;
        // A framing/timeout error closes this connection. No control frame is injected into a
        // half-finished chunk exchange, and already verified ciphertext remains in the cache.
        let limits = transfer_limits(&scope.manifest);
        let progress = if scope.importing {
            pull_from_peer(&mut stream, &scope.manifest, &mut scope.store, limits).await
        } else {
            serve_peer(&mut stream, &scope.manifest, &mut scope.store, limits).await
        }
        .map_err(|_| ControlServerError::InvalidFrame)?;
        let unique: std::collections::BTreeMap<_, _> = scope
            .manifest
            .chunks()
            .iter()
            .map(|chunk| (*chunk.id(), u64::from(chunk.length())))
            .collect();
        let complete = progress.missing == 0
            && progress.bytes == unique.values().sum::<u64>()
            && progress.chunks == unique.len()
            && validate_private_message_envelope(&scope.manifest, &mut [&mut scope.store], now())
                .is_ok();
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

fn prepare(operation: Option<Operation>) -> Result<Scope, ContentError> {
    let (encoded, key, cache, limits, importing) = match operation {
        Some(Operation::ContentImport(request)) => (
            request.manifest,
            request.publisher_key,
            request.cache,
            request.limits,
            true,
        ),
        Some(Operation::ContentExport(request)) => (
            request.manifest,
            request.publisher_key,
            request.cache,
            request.limits,
            false,
        ),
        _ => return Err(ContentError::Invalid),
    };
    let manifest = private_manifest(&encoded, &key)?;
    let cache_limits = cache_limits(limits, &manifest)?;
    let mut store = if importing {
        ChunkStore::create(Path::new(&cache), cache_limits)
    } else {
        ChunkStore::open(Path::new(&cache), cache_limits)
    }
    .map_err(|_| ContentError::Invalid)?;
    if !importing {
        validate_private_message_envelope(&manifest, &mut [&mut store], now())
            .map_err(|_| ContentError::Invalid)?;
    }
    Ok(Scope {
        manifest,
        store,
        importing,
    })
}

fn private_manifest(encoded: &[u8], key: &[u8]) -> Result<VerifiedManifest, ContentError> {
    let key = VerifyingKey::from_bytes(&key.try_into().map_err(|_| ContentError::Invalid)?)
        .map_err(|_| ContentError::Invalid)?;
    let manifest = SignedManifest::decode(encoded)
        .and_then(|signed| signed.verify(&key, now()))
        .map_err(|_| ContentError::Invalid)?;
    let metadata = manifest.metadata();
    if metadata.content_type != PRIVATE_MESSAGE_CONTENT_TYPE
        || metadata.revision != 1
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
        max_requests: 17,
        max_bytes: manifest.length(),
    }
}

fn now() -> u64 {
    crate::unix_millis() / 1000
}
