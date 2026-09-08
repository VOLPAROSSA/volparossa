//! Explicit native name resolution over protected provider streams, never global latestness.

use std::{path::PathBuf, time::Duration};

use tokio::{net::UnixStream, time::timeout};
use volparossa_content::provider::named::{NameQuery, NameResolution, lookup_publication};
use volparossa_content::transfer::{TransferLimits, serve_peer};
use volparossa_content::{CacheLimits, ChunkStore, SignedManifest, VerifiedManifest};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentFetchNameRequest, ContentReceipt, ControlResponse,
    ControlResult, NamedContentTransferReady, control_response::Payload, write_response,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{ContentError, ContentRuntime, download_cache, limits, now, tls};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

const METADATA_ROUND_TIMEOUT: Duration = Duration::from_secs(90);

struct Selected {
    signed: SignedManifest,
    manifest: VerifiedManifest,
}

struct PreparedDownload {
    selected: Selected,
    query: NameQuery,
    policy: VerifiedPolicy,
    store: ChunkStore,
    source_root: PathBuf,
    source_limits: CacheLimits,
    receipt: ContentReceipt,
}

fn cache_error(error: &volparossa_content::Error) -> ContentError {
    match error {
        volparossa_content::Error::NameConflict => ContentError::NameConflict,
        volparossa_content::Error::NameRollback => ContentError::NameRollback,
        _ => ContentError::Invalid,
    }
}

/// Persist every authenticated higher observation even when later bytes are unavailable.
/// Lower observations cannot replace the best candidate. A higher revision can resolve an
/// earlier publisher conflict, but peer arrival order never selects one branch of a conflict.
fn observe(
    store: &mut ChunkStore,
    selected: &mut Option<Selected>,
    signed: &SignedManifest,
    manifest: &VerifiedManifest,
) -> Result<(), ContentError> {
    match store.observe_name_revision(manifest, now()) {
        Ok(_)
        | Err(volparossa_content::Error::NameConflict | volparossa_content::Error::NameRollback) => {
        }
        Err(error) => return Err(cache_error(&error)),
    }
    if selected
        .as_ref()
        .is_none_or(|old| manifest.metadata().revision > old.manifest.metadata().revision)
    {
        *selected = Some(Selected {
            signed: signed.clone(),
            manifest: manifest.clone(),
        });
    }
    Ok(())
}

fn selected_at_floor(
    store: &ChunkStore,
    publisher: &[u8; 32],
    name: &str,
    selected: Option<Selected>,
) -> Result<Selected, ContentError> {
    let floor = store
        .name_revision_floor(publisher, name)
        .map_err(|error| cache_error(&error))?;
    if floor
        .as_ref()
        .is_some_and(volparossa_content::RevisionPin::conflicted)
    {
        return Err(ContentError::NameConflict);
    }
    let selected = selected.ok_or(ContentError::Unavailable)?;
    let pin = floor.ok_or(ContentError::Invalid)?;
    if selected.manifest.metadata().revision != pin.revision()
        || selected.manifest.manifest_id() != pin.manifest_id()
    {
        return Err(ContentError::NameRollback);
    }
    Ok(selected)
}

async fn checked_policy(
    context: &ControlContext,
    original: &VerifiedPolicy,
) -> Result<VerifiedPolicy, ContentError> {
    let state = context.state.read().await;
    let current = state
        .active_policy(unix_millis())
        .ok_or(ContentError::Policy)?;
    if !state.roles().client || current.policy_hash() != original.policy_hash() {
        return Err(ContentError::Policy);
    }
    Ok(current)
}

async fn metadata_round(
    context: &ControlContext,
    policy: &VerifiedPolicy,
    query: &NameQuery,
    providers: &[DiscoveredContentProvider],
    store: &mut ChunkStore,
) -> Result<Option<Selected>, ContentError> {
    let mut selected = None;
    for provider in providers {
        if !context
            .routes
            .content_provider_is_distinct(&provider.peer_id)
            .await
            || provider.offer.validity().expires <= now()
        {
            continue;
        }
        let current = checked_policy(context, policy).await?;
        let endpoint = provider.offer.endpoint();
        let Ok(mut flow) = context
            .routes
            .open_content_stream(
                &current,
                endpoint.hostname(),
                endpoint.port(),
                unix_millis(),
            )
            .await
        else {
            super::content_event(context, "CONTENT_NAME_ROUTE_UNAVAILABLE").await;
            continue;
        };
        let Ok(mut stream) =
            tls::connect(flow.stream_mut(), provider.peer_id, &provider.offer).await
        else {
            super::content_event(context, "CONTENT_NAME_TLS_UNAVAILABLE").await;
            continue;
        };
        let response = lookup_publication(
            &mut stream,
            query,
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(10),
                max_requests: 1,
                max_bytes: volparossa_content::MAX_MANIFEST_BYTES as u64,
            },
        )
        .await;
        // Persist signed observations before a potentially failing close/next provider/chunk read.
        match &response {
            Ok(NameResolution::Candidate(candidate)) => {
                observe(
                    store,
                    &mut selected,
                    candidate.signed(),
                    candidate.manifest(),
                )?;
            }
            Ok(NameResolution::Conflict(candidates)) => {
                for candidate in candidates.iter() {
                    observe(
                        store,
                        &mut selected,
                        candidate.signed(),
                        candidate.manifest(),
                    )?;
                }
            }
            Ok(NameResolution::Missing) | Err(_) => {}
        }
        if response.is_ok() && tls::finish(&mut stream).await.is_err() {
            return Err(ContentError::Unavailable);
        }
        drop(stream);
        if response.is_ok() && tls::finish(flow.stream_mut()).await.is_err() {
            return Err(ContentError::Unavailable);
        }
        flow.shutdown();
    }
    Ok(selected)
}

async fn retrieve(
    request: ContentFetchNameRequest,
    context: &ControlContext,
) -> Result<PreparedDownload, ContentError> {
    let publisher = request
        .publisher_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let query = NameQuery::new(publisher, &request.name, request.min_revision.unwrap_or(0))
        .map_err(|_| ContentError::Invalid)?;
    let cache_limits = limits(request.limits)?;
    let mut store = download_cache(&request.cache, cache_limits, request.reuse_cache)?;
    let policy = {
        let state = context.state.read().await;
        if !state.roles().client {
            return Err(ContentError::Policy);
        }
        state
            .active_policy(unix_millis())
            .ok_or(ContentError::Policy)?
    };
    Box::pin(
        context
            .routes
            .connect_tcp(&context.config, &context.discovery, &context.helper),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?;
    let control = context
        .routes
        .content_discovery_control()
        .await
        .ok_or(ContentError::Unavailable)?;
    let providers = context
        .discovery
        .discover_content_providers(control, 16)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    if providers.len() > 16 {
        return Err(ContentError::Invalid);
    }
    let selected = timeout(
        METADATA_ROUND_TIMEOUT,
        metadata_round(context, &policy, &query, &providers, &mut store),
    )
    .await
    .map_err(|_| ContentError::Unavailable)??;
    let selected = selected_at_floor(&store, &publisher, &request.name, selected)?;
    let verified = query
        .verify_candidate(&selected.signed, now())
        .map_err(|_| ContentError::Unavailable)?;
    if verified.length() > cache_limits.max_bytes
        || verified.chunks().len() > cache_limits.max_entries
    {
        return Err(ContentError::Invalid);
    }
    let (provider_peer_ids, peer_bytes) =
        ContentRuntime::pull_providers(context, &verified, &mut store, &policy, providers).await?;
    let bytes =
        volparossa_content::reassemble(&verified, &mut [&mut store], now(), &mut std::io::sink())
            .map_err(|_| ContentError::Unavailable)?;
    let receipt = ContentReceipt {
        bytes,
        chunks: u32::try_from(verified.chunks().len()).map_err(|_| ContentError::Invalid)?,
        providers_used: u32::try_from(provider_peer_ids.len())
            .map_err(|_| ContentError::Invalid)?,
        provider_peer_ids,
        control_relay_peer_id: control.to_string(),
        peer_bytes,
        ..ContentReceipt::default()
    };
    Ok(PreparedDownload {
        selected,
        query,
        policy,
        store,
        source_root: PathBuf::from(request.cache),
        source_limits: cache_limits,
        receipt,
    })
}

/// The local user supplies publisher/name trust. The agent sends only the original signed
/// envelope, then serves checked chunks and a distinct completion receipt on the same socket.
pub(super) async fn download(
    request: ContentFetchNameRequest,
    context: &ControlContext,
    stream: &mut UnixStream,
    request_id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let PreparedDownload {
        selected,
        query,
        policy,
        mut store,
        source_root,
        source_limits,
        receipt,
    } = retrieve(request, context).await?;
    let verified = &selected.manifest;
    let remaining = verified
        .validity()
        .expires
        .checked_sub(now())
        .filter(|v| *v > 0)
        .ok_or(ContentError::Unavailable)?;
    timeout(Duration::from_secs(remaining.min(30)), async {
        checked_policy(context, &policy).await?;
        query
            .verify_candidate(&selected.signed, now())
            .map_err(|_| ContentError::Unavailable)?;
        *ready_sent = true;
        send_response(
            stream,
            request_id,
            "NAMED_CONTENT_TRANSFER_READY",
            Payload::NamedContentTransferReady(NamedContentTransferReady {
                manifest: selected.signed.encode(),
            }),
        )
        .await?;
        let progress = serve_peer(
            stream,
            verified,
            &mut store,
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(30),
                max_requests: verified.chunks().len().max(1),
                max_bytes: verified.length().max(1),
            },
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        if progress.missing != 0
            || progress.bytes != verified.length()
            || progress.chunks != verified.chunks().len()
        {
            return Err(ContentError::Unavailable);
        }
        checked_policy(context, &policy).await?;
        query
            .verify_candidate(&selected.signed, now())
            .map_err(|_| ContentError::Unavailable)?;
        context
            .content
            .contribute_native(
                selected.signed.clone(),
                verified.clone(),
                source_root,
                source_limits,
            )
            .await;
        send_response(stream, request_id, "CONTENT_OK", Payload::Content(receipt)).await
    })
    .await
    .map_err(|_| ContentError::Unavailable)?
}

async fn send_response(
    stream: &mut UnixStream,
    id: &[u8],
    code: &str,
    payload: Payload,
) -> Result<(), ContentError> {
    write_response(
        stream,
        &ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: id.to_vec(),
            result: ControlResult::Ok as i32,
            diagnostic_code: code.into(),
            payload: Some(payload),
        },
    )
    .await
    .map_err(|_| ContentError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use volparossa_content::{CacheLimits, Metadata, Publication, Validity, publish};

    fn cache_limits() -> CacheLimits {
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        }
    }

    fn publication(
        key: &SigningKey,
        revision: u64,
        store: &mut ChunkStore,
    ) -> (SignedManifest, VerifiedManifest) {
        let data = b"named public fixture";
        let signed = publish(
            &mut &data[..],
            Publication {
                metadata: Metadata {
                    name: "Exact Name".into(),
                    revision,
                    content_type: "text/plain".into(),
                },
                length: data.len() as u64,
                validity: Validity {
                    created: now(),
                    expires: now() + 600,
                },
            },
            key,
            store,
        )
        .unwrap();
        let manifest = signed.verify(&key.verifying_key(), now()).unwrap();
        (signed, manifest)
    }

    #[test]
    fn named_round_keeps_highest_before_bytes_and_refuses_rollback_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("cache");
        let mut cache = ChunkStore::create(&root, cache_limits()).unwrap();
        let mut source =
            ChunkStore::create(&directory.path().join("source"), cache_limits()).unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let (older, old) = publication(&key, 1, &mut source);
        let (newer, new) = publication(&key, 2, &mut source);
        let mut selected = None;
        observe(&mut cache, &mut selected, &newer, &new).unwrap();
        observe(&mut cache, &mut selected, &older, &old).unwrap();
        let best = selected_at_floor(
            &cache,
            key.verifying_key().as_bytes(),
            "Exact Name",
            selected,
        )
        .unwrap();
        assert_eq!(best.manifest.manifest_id(), new.manifest_id());
        assert_eq!(
            cache.usage().bytes,
            0,
            "metadata observation precedes any content transfer"
        );
        drop(cache);
        let mut reopened = ChunkStore::open(&root, cache_limits()).unwrap();
        let mut selected = None;
        observe(&mut reopened, &mut selected, &older, &old).unwrap();
        assert!(matches!(
            selected_at_floor(
                &reopened,
                key.verifying_key().as_bytes(),
                "Exact Name",
                selected
            ),
            Err(ContentError::NameRollback)
        ));
    }

    #[test]
    fn named_round_conflict_is_durable_until_a_higher_verified_revision() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("cache");
        let mut cache = ChunkStore::create(&root, cache_limits()).unwrap();
        let mut source =
            ChunkStore::create(&directory.path().join("source"), cache_limits()).unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let (left, first) = publication(&key, 1, &mut source);
        let (right, second) = publication(&key, 1, &mut source);
        assert_ne!(first.manifest_id(), second.manifest_id());
        let mut selected = None;
        observe(&mut cache, &mut selected, &left, &first).unwrap();
        observe(&mut cache, &mut selected, &right, &second).unwrap();
        assert!(matches!(
            selected_at_floor(
                &cache,
                key.verifying_key().as_bytes(),
                "Exact Name",
                selected
            ),
            Err(ContentError::NameConflict)
        ));
        drop(cache);
        let mut cache = ChunkStore::open(&root, cache_limits()).unwrap();
        assert!(
            cache
                .name_revision_floor(key.verifying_key().as_bytes(), "Exact Name")
                .unwrap()
                .unwrap()
                .conflicted()
        );
        let (newer, new) = publication(&key, 2, &mut source);
        let mut selected = None;
        observe(&mut cache, &mut selected, &newer, &new).unwrap();
        assert_eq!(
            selected_at_floor(
                &cache,
                key.verifying_key().as_bytes(),
                "Exact Name",
                selected
            )
            .unwrap()
            .manifest
            .manifest_id(),
            new.manifest_id()
        );
    }
}
