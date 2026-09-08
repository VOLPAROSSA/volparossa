//! Explicit public content serving and protected native retrieval.
//!
//! Neither browsing capture nor a default listener is enabled. Provider offers are only
//! discovery hints: every destination still passes the existing signed Exit policy.

mod https;
mod replication;
mod replication_budget;
#[cfg(test)]
mod resume_tests;
mod tls;

use replication::ReplicationRuntime;
use replication_budget::Foreground;

use std::{collections::HashSet, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use ed25519_dalek::{SigningKey, VerifyingKey};
use socket2::SockRef;
use tokio::{
    net::TcpListener,
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
    time::{interval, timeout},
};
use volparossa_content::provider::{
    ProviderEndpoint, PublicationRegistry, SignedProviderOffer, pull_publication_with_progress,
    serve_publication,
};
use volparossa_content::transfer::{TransferLimits, TransferProgress};
use volparossa_content::{CacheLimits, ChunkStore, SignedManifest, Validity, VerifiedManifest};
use volparossa_core::CONTRIBUTION_SOCKET_PRIORITY;
use volparossa_identity::Identity;
use volparossa_local_control::{
    ContentCacheLimits, ContentFetchRequest, ContentReceipt, ContentServeRequest,
    HttpsContentFetchRequest,
};
use zeroize::Zeroizing;

use crate::{control::ControlContext, discovery::DiscoveryControlHandle, unix_millis};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(600);
const OFFER_LIFETIME: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ContentError {
    #[error("content input or local state is invalid")]
    Invalid,
    #[error("content operation is unavailable")]
    Unavailable,
    #[error("content operation is already active")]
    Busy,
    #[error("content policy or role does not permit this operation")]
    Policy,
}

/// In-memory lifecycle, sharing the existing node identity without exporting its private key.
#[derive(Clone)]
pub(crate) struct ContentRuntime {
    signer: Arc<SigningKey>,
    tls_identity: Arc<libp2p::identity::Keypair>,
    service: Arc<Mutex<Option<Service>>>,
    retrieval: Arc<Mutex<()>>,
    foreground: Arc<Foreground>,
}

struct Service {
    registry: Arc<Mutex<PublicationRegistry>>,
    endpoint: ProviderEndpoint,
    bind: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    replication: Option<Arc<ReplicationRuntime>>,
}

impl ContentRuntime {
    pub(crate) fn new(identity: &Identity) -> Result<Self, ContentError> {
        let pair = identity
            .keypair()
            .clone()
            .try_into_ed25519()
            .map_err(|_| ContentError::Invalid)?;
        let bytes = Zeroizing::new(pair.to_bytes());
        let signer = SigningKey::from_keypair_bytes(&bytes).map_err(|_| ContentError::Invalid)?;
        Ok(Self {
            signer: Arc::new(signer),
            tls_identity: Arc::new(identity.keypair().clone()),
            service: Arc::new(Mutex::new(None)),
            retrieval: Arc::new(Mutex::new(())),
            foreground: Arc::new(Foreground::default()),
        })
    }

    pub(crate) async fn serve(
        &self,
        request: ContentServeRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let mut service = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let (roles, policy) = {
            let state = context.state.read().await;
            (
                state.roles(),
                state
                    .active_policy(unix_millis())
                    .ok_or(ContentError::Policy)?,
            )
        };
        if !roles.relay {
            return Err(ContentError::Policy);
        }
        let manifest = verified(&request.manifest, &request.publisher_key)?;
        let bind: SocketAddr = request
            .bind_address
            .parse()
            .map_err(|_| ContentError::Invalid)?;
        let endpoint = ProviderEndpoint::new(&request.advertised_hostname, bind.port())
            .map_err(|_| ContentError::Invalid)?;
        policy
            .authorize_domain(
                unix_millis(),
                endpoint.hostname(),
                volparossa_policy::TransportProtocol::Tcp,
                endpoint.port(),
            )
            .map_err(|_| ContentError::Policy)?;
        let cache_limits = limits(request.limits)?;
        if let Some(active) = service.as_ref() {
            if active.bind != bind || active.endpoint != endpoint || active.task.is_finished() {
                return Err(ContentError::Busy);
            }
            if !match (&active.replication, &request.replication) {
                (None, None) => true,
                (Some(runtime), Some(config)) => runtime.matches(config),
                _ => false,
            } {
                return Err(ContentError::Busy);
            }
            let mut registry = active.registry.try_lock().map_err(|_| ContentError::Busy)?;
            register(&mut registry, &request, manifest, cache_limits)?;
            let mut receipt = serving_receipt(&registry)?;
            drop(registry);
            if let Some(replication) = &active.replication {
                replication.receipt(&mut receipt).await?;
            }
            return Ok(receipt);
        }
        let mut registry = PublicationRegistry::new();
        register(&mut registry, &request, manifest, cache_limits)?;
        let replication = request
            .replication
            .map(|config| ReplicationRuntime::create(config, &mut registry))
            .transpose()?;
        let mut receipt = serving_receipt(&registry)?;
        if let Some(runtime) = &replication {
            runtime.receipt(&mut receipt).await?;
        }
        let tls = tls::ContentTlsServer::new(&self.tls_identity, endpoint.hostname())
            .map_err(|_| ContentError::Unavailable)?;
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        SockRef::from(&listener)
            .set_priority(CONTRIBUTION_SOCKET_PRIORITY)
            .map_err(|_| ContentError::Unavailable)?;
        let offer = self.offer(endpoint.clone())?;
        // The listener and a verified registration exist before announcing service availability.
        context
            .discovery
            .register_content_offer(offer)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        let registry = Arc::new(Mutex::new(registry));
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(Self::serve_loop(
            listener,
            tls,
            Arc::clone(&registry),
            Arc::clone(&self.signer),
            endpoint.clone(),
            context.discovery.clone(),
            receiver,
        ));
        *service = Some(Service {
            registry,
            endpoint,
            bind,
            stop,
            task,
            replication,
        });
        Ok(receipt)
    }

    fn offer(&self, endpoint: ProviderEndpoint) -> Result<SignedProviderOffer, ContentError> {
        make_offer(&self.signer, endpoint)
    }

    async fn serve_loop(
        listener: TcpListener,
        tls: tls::ContentTlsServer,
        registry: Arc<Mutex<PublicationRegistry>>,
        signer: Arc<SigningKey>,
        endpoint: ProviderEndpoint,
        discovery: DiscoveryControlHandle,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut sessions = JoinSet::new();
        let mut refresh = interval(Duration::from_secs(60));
        refresh.tick().await;
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() { break; }
                }
                _ = refresh.tick() => {
                    let Ok(offer) = make_offer(&signer, endpoint.clone()) else { break; };
                    if discovery.register_content_offer(offer).await.is_err() { break; }
                }
                accepted = listener.accept(), if sessions.len() < 4 => {
                    let Ok((stream, _source)) = accepted else { break; };
                    if SockRef::from(&stream).set_priority(CONTRIBUTION_SOCKET_PRIORITY).is_err() {
                        continue;
                    }
                    let registry = Arc::clone(&registry);
                    let tls = tls.clone();
                    sessions.spawn(async move {
                        let Ok(mut stream) = tls.accept(stream).await else { return; };
                        // Snapshot at most 64 explicit registrations; never hold the metadata
                        // lock while a background receiver waits before requesting a chunk.
                        // Cache handles retain their own exclusive ownership checks.
                        let registry = {
                            let Ok(current) = registry.try_lock() else { return; };
                            current.clone()
                        };
                        if serve_publication(&mut stream, &registry, TransferLimits::default()).await.is_ok() {
                            let _ = tls::finish(&mut stream).await;
                        }
                    });
                }
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
        drop(listener);
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        let _ = discovery.withdraw_content_offer().await;
    }

    pub(crate) async fn stop(
        &self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<ContentReceipt, ContentError> {
        let mut current = self.service.lock().await;
        if let Some(service) = current.take() {
            let _ = service.stop.send(true);
            if let Some(replication) = service.replication {
                replication.stop().await;
            }
            let mut task = service.task;
            if timeout(Duration::from_secs(20), &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        discovery
            .withdraw_content_offer()
            .await
            .map_err(|_| ContentError::Unavailable)?;
        Ok(ContentReceipt::default())
    }

    pub(crate) async fn status(
        &self,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let service = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let (serving, publications) = if let Some(service) = service.as_ref() {
            let registry = service
                .registry
                .try_lock()
                .map_err(|_| ContentError::Busy)?;
            (
                !service.task.is_finished(),
                u32::try_from(registry.len()).map_err(|_| ContentError::Invalid)?,
            )
        } else {
            (false, 0)
        };
        let mut receipt = ContentReceipt {
            serving,
            publications,
            control_relay_peer_id: context
                .routes
                .content_discovery_control()
                .await
                .map(|peer| peer.to_string())
                .unwrap_or_default(),
            ..ContentReceipt::default()
        };
        if let Some(replication) = service.as_ref().and_then(|s| s.replication.as_ref()) {
            replication.receipt(&mut receipt).await?;
        }
        Ok(receipt)
    }

    pub(crate) async fn fetch(
        &self,
        request: ContentFetchRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let foreground = self.foreground.enter();
        let retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        let result = timeout(OPERATION_TIMEOUT, Self::fetch_inner(request, context))
            .await
            .map_err(|_| ContentError::Unavailable)?;
        drop(retrieval);
        drop(foreground);
        if result.is_ok() {
            self.start_replication(context).await;
        }
        result
    }

    pub(crate) async fn fetch_https(
        &self,
        request: HttpsContentFetchRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let foreground = self.foreground.enter();
        let retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        let result = timeout(OPERATION_TIMEOUT, https::fetch(request, context))
            .await
            .map_err(|_| ContentError::Unavailable)?;
        drop(retrieval);
        drop(foreground);
        if result.is_ok() {
            self.start_replication(context).await;
        }
        result
    }

    pub(crate) async fn download_https(
        &self,
        request: HttpsContentFetchRequest,
        context: &ControlContext,
        stream: &mut tokio::net::UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let foreground = self.foreground.enter();
        let retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        let result = timeout(
            OPERATION_TIMEOUT,
            https::download(request, context, stream, request_id, ready_sent),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        drop(retrieval);
        drop(foreground);
        if result.is_ok() {
            self.start_replication(context).await;
        }
        result
    }

    async fn start_replication(&self, context: &ControlContext) {
        let Ok(service) = self.service.try_lock() else {
            return;
        };
        let Some(service) = service.as_ref().filter(|s| !s.task.is_finished()) else {
            return;
        };
        let Some(replication) = &service.replication else {
            return;
        };
        replication
            .start(
                context.clone(),
                Arc::clone(&service.registry),
                Arc::clone(&self.foreground),
                service.stop.subscribe(),
            )
            .await;
    }

    async fn remember_provider(
        &self,
        peer: libp2p::PeerId,
        offer: volparossa_content::provider::VerifiedProviderOffer,
        manifest: [u8; 32],
    ) {
        let Ok(service) = self.service.try_lock() else {
            return;
        };
        if let Some(replication) = service.as_ref().and_then(|s| s.replication.as_ref()) {
            replication.remember(peer, offer, manifest).await;
        }
    }

    async fn fetch_inner(
        request: ContentFetchRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let manifest = verified(&request.manifest, &request.publisher_key)?;
        let output = PathBuf::from(request.output);
        if output.try_exists().map_err(|_| ContentError::Invalid)? {
            return Err(ContentError::Invalid);
        }
        let mut store =
            download_cache(&request.cache, limits(request.limits)?, request.reuse_cache)?;
        let policy = {
            let state = context.state.read().await;
            if !state.roles().client {
                return Err(ContentError::Policy);
            }
            state
                .active_policy(unix_millis())
                .ok_or(ContentError::Policy)?
        };
        // No plain-TCP, single-path or direct-provider fallback exists here.
        let connected = Box::pin(context.routes.connect_tcp(
            &context.config,
            &context.discovery,
            &context.helper,
        ))
        .await;
        if connected.is_err() {
            content_event(context, "CONTENT_FETCH_ROUTE_UNAVAILABLE").await;
            return Err(ContentError::Unavailable);
        }
        let Some(control_peer) = context.routes.content_discovery_control().await else {
            content_event(context, "CONTENT_FETCH_CONTROL_UNAVAILABLE").await;
            return Err(ContentError::Unavailable);
        };
        content_event(context, "CONTENT_FETCH_ROUTE_READY").await;
        let (provider_peer_ids, peer_bytes) =
            Self::pull_registered_providers(context, &manifest, &mut store, &policy, control_peer)
                .await?;
        let bytes =
            volparossa_content::reassemble_to_file(&manifest, &mut [&mut store], now(), &output)
                .map_err(|_| ContentError::Unavailable)?;
        Ok(ContentReceipt {
            bytes,
            chunks: u32::try_from(manifest.chunks().len()).map_err(|_| ContentError::Invalid)?,
            providers_used: u32::try_from(provider_peer_ids.len())
                .map_err(|_| ContentError::Invalid)?,
            provider_peer_ids,
            control_relay_peer_id: control_peer.to_string(),
            peer_bytes,
            ..ContentReceipt::default()
        })
    }

    /// Shared native/HTTPS chunk retrieval. This borrows only the verified native chunk
    /// authority; HTTPS callers must retain their separate original origin authorization.
    async fn pull_registered_providers(
        context: &ControlContext,
        manifest: &VerifiedManifest,
        store: &mut ChunkStore,
        policy: &volparossa_policy::VerifiedManifest,
        control_peer: libp2p::PeerId,
    ) -> Result<(Vec<String>, u64), ContentError> {
        if complete(manifest, store)? {
            return Ok((Vec::new(), 0));
        }
        let providers = context
            .discovery
            .discover_content_providers(control_peer, 16)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        let mut used = HashSet::new();
        let mut peer_bytes = 0_u64;
        for provider in providers {
            if complete(manifest, store)? {
                break;
            }
            if !context
                .routes
                .content_provider_is_distinct(&provider.peer_id)
                .await
            {
                continue;
            }
            let endpoint = provider.offer.endpoint();
            let current = context
                .state
                .read()
                .await
                .active_policy(unix_millis())
                .ok_or(ContentError::Policy)?;
            if current.policy_hash() != policy.policy_hash() {
                return Err(ContentError::Policy);
            }
            if provider.offer.validity().expires <= now() {
                continue;
            }
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
                content_event(context, "CONTENT_PROVIDER_ROUTE_FLOW_FAILED").await;
                continue;
            };
            let Ok(mut stream) =
                tls::connect(flow.stream_mut(), provider.peer_id, &provider.offer).await
            else {
                content_event(context, "CONTENT_PROVIDER_TLS_FAILED").await;
                continue;
            };
            let mut progress = TransferProgress::default();
            let pulled = pull_publication_with_progress(
                &mut stream,
                manifest,
                store,
                TransferLimits::default(),
                &mut progress,
            )
            .await;
            if pulled.is_ok() && tls::finish(&mut stream).await.is_err() {
                content_event(context, "CONTENT_PROVIDER_TLS_CLOSE_FAILED").await;
                return Err(ContentError::Unavailable);
            }
            drop(stream);
            if pulled.is_ok() && tls::finish(flow.stream_mut()).await.is_err() {
                content_event(context, "CONTENT_PROVIDER_ROUTE_CLOSE_FAILED").await;
                return Err(ContentError::Unavailable);
            }
            flow.shutdown();
            if pulled.is_err() {
                content_event(context, "CONTENT_PROVIDER_TRANSFER_FAILED").await;
            }
            // Includes verified inserts before a later failure, excluding old cache hits.
            let received = progress.bytes;
            peer_bytes = peer_bytes
                .checked_add(received)
                .ok_or(ContentError::Invalid)?;
            if received > 0 {
                used.insert(provider.peer_id.to_string());
                context
                    .content
                    .remember_provider(provider.peer_id, provider.offer, *manifest.manifest_id())
                    .await;
            }
        }
        let mut provider_peer_ids: Vec<_> = used.into_iter().collect();
        provider_peer_ids.sort_unstable();
        Ok((provider_peer_ids, peer_bytes))
    }
}

fn register(
    registry: &mut PublicationRegistry,
    request: &ContentServeRequest,
    manifest: VerifiedManifest,
    cache_limits: CacheLimits,
) -> Result<(), ContentError> {
    let root = PathBuf::from(&request.cache);
    let result = if request.replication.is_some() {
        let key: [u8; 32] = request
            .publisher_key
            .as_slice()
            .try_into()
            .map_err(|_| ContentError::Invalid)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| ContentError::Invalid)?;
        let signed =
            SignedManifest::decode(&request.manifest).map_err(|_| ContentError::Invalid)?;
        registry.register_shareable(signed, &key, root, cache_limits, now())
    } else {
        registry.register(manifest, root, cache_limits, now())
    };
    result.map_err(|_| ContentError::Invalid)
}

fn make_offer(
    signer: &SigningKey,
    endpoint: ProviderEndpoint,
) -> Result<SignedProviderOffer, ContentError> {
    let created = now();
    SignedProviderOffer::sign(
        signer,
        endpoint,
        Validity {
            created,
            expires: created + OFFER_LIFETIME,
        },
    )
    .map_err(|_| ContentError::Invalid)
}

fn now() -> u64 {
    unix_millis() / 1000
}

async fn content_event(context: &ControlContext, code: &'static str) {
    context.state.write().await.log(
        volparossa_local_control::LogLevel::Info,
        code,
        unix_millis(),
    );
}

fn serving_receipt(registry: &PublicationRegistry) -> Result<ContentReceipt, ContentError> {
    Ok(ContentReceipt {
        serving: true,
        publications: u32::try_from(registry.len()).map_err(|_| ContentError::Invalid)?,
        ..ContentReceipt::default()
    })
}

fn verified(bytes: &[u8], key: &[u8]) -> Result<VerifiedManifest, ContentError> {
    let key: [u8; 32] = key.try_into().map_err(|_| ContentError::Invalid)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| ContentError::Invalid)?;
    SignedManifest::decode(bytes)
        .and_then(|signed| signed.verify(&key, now()))
        .map_err(|_| ContentError::Invalid)
}

fn limits(value: Option<ContentCacheLimits>) -> Result<CacheLimits, ContentError> {
    let value = value.ok_or(ContentError::Invalid)?;
    Ok(CacheLimits {
        max_bytes: value.quota_bytes,
        max_entries: value.max_entries as usize,
        min_free_bytes: value.min_free_bytes,
    })
}

fn download_cache(
    path: &str,
    limits: CacheLimits,
    reuse: bool,
) -> Result<ChunkStore, ContentError> {
    let root = PathBuf::from(path);
    if reuse {
        ChunkStore::open(&root, limits)
    } else {
        ChunkStore::create(&root, limits)
    }
    .map_err(|_| ContentError::Invalid)
}

fn complete(manifest: &VerifiedManifest, store: &mut ChunkStore) -> Result<bool, ContentError> {
    for chunk in manifest.chunks() {
        if store
            .get(chunk.id())
            .map_err(|_| ContentError::Invalid)?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
