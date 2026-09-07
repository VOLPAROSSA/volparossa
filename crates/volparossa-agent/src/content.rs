//! Explicit public content serving and protected native retrieval.
//!
//! Neither browsing capture nor a default listener is enabled. Provider offers are only
//! discovery hints: every destination still passes the existing signed Exit policy.

use std::{collections::HashSet, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::{
    net::TcpListener,
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
    time::{interval, timeout},
};
use volparossa_content::provider::{
    ProviderEndpoint, PublicationRegistry, SignedProviderOffer, pull_publication, serve_publication,
};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{CacheLimits, ChunkStore, SignedManifest, Validity, VerifiedManifest};
use volparossa_identity::Identity;
use volparossa_local_control::{
    ContentCacheLimits, ContentFetchRequest, ContentReceipt, ContentServeRequest,
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
    service: Arc<Mutex<Option<Service>>>,
    retrieval: Arc<Mutex<()>>,
}

struct Service {
    registry: Arc<Mutex<PublicationRegistry>>,
    endpoint: ProviderEndpoint,
    bind: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
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
            service: Arc::new(Mutex::new(None)),
            retrieval: Arc::new(Mutex::new(())),
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
            let mut registry = active.registry.try_lock().map_err(|_| ContentError::Busy)?;
            registry
                .register(manifest, PathBuf::from(request.cache), cache_limits, now())
                .map_err(|_| ContentError::Invalid)?;
            return Ok(ContentReceipt {
                serving: true,
                publications: u32::try_from(registry.len()).map_err(|_| ContentError::Invalid)?,
                ..ContentReceipt::default()
            });
        }
        let mut registry = PublicationRegistry::new();
        registry
            .register(manifest, PathBuf::from(request.cache), cache_limits, now())
            .map_err(|_| ContentError::Invalid)?;
        let listener = TcpListener::bind(bind)
            .await
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
        });
        Ok(ContentReceipt {
            serving: true,
            publications: 1,
            ..ContentReceipt::default()
        })
    }

    fn offer(&self, endpoint: ProviderEndpoint) -> Result<SignedProviderOffer, ContentError> {
        make_offer(&self.signer, endpoint)
    }

    async fn serve_loop(
        listener: TcpListener,
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
                    let Ok((mut stream, _source)) = accepted else { break; };
                    let registry = Arc::clone(&registry);
                    sessions.spawn(async move {
                        // One owned-cache session at a time; no unbounded queue or lock wait.
                        let Ok(registry) = registry.try_lock() else { return; };
                        let _ = serve_publication(&mut stream, &registry, TransferLimits::default()).await;
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
        Ok(ContentReceipt {
            serving,
            publications,
            control_relay_peer_id: context
                .routes
                .content_discovery_control()
                .await
                .map(|peer| peer.to_string())
                .unwrap_or_default(),
            ..ContentReceipt::default()
        })
    }

    pub(crate) async fn fetch(
        &self,
        request: ContentFetchRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let _retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        timeout(OPERATION_TIMEOUT, Self::fetch_inner(request, context))
            .await
            .map_err(|_| ContentError::Unavailable)?
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
        let mut store = ChunkStore::create(&PathBuf::from(request.cache), limits(request.limits)?)
            .map_err(|_| ContentError::Invalid)?;
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
        Box::pin(
            context
                .routes
                .connect_tcp(&context.config, &context.discovery, &context.helper),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        let control_peer = context
            .routes
            .content_discovery_control()
            .await
            .ok_or(ContentError::Unavailable)?;
        let providers = context
            .discovery
            .discover_content_providers(control_peer, 16)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        let mut used = HashSet::new();
        for provider in providers {
            if complete(&manifest, &mut store)? {
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
                continue;
            };
            let before = store.usage().bytes;
            let _progress = pull_publication(
                flow.stream_mut(),
                &manifest,
                &mut store,
                TransferLimits::default(),
            )
            .await;
            flow.shutdown();
            // A later session error does not undo chunks already authenticated and stored.
            if store.usage().bytes > before {
                used.insert(provider.peer_id.to_string());
            }
        }
        let bytes =
            volparossa_content::reassemble_to_file(&manifest, &mut [&mut store], now(), &output)
                .map_err(|_| ContentError::Unavailable)?;
        let mut provider_peer_ids: Vec<_> = used.into_iter().collect();
        provider_peer_ids.sort_unstable();
        Ok(ContentReceipt {
            bytes,
            chunks: u32::try_from(manifest.chunks().len()).map_err(|_| ContentError::Invalid)?,
            providers_used: u32::try_from(provider_peer_ids.len())
                .map_err(|_| ContentError::Invalid)?,
            provider_peer_ids,
            control_relay_peer_id: control_peer.to_string(),
            ..ContentReceipt::default()
        })
    }
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
