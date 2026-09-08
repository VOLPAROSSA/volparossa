//! Explicitly configured, automatic storage-only contribution after verified public downloads.
//! Queue entries contain no URL, recipient key, output path or reusable HTTPS authority.

use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Duration};

use tokio::{
    sync::{Mutex, Notify, watch},
    task::JoinHandle,
    time::{Instant, interval, timeout},
};
use volparossa_config::ContentContributionConfig;
use volparossa_content::{
    CacheLimits, ChunkStore, SignedManifest, VerifiedManifest,
    origin_https::OriginAuthorizedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    provider::replication::{LocalReplicaLimits, admit_public_replica},
    provider::{ProviderEndpoint, PublicationRegistry},
};
use volparossa_local_control::{ContentCacheLimits, ContentReplicationConfig};

use super::{
    ContentError, ContentRuntime, ServiceOptions, content_event, now,
    replication::ReplicationRuntime,
    replication_budget::{Foreground, IdleBudget},
    serving_policy,
};
use crate::{control::ControlContext, unix_millis};

const MAX_PENDING: usize = 16;
const QUEUE_LIFETIME: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests;

struct Pending {
    signed: SignedManifest,
    authorized: VerifiedManifest,
    root: PathBuf,
    limits: CacheLimits,
    expires: u64,
    deadline: Instant,
}

impl Pending {
    fn live(&self) -> bool {
        now() < self.expires && Instant::now() < self.deadline
    }
}

pub(super) struct ContributionRuntime {
    config: ContentContributionConfig,
    replication: Arc<ReplicationRuntime>,
    queue: Mutex<VecDeque<Pending>>,
    wake: Notify,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ContentRuntime {
    /// Invoked by the startup supervisor only after the Discovery actor is running.
    pub(crate) async fn start_contribution(
        &self,
        context: &ControlContext,
    ) -> Result<(), ContentError> {
        let config = &context.config.content_contribution;
        if !config.enabled {
            return Ok(());
        }
        let mut service = self.service.lock().await;
        // Do not replace an explicit endpoint, cache, mailbox or live service.
        if service.is_some() || self.contribution.lock().await.is_some() {
            return Err(ContentError::Busy);
        }
        let policy = serving_policy(context).await?;
        let bind: std::net::SocketAddr = config
            .bind_address
            .parse()
            .map_err(|_| ContentError::Invalid)?;
        let endpoint = ProviderEndpoint::new(&config.advertised_hostname, bind.port())
            .map_err(|_| ContentError::Invalid)?;
        policy
            .authorize_domain(
                unix_millis(),
                endpoint.hostname(),
                volparossa_policy::TransportProtocol::Tcp,
                endpoint.port(),
            )
            .map_err(|_| ContentError::Policy)?;
        let mut registry = PublicationRegistry::new();
        registry.set_name_lookup(true);
        let replication =
            ReplicationRuntime::create_public(replication_config(config)?, &mut registry)?;
        let runtime = Arc::new(ContributionRuntime {
            config: config.clone(),
            replication: Arc::clone(&replication),
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            worker: Mutex::new(None),
        });
        let active = self
            .start_service(
                context,
                bind,
                endpoint,
                registry,
                ServiceOptions {
                    replication: Some(replication),
                    name_lookup: true,
                    automatic: true,
                },
            )
            .await?;
        let worker = tokio::spawn(Arc::clone(&runtime).run(
            context.clone(),
            Arc::clone(&active.registry),
            Arc::clone(&self.foreground),
            active.stop.subscribe(),
            active.endpoint.clone(),
        ));
        *runtime.worker.lock().await = Some(worker);
        *self.contribution.lock().await = Some(runtime);
        *service = Some(active);
        drop(service);
        content_event(context, "CONTENT_CONTRIBUTION_STARTED").await;
        Ok(())
    }

    /// Enabling contribution explicitly opts ordinary public native downloads in; it never
    /// opts private-message/mailbox content in. Native callers retain independent key trust.
    pub(crate) async fn contribute_native(
        &self,
        signed: SignedManifest,
        authorized: VerifiedManifest,
        source_root: PathBuf,
        source_limits: CacheLimits,
    ) {
        let expires = authorized.validity().expires;
        self.queue_contribution(signed, authorized, source_root, source_limits, expires)
            .await;
    }

    /// Only a currently live cooperative-origin result can admit HTTP bytes. The queue stores
    /// the original native envelope and an admission deadline, never the URL/HTTP authority.
    pub(crate) async fn contribute_https(
        &self,
        authorized: &OriginAuthorizedManifest,
        source_root: PathBuf,
        source_limits: CacheLimits,
    ) {
        let Ok(expires) = authorized.check_validity(now()) else {
            return;
        };
        let Ok(signed) = SignedManifest::decode(authorized.native_manifest_bytes()) else {
            return;
        };
        self.queue_contribution(
            signed,
            authorized.manifest().clone(),
            source_root,
            source_limits,
            expires,
        )
        .await;
    }

    /// Only the HTTPS caller's whole-object-verified digest result reaches this admission seam.
    pub(crate) async fn contribute_https_digest(
        &self,
        authority: &volparossa_content::origin_https::OriginAuthorizedDigest,
        signed: SignedManifest,
        manifest: VerifiedManifest,
        root: PathBuf,
        limits: CacheLimits,
    ) {
        let Ok(expires) = authority.check_validity(now()) else {
            return;
        };
        if authority.verify_candidate(&signed, now()).is_err() {
            return;
        }
        self.queue_contribution(signed, manifest, root, limits, expires)
            .await;
    }

    async fn queue_contribution(
        &self,
        signed: SignedManifest,
        authorized: VerifiedManifest,
        root: PathBuf,
        limits: CacheLimits,
        expires: u64,
    ) {
        if authorized.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
            || authorized.chunks().is_empty()
            || expires <= now()
        {
            return;
        }
        let runtime = self.contribution.lock().await.clone();
        let Some(runtime) = runtime else {
            return;
        };
        if root == PathBuf::from(&runtime.config.cache) {
            return;
        }
        let mut queue = runtime.queue.lock().await;
        queue.retain(Pending::live);
        if queue.len() >= MAX_PENDING
            || queue
                .iter()
                .any(|entry| entry.authorized.manifest_id() == authorized.manifest_id())
        {
            return;
        }
        let remaining = Duration::from_secs(expires.saturating_sub(now())).min(QUEUE_LIFETIME);
        queue.push_back(Pending {
            signed,
            authorized,
            root,
            limits,
            expires,
            deadline: Instant::now() + remaining,
        });
        runtime.wake.notify_one();
    }
}

fn replication_config(
    config: &ContentContributionConfig,
) -> Result<ContentReplicationConfig, ContentError> {
    let root = PathBuf::from(&config.cache);
    let reuse = match std::fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) | Ok(_) => return Err(ContentError::Invalid),
    };
    Ok(ContentReplicationConfig {
        replica_cache: config.cache.clone(),
        reuse_replica_cache: reuse,
        limits: Some(ContentCacheLimits {
            quota_bytes: config.quota_bytes,
            max_entries: config.max_entries,
            min_free_bytes: config.min_free_bytes,
        }),
        max_bytes: config.max_bytes,
        max_chunks: config.max_chunks,
    })
}

impl ContributionRuntime {
    pub(super) async fn stop(&self) {
        if let Some(mut worker) = self.worker.lock().await.take() {
            if timeout(Duration::from_secs(2), &mut worker).await.is_err() {
                worker.abort();
                let _ = worker.await;
            }
        }
        self.queue.lock().await.clear();
    }

    async fn run(
        self: Arc<Self>,
        context: ControlContext,
        registry: Arc<Mutex<PublicationRegistry>>,
        foreground: Arc<Foreground>,
        mut stop: watch::Receiver<bool>,
        endpoint: ProviderEndpoint,
    ) {
        let mut tick = interval(Duration::from_secs(5));
        let mut next = Instant::now();
        loop {
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                () = self.wake.notified() => {},
                _ = tick.tick() => {},
            }
            if *stop.borrow() {
                break;
            }
            if foreground.active() || Instant::now() < next {
                continue;
            }
            let Ok(policy) = serving_policy(&context).await else {
                continue;
            };
            if policy
                .authorize_domain(
                    unix_millis(),
                    endpoint.hostname(),
                    volparossa_policy::TransportProtocol::Tcp,
                    endpoint.port(),
                )
                .is_err()
            {
                continue;
            }
            let Some(slot) = self.replication.try_background_slot() else {
                continue;
            };
            if self.replication.reclaim(&registry, now()).await.is_err() {
                continue;
            }
            let Some(pending) = self.queue.lock().await.pop_front() else {
                continue;
            };
            if !pending.live() {
                continue;
            }
            let Some(budget) = IdleBudget::new(&context.config) else {
                continue;
            };
            let mut changed = foreground.subscribe();
            if foreground.active() {
                self.queue.lock().await.push_front(pending);
                continue;
            }
            next = Instant::now() + budget.cooldown(self.config.max_bytes);
            let progress = tokio::select! {
                biased;
                _ = stop.changed() => None,
                _ = changed.changed() => None,
                () = tokio::time::sleep(Duration::from_secs(30)) => None,
                result = self.copy(&pending, &budget) => Some(result),
            };
            if pending.live() && progress != Some(false) {
                self.queue.lock().await.push_back(pending);
            }
            if *stop.borrow() {
                break;
            }
            if foreground.active() {
                continue; // Journaled prefixes are restored only after owner work releases us.
            }
            // Native helper persists before registration; restore rechecks exact cached chunks.
            let usable = self.replication.reclaim(&registry, now()).await.is_ok()
                && registry.lock().await.has_live_publications(now());
            if usable {
                if let Ok(offer) = super::make_offer(&context.content.signer, endpoint.clone()) {
                    if context
                        .discovery
                        .register_content_offer(offer)
                        .await
                        .is_ok()
                    {
                        content_event(&context, "CONTENT_CONTRIBUTION_CHUNKS_AVAILABLE").await;
                    }
                }
            }
            drop(slot);
            if *stop.borrow() {
                break;
            }
            self.replication
                .start(
                    context.clone(),
                    Arc::clone(&registry),
                    Arc::clone(&foreground),
                    stop.clone(),
                )
                .await;
        }
    }

    /// One chunk per quiet boundary. Synchronous disk work is bounded to this single chunk;
    /// cancellation never detaches a writer that could outlive the shared background slot.
    async fn copy(&self, pending: &Pending, budget: &IdleBudget) -> bool {
        let mut bytes = self.config.max_bytes;
        let mut admitted = false;
        for _ in 0..self.config.max_chunks {
            budget.wait_until_quiet().await;
            if !pending.live() {
                return false;
            }
            if bytes == 0 {
                return admitted;
            }
            // A duplicate adds journal ownership without adding payload bytes. Charge the
            // largest eligible single read, not net cache growth, against this I/O batch.
            let charge = pending
                .authorized
                .chunks()
                .iter()
                .map(|chunk| u64::from(chunk.length()))
                .filter(|length| *length <= bytes)
                .max()
                .unwrap_or(0);
            match self.copy_one(pending, bytes) {
                Ok(Some(_)) => {
                    bytes = bytes.saturating_sub(charge);
                    admitted = true;
                }
                Err(ContentError::Busy) => return true,
                Ok(None) => return admitted,
                Err(_) => return false,
            }
        }
        true
    }

    fn copy_one(&self, pending: &Pending, bytes: u64) -> Result<Option<u64>, ContentError> {
        if !pending.live() {
            return Ok(None);
        }
        let mut source =
            ChunkStore::open(&pending.root, pending.limits).map_err(|_| ContentError::Busy)?;
        let mut destination = ChunkStore::open(
            &PathBuf::from(&self.config.cache),
            CacheLimits {
                max_bytes: self.config.quota_bytes,
                max_entries: self.config.max_entries as usize,
                min_free_bytes: self.config.min_free_bytes,
            },
        )
        .map_err(|_| ContentError::Busy)?;
        let progress = admit_public_replica(
            &pending.signed,
            &pending.authorized,
            &mut source,
            &mut destination,
            LocalReplicaLimits {
                max_chunks: 1,
                max_bytes: bytes,
            },
            now(),
        )
        .map_err(|_| ContentError::Invalid)?;
        Ok((!progress.replicas.is_empty()).then_some(progress.bytes))
    }
}
