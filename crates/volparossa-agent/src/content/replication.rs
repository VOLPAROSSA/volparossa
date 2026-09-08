//! Small post-download replicas; no content catalogue, new routes or consumer trust.

use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use libp2p::PeerId;
use tokio::{
    sync::{Mutex, OwnedMutexGuard, watch},
    task::JoinHandle,
};
use volparossa_content::provider::replication::{
    ReplicationExclusions, ReplicationLimits, ReplicationProgress, persist_replicas,
    pull_public_replicas_with_admission, pull_replicas_with_admission, restore_public_replicas,
    restore_replicas,
};
use volparossa_content::provider::{ProviderError, PublicationRegistry, VerifiedProviderOffer};
use volparossa_content::{CacheLimits, CacheUsage, ChunkId, ChunkStore};
use volparossa_local_control::{ContentReceipt, ContentReplicationConfig};

use super::replication_budget::{Foreground, IdleBudget};
use super::{ContentError, content_event, limits, now};
use crate::{control::ControlContext, unix_millis};

const MAX_CONTACTS: usize = 16;
const MAX_REMEMBERED_CHUNKS: usize = 48;

struct Contact {
    peer: PeerId,
    offer: VerifiedProviderOffer,
    foreground: [u8; 32],
}

struct State {
    contacts: VecDeque<Contact>,
    chunks: VecDeque<ChunkId>,
    publications: BTreeSet<[u8; 32]>,
    usage: CacheUsage,
    next: Instant,
}

pub(super) struct ReplicationRuntime {
    config: ContentReplicationConfig,
    root: PathBuf,
    limits: CacheLimits,
    state: Mutex<State>,
    job: Mutex<Option<JoinHandle<()>>>,
    background: Arc<Mutex<()>>,
    public_only: bool,
}

impl ReplicationRuntime {
    pub(super) fn create(
        config: ContentReplicationConfig,
        registry: &mut PublicationRegistry,
    ) -> Result<Arc<Self>, ContentError> {
        Self::create_mode(config, registry, false)
    }

    pub(super) fn create_public(
        config: ContentReplicationConfig,
        registry: &mut PublicationRegistry,
    ) -> Result<Arc<Self>, ContentError> {
        Self::create_mode(config, registry, true)
    }

    fn create_mode(
        config: ContentReplicationConfig,
        registry: &mut PublicationRegistry,
        public_only: bool,
    ) -> Result<Arc<Self>, ContentError> {
        let cache_limits = limits(config.limits)?;
        if !(64..=1024 * 1024).contains(&config.max_bytes)
            || !(1..=4).contains(&config.max_chunks)
            || cache_limits.max_bytes > 256 * 1024 * 1024
        {
            return Err(ContentError::Invalid);
        }
        let root = PathBuf::from(&config.replica_cache);
        // Reopen only on explicit request; the store checks UID/inode, exclusive ownership,
        // limits and fixed-name metadata. Nothing is inferred from arbitrary directory files.
        let mut store = if config.reuse_replica_cache {
            ChunkStore::open(&root, cache_limits)
        } else {
            ChunkStore::create(&root, cache_limits)
        }
        .map_err(|_| ContentError::Invalid)?;
        let restored = if public_only {
            restore_public_replicas(&mut store, now())
        } else {
            restore_replicas(&mut store, now())
        }
        .map_err(|_| ContentError::Invalid)?;
        let usage = store.usage();
        drop(store);
        let mut chunks = VecDeque::new();
        let mut publications = BTreeSet::new();
        for replica in restored {
            if public_only
                && replica.content_type()
                    == volparossa_content::private_message::PRIVATE_MESSAGE_CONTENT_TYPE
            {
                continue;
            }
            let id = *replica.manifest_id();
            remember_chunks(&mut chunks, replica.chunk_ids());
            // Explicit foreground registrations take precedence. A full registry is not
            // corrupt storage: retain excess metadata for a later explicitly started service.
            if registry.contains(&id) || registry.len() >= 64 {
                continue;
            }
            registry
                .register_replica(replica, root.clone(), cache_limits, now())
                .map_err(|_| ContentError::Invalid)?;
            publications.insert(id);
        }
        Ok(Arc::new(Self {
            config,
            root,
            limits: cache_limits,
            state: Mutex::new(State {
                contacts: VecDeque::new(),
                chunks,
                publications,
                usage,
                next: Instant::now(),
            }),
            job: Mutex::new(None),
            background: Arc::new(Mutex::new(())),
            public_only,
        }))
    }

    /// One owner for local contribution copies and optional network exchanges alike.
    pub(super) fn try_background_slot(&self) -> Option<OwnedMutexGuard<()>> {
        Arc::clone(&self.background).try_lock_owned().ok()
    }

    /// Foreground publication waits briefly for an already cancelled optional writer to exit.
    pub(super) async fn publication_slot(&self) -> Result<OwnedMutexGuard<()>, ContentError> {
        tokio::time::timeout(
            Duration::from_secs(2),
            Arc::clone(&self.background).lock_owned(),
        )
        .await
        .map_err(|_| ContentError::Busy)
    }

    pub(super) fn matches(&self, config: &ContentReplicationConfig) -> bool {
        let mut requested = config.clone();
        requested.reuse_replica_cache = self.config.reuse_replica_cache;
        self.config == requested
    }

    pub(super) async fn receipt(&self, receipt: &mut ContentReceipt) -> Result<(), ContentError> {
        let store = ChunkStore::open(&self.root, self.limits).map_err(|_| ContentError::Busy)?;
        let mut state = self.state.lock().await;
        state.usage = store.usage();
        drop(store);
        receipt.replication_enabled = true;
        receipt.replica_bytes = state.usage.bytes;
        receipt.replica_chunks = u32::try_from(state.usage.entries).unwrap_or(u32::MAX);
        receipt.replica_publications = u32::try_from(state.publications.len()).unwrap_or(u32::MAX);
        Ok(())
    }

    pub(super) async fn remember(
        &self,
        peer: PeerId,
        offer: VerifiedProviderOffer,
        foreground: [u8; 32],
    ) {
        let mut state = self.state.lock().await;
        state
            .contacts
            .retain(|contact| contact.peer != peer && contact.offer.validity().expires > now());
        if state.contacts.len() >= MAX_CONTACTS {
            state.contacts.pop_front();
        }
        state.contacts.push_back(Contact {
            peer,
            offer,
            foreground,
        });
    }

    pub(super) async fn stop(&self) {
        if let Some(mut task) = self.job.lock().await.take() {
            if tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }

    pub(super) async fn reclaim(
        &self,
        registry: &Mutex<PublicationRegistry>,
        at: u64,
    ) -> Result<bool, ContentError> {
        let mut registry = registry.try_lock().map_err(|_| ContentError::Busy)?;
        let result = registry
            .reclaim_replica_cache(&self.root, self.limits, at)
            .map_err(|_| ContentError::Busy)?;
        let mut state = self.state.lock().await;
        state.usage = result.usage;
        state.publications.retain(|id| {
            registry.contains(id)
                && result
                    .live
                    .iter()
                    .any(|replica| replica.manifest_id() == id)
        });
        state.chunks.clear();
        for replica in result.live {
            if self.public_only
                && replica.content_type()
                    == volparossa_content::private_message::PRIVATE_MESSAGE_CONTENT_TYPE
            {
                continue;
            }
            remember_chunks(&mut state.chunks, replica.chunk_ids());
            let id = *replica.manifest_id();
            if registry.contains(&id) || registry.len() >= 64 {
                continue;
            }
            registry
                .register_replica(replica, self.root.clone(), self.limits, at)
                .map_err(|_| ContentError::Invalid)?;
            state.publications.insert(id);
        }
        Ok(!result.expired_manifest_ids.is_empty())
    }

    pub(super) async fn start(
        self: &Arc<Self>,
        context: ControlContext,
        registry: Arc<Mutex<PublicationRegistry>>,
        foreground: Arc<Foreground>,
        mut stop: watch::Receiver<bool>,
    ) {
        let Ok(mut job) = self.job.try_lock() else {
            return;
        };
        if job.as_ref().is_some_and(|task| !task.is_finished()) || *stop.borrow() {
            return;
        }
        if foreground.active() {
            return;
        }
        let Some(background) = self.try_background_slot() else {
            return;
        };
        match self.reclaim(&registry, now()).await {
            Ok(true) => content_event(&context, "CONTENT_REPLICATION_EXPIRED_RECLAIMED").await,
            Ok(false) => {}
            Err(_) => return, // Busy or unsafe storage never authorizes speculative quota credit.
        }
        let Some(budget) = IdleBudget::new(&context.config) else {
            content_event(&context, "CONTENT_REPLICATION_ACCOUNTING_UNAVAILABLE").await;
            return;
        };
        let (contact, exclusions) = {
            let mut state = self.state.lock().await;
            if state.next > Instant::now()
                || state.publications.len() >= 64
                || state.usage.entries >= self.limits.max_entries
                || state.usage.bytes >= self.limits.max_bytes
            {
                return;
            }
            let Some(contact) = state.contacts.pop_front() else {
                return;
            };
            if contact.offer.validity().expires <= now() {
                return;
            }
            let exclusions = ReplicationExclusions {
                manifest_ids: vec![contact.foreground],
                chunk_ids: state.chunks.iter().copied().collect(),
            };
            // Reserve a conservative full-session budget even on early failure/cancellation.
            state.next = Instant::now() + budget.cooldown(self.config.max_bytes);
            (contact, exclusions)
        };
        let runtime = Arc::clone(self);
        *job = Some(tokio::spawn(async move {
            let _background = background;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            let mut owner_change = foreground.subscribe();
            if foreground.active() || *stop.borrow() {
                return;
            }
            let ready = tokio::select! {
                biased;
                _ = stop.changed() => false,
                _ = owner_change.changed() => false,
                () = tokio::time::sleep_until(deadline) => false,
                () = budget.wait_until_quiet() => true,
            };
            if !ready {
                return;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => {},
                _ = owner_change.changed() => {},
                () = tokio::time::sleep_until(deadline) => {},
                () = runtime.exchange(&context, &registry, contact, &exclusions, &budget) => {},
            }
            // Cancellation can retain independently verified chunks. Count the owned store,
            // not only the last complete protocol receipt; metadata is not invented for them.
            if let Ok(store) = ChunkStore::open(&runtime.root, runtime.limits) {
                runtime.state.lock().await.usage = store.usage();
            }
        }));
    }

    async fn exchange(
        &self,
        context: &ControlContext,
        registry: &Mutex<PublicationRegistry>,
        contact: Contact,
        exclusions: &ReplicationExclusions,
        budget: &IdleBudget,
    ) {
        if !context
            .routes
            .content_provider_is_distinct(&contact.peer)
            .await
        {
            return;
        }
        let policy = {
            let state = context.state.read().await;
            if !state.roles().client || !state.roles().relay {
                return;
            }
            let Some(policy) = state.active_policy(unix_millis()) else {
                return;
            };
            policy
        };
        if contact.offer.validity().expires <= now() {
            return;
        }
        let endpoint = contact.offer.endpoint();
        // Reuse the established protected route; never dial the peer directly or create a route
        // for optional cache work. The current policy still authorizes the exact destination.
        let Ok(mut flow) = context
            .routes
            .open_content_stream(&policy, endpoint.hostname(), endpoint.port(), unix_millis())
            .await
        else {
            return;
        };
        async {
            let Ok(mut stream) =
                super::tls::connect(flow.stream_mut(), contact.peer, &contact.offer).await
            else {
                return;
            };
            let Ok(mut store) = ChunkStore::open(&self.root, self.limits) else {
                return;
            };
            let progress = self
                .pull(&mut stream, &mut store, exclusions, budget)
                .await
                .ok();
            if progress.is_some() && super::tls::finish(&mut stream).await.is_err() {
                return;
            }
            drop(stream);
            if progress.is_some() && super::tls::finish(flow.stream_mut()).await.is_err() {
                return;
            }
            if let Some(progress) = &progress {
                // Persist before exposing any new registration. Failure retains only owned
                // chunks, never an unjournaled re-serving claim or a renewed expiry.
                if persist_replicas(&mut store, &progress.replicas, now()).is_err() {
                    return;
                }
            }
            let usage = store.usage();
            drop(store); // Registration must independently reopen and verify the owned cache.
            self.state.lock().await.usage = usage;
            let Some(progress) = progress else {
                return;
            };
            let Ok(mut registry) = registry.try_lock() else {
                return;
            };
            let mut state = self.state.lock().await;
            let mut registered = false;
            for replica in progress.replicas {
                let id = *replica.manifest_id();
                let chunks = replica.chunk_ids().to_vec();
                if state.publications.contains(&id)
                    || registry
                        .register_replica(replica, self.root.clone(), self.limits, now())
                        .is_ok()
                {
                    state.publications.insert(id);
                    registered = true;
                    remember_chunks(&mut state.chunks, &chunks);
                }
            }
            drop(state);
            drop(registry);
            if registered {
                content_event(context, "CONTENT_REPLICATION_CHUNKS_AVAILABLE").await;
            }
        }
        .await;
        flow.shutdown();
    }

    async fn pull<S>(
        &self,
        stream: &mut S,
        store: &mut ChunkStore,
        exclusions: &ReplicationExclusions,
        budget: &IdleBudget,
    ) -> Result<ReplicationProgress, ProviderError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let transfer_limits = ReplicationLimits {
            max_chunks: self.config.max_chunks as usize,
            max_wire_bytes: self.config.max_bytes,
            ..ReplicationLimits::default()
        };
        // The provider waits for credit: sample owner demand without counting our
        // active payload, and never renew the original deadline or reserved budget.
        let admission = || async {
            budget.wait_until_quiet().await;
            true
        };
        if self.public_only {
            pull_public_replicas_with_admission(
                stream,
                store,
                transfer_limits,
                exclusions,
                admission,
            )
            .await
        } else {
            pull_replicas_with_admission(stream, store, transfer_limits, exclusions, admission)
                .await
        }
    }
}

fn remember_chunks(remembered: &mut VecDeque<ChunkId>, chunks: &[ChunkId]) {
    for chunk in chunks {
        remembered.retain(|known| known != chunk);
        if remembered.len() >= MAX_REMEMBERED_CHUNKS {
            remembered.pop_front();
        }
        remembered.push_back(*chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use volparossa_content::provider::serve_publication;
    use volparossa_content::transfer::TransferLimits;
    use volparossa_content::{Metadata, Publication, SignedManifest, Validity, publish};
    use volparossa_local_control::ContentCacheLimits;

    fn test_publication(store: &mut ChunkStore, key: &SigningKey) -> SignedManifest {
        publish(
            &mut &b"owned replica"[..],
            Publication {
                metadata: Metadata {
                    name: "explicit restart fixture".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: 13,
                validity: Validity {
                    created: now(),
                    expires: now() + 600,
                },
            },
            key,
            store,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn restored_metadata_does_not_replace_primary_or_fail_a_full_registry() {
        let directory = tempfile::tempdir().unwrap();
        let source_root = directory.path().join("source");
        let replica_root = directory.path().join("replicas");
        let cache_limits = CacheLimits {
            max_bytes: 1024,
            max_entries: 4,
            min_free_bytes: 0,
        };
        let mut source = ChunkStore::create(&source_root, cache_limits).unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let manifest = test_publication(&mut source, &key);
        let id = *manifest
            .verify(&key.verifying_key(), now())
            .unwrap()
            .manifest_id();
        drop(source);
        let mut registry = PublicationRegistry::new();
        registry
            .register_shareable(
                manifest,
                &key.verifying_key(),
                source_root.clone(),
                cache_limits,
                now(),
            )
            .unwrap();
        let mut replica_store = ChunkStore::create(&replica_root, cache_limits).unwrap();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let exclusions = ReplicationExclusions::default();
        let (received, sent) = tokio::join!(
            pull_replicas_with_admission(
                &mut client,
                &mut replica_store,
                ReplicationLimits::default(),
                &exclusions,
                || async { true }
            ),
            serve_publication(&mut server, &registry, TransferLimits::default()),
        );
        sent.unwrap();
        persist_replicas(&mut replica_store, &received.unwrap().replicas, now()).unwrap();
        drop(replica_store);
        let config = ContentReplicationConfig {
            replica_cache: replica_root.to_str().unwrap().to_owned(),
            limits: Some(ContentCacheLimits {
                quota_bytes: 1024,
                max_entries: 4,
                min_free_bytes: 0,
            }),
            max_bytes: 1024,
            max_chunks: 1,
            reuse_replica_cache: true,
        };
        let runtime = ReplicationRuntime::create(config.clone(), &mut registry).unwrap();
        let mut receipt = ContentReceipt::default();
        runtime.receipt(&mut receipt).await.unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(receipt.replica_publications, 0); // Existing primary is not silently replaced.
        drop(runtime);
        assert!(registry.remove(&id));
        for _ in 0..64 {
            let mut source = ChunkStore::open(&source_root, cache_limits).unwrap();
            let manifest = test_publication(&mut source, &key);
            let checked = manifest.verify(&key.verifying_key(), now()).unwrap();
            drop(source);
            registry
                .register(checked, source_root.clone(), cache_limits, now())
                .unwrap();
        }
        let runtime = ReplicationRuntime::create(config, &mut registry).unwrap();
        runtime.receipt(&mut receipt).await.unwrap();
        assert_eq!(registry.len(), 64);
        assert_eq!(receipt.replica_publications, 0);
        assert_eq!(receipt.replica_chunks, 1);
        let mut store = ChunkStore::open(&replica_root, cache_limits).unwrap();
        assert_eq!(restore_replicas(&mut store, now()).unwrap().len(), 1);
        drop(store);
        // Explicit library clock, not an elapsed-time or networking claim. The normal
        // runtime maintenance refreshes capacity even when unrelated primaries fill serving.
        let registry = Mutex::new(registry);
        assert!(runtime.reclaim(&registry, now() + 601).await.unwrap());
        runtime.receipt(&mut receipt).await.unwrap();
        assert_eq!(registry.lock().await.len(), 64);
        assert_eq!(receipt.replica_publications, 0);
        assert_eq!((receipt.replica_chunks, receipt.replica_bytes), (0, 0));
    }

    #[tokio::test]
    async fn replica_cache_is_exclusive_and_counts_retained_chunks_without_inventing_publications()
    {
        let directory = tempfile::tempdir().unwrap();
        let config = ContentReplicationConfig {
            replica_cache: directory
                .path()
                .join("replicas")
                .to_str()
                .unwrap()
                .to_owned(),
            limits: Some(ContentCacheLimits {
                quota_bytes: 1024,
                max_entries: 4,
                min_free_bytes: 0,
            }),
            max_bytes: 1024,
            max_chunks: 2,
            reuse_replica_cache: false,
        };
        let mut registry = PublicationRegistry::new();
        let runtime = ReplicationRuntime::create(config.clone(), &mut registry).unwrap();
        assert!(runtime.matches(&config));
        assert!(ReplicationRuntime::create(config.clone(), &mut registry).is_err());
        let mut receipt = ContentReceipt::default();
        runtime.receipt(&mut receipt).await.unwrap();
        assert!(receipt.replication_enabled);
        assert_eq!(
            (
                receipt.replica_chunks,
                receipt.replica_bytes,
                receipt.replica_publications
            ),
            (0, 0, 0)
        );
        let bytes = b"bounded, independently checked replica bytes";
        let mut store = ChunkStore::open(&runtime.root, runtime.limits).unwrap();
        store
            .put_verified_if_space(ChunkId::digest(bytes), bytes)
            .unwrap();
        assert!(runtime.receipt(&mut receipt).await.is_err()); // Never invent a busy-store reading.
        drop(store);
        runtime.receipt(&mut receipt).await.unwrap();
        assert_eq!(
            (receipt.replica_chunks, receipt.replica_bytes),
            (1, bytes.len() as u64)
        );
        assert_eq!(receipt.replica_publications, 0); // Cancelled/partial metadata is not registered.
        runtime.stop().await;
        let mut reopen = config;
        reopen.reuse_replica_cache = true;
        assert!(runtime.matches(&reopen)); // Creation intent is not an active-service setting.
        drop(runtime);
        let restarted = ReplicationRuntime::create(reopen, &mut registry).unwrap();
        restarted.receipt(&mut receipt).await.unwrap();
        assert_eq!(receipt.replica_chunks, 1);
        assert_eq!(receipt.replica_publications, 0); // Missing journal does not invent a manifest.
        assert!(registry.is_empty());
    }
}
