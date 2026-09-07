//! Small post-download replicas; no content catalogue, new routes or consumer trust.

use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use libp2p::PeerId;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use volparossa_content::provider::replication::{
    ReplicationExclusions, ReplicationLimits, pull_replicas,
};
use volparossa_content::provider::{PublicationRegistry, VerifiedProviderOffer};
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
}

impl ReplicationRuntime {
    pub(super) fn create(config: ContentReplicationConfig) -> Result<Arc<Self>, ContentError> {
        let cache_limits = limits(config.limits)?;
        if !(64..=1024 * 1024).contains(&config.max_bytes)
            || !(1..=4).contains(&config.max_chunks)
            || cache_limits.max_bytes > 256 * 1024 * 1024
        {
            return Err(ContentError::Invalid);
        }
        let root = PathBuf::from(&config.replica_cache);
        // Exclusive new private root: never adopt the foreground cache or another directory.
        let store = ChunkStore::create(&root, cache_limits).map_err(|_| ContentError::Invalid)?;
        let usage = store.usage();
        drop(store);
        Ok(Arc::new(Self {
            config,
            root,
            limits: cache_limits,
            state: Mutex::new(State {
                contacts: VecDeque::new(),
                chunks: VecDeque::new(),
                publications: BTreeSet::new(),
                usage,
                next: Instant::now(),
            }),
            job: Mutex::new(None),
        }))
    }

    pub(super) fn matches(&self, config: &ContentReplicationConfig) -> bool {
        self.config == *config
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
                () = runtime.exchange(&context, &registry, contact, &exclusions) => {},
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
            let Ok(mut store) = ChunkStore::open(&self.root, self.limits) else {
                return;
            };
            let progress = pull_replicas(
                flow.stream_mut(),
                &mut store,
                ReplicationLimits {
                    max_chunks: self.config.max_chunks as usize,
                    max_wire_bytes: self.config.max_bytes,
                    ..ReplicationLimits::default()
                },
                exclusions,
            )
            .await
            .ok();
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
                    for chunk in chunks {
                        state.chunks.retain(|known| *known != chunk);
                        if state.chunks.len() >= MAX_REMEMBERED_CHUNKS {
                            state.chunks.pop_front();
                        }
                        state.chunks.push_back(chunk);
                    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_local_control::ContentCacheLimits;

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
        };
        let runtime = ReplicationRuntime::create(config.clone()).unwrap();
        assert!(runtime.matches(&config));
        assert!(ReplicationRuntime::create(config).is_err());
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
    }
}
