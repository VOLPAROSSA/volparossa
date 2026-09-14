//! Receiver-owned restoration of healthy partial public journals, without publisher keys.
//! Generic discovery carries no content IDs. Only an authorized protected stream receives
//! the exact missing set; the receiver never asks a remote node to promise new storage.

use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};

use ed25519_dalek::VerifyingKey;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, watch},
    time::Instant,
};
use volparossa_content::{
    ChunkStore,
    provider::{
        PublicationRegistry,
        custody_storage::PublicCustodyStore,
        replication::{
            Replica, ReplicationLimits, ReplicationProgress, persist_replicas,
            pull_public_repair_with_admission, restore_public_replicas,
        },
    },
};

use super::{
    ContentError, ControlContext, Foreground, IdleBudget, ReplicationRuntime, content_event, now,
    unix_millis,
};

#[cfg(test)]
mod tests;

impl ReplicationRuntime {
    /// A persistent journal supplies work after restart, not a remembered publisher session.
    pub(in crate::content) async fn start_repair(
        self: &Arc<Self>,
        context: ControlContext,
        registry: Arc<Mutex<PublicationRegistry>>,
        foreground: Arc<Foreground>,
        mut stop: watch::Receiver<bool>,
    ) {
        if !self.public_only || foreground.active() || *stop.borrow() {
            return;
        }
        let Ok(mut job) = self.job.try_lock() else {
            return;
        };
        if job.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let Some(slot) = self.try_background_slot() else {
            return;
        };
        let Some(budget) = IdleBudget::new(&context.config) else {
            return;
        };
        let permitted = {
            let state = context.state.read().await;
            state.roles().client
                && state.roles().relay
                && state.active_policy(unix_millis()).is_some()
        };
        if !permitted || self.state.lock().await.next > std::time::Instant::now() {
            return;
        }
        let Ok(Some(target)) = self.repair_candidate().await else {
            return;
        };
        // Bound unsuccessful discovery/route retries too; no tight loop on absent providers.
        self.state.lock().await.next = std::time::Instant::now()
            + budget
                .cooldown(self.config.max_bytes)
                .max(Duration::from_secs(30));
        let runtime = Arc::clone(self);
        *job = Some(tokio::spawn(async move {
            let _slot = slot;
            let mut changed = foreground.subscribe();
            if foreground.active() || *stop.borrow() {
                return;
            }
            let remaining = target.validity().expires.saturating_sub(now()).min(150);
            let deadline = Instant::now() + Duration::from_secs(remaining);
            tokio::select! {
                biased;
                _ = stop.changed() => {},
                _ = changed.changed() => {},
                () = tokio::time::sleep_until(deadline) => {},
                () = async {
                    budget.wait_until_quiet().await;
                    if runtime.repair_network(&context, &registry, &target, &budget).await.is_err() {
                        content_event(&context, "CONTENT_REPAIR_DEFERRED").await;
                    }
                } => {},
            }
        }));
    }

    async fn repair_candidate(&self) -> Result<Option<Replica>, ContentError> {
        let mut store =
            ChunkStore::open(&self.root, self.limits).map_err(|_| ContentError::Busy)?;
        let restored =
            restore_public_replicas(&mut store, now()).map_err(|_| ContentError::Invalid)?;
        drop(store);
        let mut candidates = Vec::new();
        for replica in restored {
            let key = VerifyingKey::from_bytes(&replica.publisher_key_hint())
                .map_err(|_| ContentError::Invalid)?;
            let manifest = replica
                .signed_manifest()
                .verify(&key, now())
                .map_err(|_| ContentError::Invalid)?;
            let wanted: BTreeSet<_> = manifest.chunks().iter().map(|chunk| *chunk.id()).collect();
            let held: BTreeSet<_> = replica.chunk_ids().iter().copied().collect();
            if !wanted.is_subset(&held) {
                candidates.push(replica);
            }
        }
        candidates.sort_by_key(|candidate| *candidate.manifest_id());
        let mut state = self.state.lock().await;
        let selected = candidates
            .iter()
            .find(|candidate| {
                state
                    .repair_cursor
                    .is_none_or(|last| *candidate.manifest_id() > last)
            })
            .or_else(|| candidates.first())
            .cloned();
        state.repair_cursor = selected.as_ref().map(|replica| *replica.manifest_id());
        Ok(selected)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep the original policy, route scope and protected flow owner together through repair and close"
    )]
    async fn repair_network(
        &self,
        context: &ControlContext,
        registry: &Mutex<PublicationRegistry>,
        target: &Replica,
        budget: &IdleBudget,
    ) -> Result<(), ContentError> {
        let policy = {
            let state = context.state.read().await;
            if !state.roles().client || !state.roles().relay {
                return Err(ContentError::Policy);
            }
            state
                .active_policy(unix_millis())
                .ok_or(ContentError::Policy)?
        };
        // The normal route owner performs discovery, reservations and exactly-one-relay paths.
        // Unlike incidental uptake, repair can bootstrap after restart with no foreground flow.
        Box::pin(
            context
                .routes
                .connect_tcp(&context.config, &context.discovery, &context.helper),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        let scope = context
            .routes
            .content_discovery_scope()
            .await
            .ok_or(ContentError::Unavailable)?;
        let providers = context
            .discovery
            .discover_content_providers(scope.0, volparossa_discovery::MAX_CONTENT_OFFERS)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        for provider in providers {
            if now() >= target.validity().expires
                || context.routes.content_discovery_scope().await != Some(scope)
            {
                return Err(ContentError::Unavailable);
            }
            {
                let state = context.state.read().await;
                if !state.roles().client
                    || !state.roles().relay
                    || state
                        .active_policy(unix_millis())
                        .is_none_or(|current| current.policy_hash() != policy.policy_hash())
                {
                    return Err(ContentError::Policy);
                }
            }
            if provider.offer.validity().expires <= now()
                || !context
                    .routes
                    .content_provider_is_distinct(&provider.peer_id)
                    .await
            {
                continue;
            }
            budget.wait_until_quiet().await;
            let endpoint = provider.offer.endpoint();
            let Ok(mut flow) = context
                .routes
                .open_content_stream(&policy, endpoint.hostname(), endpoint.port(), unix_millis())
                .await
            else {
                continue;
            };
            let result = async {
                let mut stream = super::super::tls::connect(
                    flow.stream_mut(),
                    provider.peer_id,
                    &provider.offer,
                )
                .await
                .map_err(|_| ContentError::Unavailable)?;
                let progress = self
                    .repair_from_stream(&mut stream, target, || async {
                        budget.wait_until_quiet().await;
                        let state = context.state.read().await;
                        state.roles().client
                            && state.roles().relay
                            && state.active_policy(unix_millis()).is_some_and(|current| {
                                current.policy_hash() == policy.policy_hash()
                            })
                    })
                    .await?;
                super::super::tls::finish(&mut stream)
                    .await
                    .map_err(|_| ContentError::Unavailable)?;
                drop(stream);
                super::super::tls::finish(flow.stream_mut())
                    .await
                    .map_err(|_| ContentError::Unavailable)?;
                self.reclaim(registry, now()).await?;
                Ok::<_, ContentError>(progress)
            }
            .await;
            flow.shutdown();
            if let Ok(progress) = result {
                if !progress.replicas.is_empty() {
                    let custody = PublicCustodyStore::open(self.root.clone(), self.limits)
                        .map_err(|_| ContentError::Invalid)?;
                    let complete = custody
                        .inspect_complete(target.manifest_id(), now())
                        .map_err(|_| ContentError::Invalid)?
                        .is_some();
                    content_event(
                        context,
                        if complete {
                            "CONTENT_REPAIR_COMPLETE"
                        } else {
                            "CONTENT_REPAIR_CHUNKS_AVAILABLE"
                        },
                    )
                    .await;
                    return Ok(());
                }
            }
        }
        Err(ContentError::Unavailable)
    }

    async fn repair_from_stream<S, F, Fut>(
        &self,
        stream: &mut S,
        target: &Replica,
        admission: F,
    ) -> Result<ReplicationProgress, ContentError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let mut store =
            ChunkStore::open(&self.root, self.limits).map_err(|_| ContentError::Busy)?;
        let progress = pull_public_repair_with_admission(
            stream,
            &mut store,
            target,
            ReplicationLimits {
                max_chunks: self.config.max_chunks as usize,
                max_wire_bytes: self.config.max_bytes,
                ..ReplicationLimits::default()
            },
            admission,
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        persist_replicas(&mut store, &progress.replicas, now())
            .map_err(|_| ContentError::Invalid)?;
        self.state.lock().await.usage = store.usage();
        Ok(progress)
    }
}
