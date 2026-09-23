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
            pull_public_repair_with_policy, restore_public_replicas,
        },
    },
};

use super::{
    ContentError, ControlContext, Foreground, IdleBudget, ReplicationRuntime, content_event, now,
    unix_millis,
};

#[cfg(test)]
mod tests;

#[derive(Debug)]
enum CompletionError {
    Registry,
    Verification,
}

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
        if !permitted {
            return;
        }
        // Durable progress survives a later TLS-close error, foreground cancellation or
        // momentarily busy registry. Complete journals are not new network candidates;
        // retry this local-only stage before applying the network retry cooldown.
        if self.state.lock().await.repair_pending.is_some() {
            let _ = self.complete_repair(&context, &registry).await;
            return;
        }
        if self.state.lock().await.next > std::time::Instant::now() {
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
                    .repair_from_stream(
                        &mut stream,
                        target,
                        &context.content.object_policy,
                        || async {
                            budget.wait_until_quiet().await;
                            let state = context.state.read().await;
                            state.roles().client
                                && state.roles().relay
                                && state.active_policy(unix_millis()).is_some_and(|current| {
                                    current.policy_hash() == policy.policy_hash()
                                })
                        },
                    )
                    .await;
                let progress = match progress {
                    Ok(progress) => progress,
                    Err(error) => {
                        content_event(context, "CONTENT_REPAIR_TRANSFER_COMMIT_FAILED").await;
                        return Err(error);
                    }
                };
                if super::super::tls::finish(&mut stream).await.is_err() {
                    content_event(context, "CONTENT_REPAIR_APPLICATION_CLOSE_FAILED").await;
                    return Err(ContentError::Unavailable);
                }
                drop(stream);
                if super::super::tls::finish(flow.stream_mut()).await.is_err() {
                    content_event(context, "CONTENT_REPAIR_ROUTE_CLOSE_FAILED").await;
                    return Err(ContentError::Unavailable);
                }
                Ok::<_, ContentError>(progress)
            }
            .await;
            flow.shutdown();
            if let Ok(progress) = result {
                if !progress.replicas.is_empty() {
                    return self.complete_repair(context, registry).await;
                }
            }
            if self.state.lock().await.repair_pending.is_some() {
                // Do not redownload verified durable progress after a failed close.
                // The next permitted idle tick independently reconciles local storage;
                // this network operation still reports its actual failure.
                return Err(ContentError::Unavailable);
            }
        }
        Err(ContentError::Unavailable)
    }

    async fn repair_from_stream<S, F, Fut>(
        &self,
        stream: &mut S,
        target: &Replica,
        policy: &volparossa_content::object_policy::ObjectPolicyGate,
        admission: F,
    ) -> Result<ReplicationProgress, ContentError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let mut store =
            ChunkStore::open(&self.root, self.limits).map_err(|_| ContentError::Busy)?;
        let progress = pull_public_repair_with_policy(
            stream,
            &mut store,
            target,
            ReplicationLimits {
                max_chunks: self.config.max_chunks as usize,
                max_wire_bytes: self.config.max_bytes,
                ..ReplicationLimits::default()
            },
            policy,
            admission,
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        let mut state = self.state.lock().await;
        persist_replicas(&mut store, &progress.replicas, now())
            .map_err(|_| ContentError::Invalid)?;
        state.usage = store.usage();
        if !progress.replicas.is_empty() {
            state.repair_pending = Some(target.clone());
        }
        Ok(progress)
    }

    async fn complete_repair(
        &self,
        context: &ControlContext,
        registry: &Mutex<PublicationRegistry>,
    ) -> Result<(), ContentError> {
        let code = match self.finalize_pending(registry).await {
            Ok(Some(true)) => "CONTENT_REPAIR_COMPLETE",
            Ok(Some(false)) => "CONTENT_REPAIR_CHUNKS_AVAILABLE",
            Ok(None) => return Ok(()),
            Err(error) => {
                content_event(
                    context,
                    match error {
                        CompletionError::Registry => "CONTENT_REPAIR_REGISTRY_DEFERRED",
                        CompletionError::Verification => "CONTENT_REPAIR_VERIFICATION_DEFERRED",
                    },
                )
                .await;
                return Err(ContentError::Unavailable);
            }
        };
        // Completion describes the independently verified stored object/registration.
        // A preceding close-failure event remains a failure, not clean transport proof.
        content_event(context, code).await;
        // Keep pending through the event await too: foreground cancellation before the
        // observable completion must leave a retry, not a now-ineligible complete journal.
        self.state.lock().await.repair_pending = None;
        Ok(())
    }

    async fn finalize_pending(
        &self,
        registry: &Mutex<PublicationRegistry>,
    ) -> Result<Option<bool>, CompletionError> {
        let Some(target) = self.state.lock().await.repair_pending.clone() else {
            return Ok(None);
        };
        let at = now();
        if at >= target.validity().expires {
            self.state.lock().await.repair_pending = None;
            return Err(CompletionError::Verification);
        }
        self.reclaim(registry, at)
            .await
            .map_err(|_| CompletionError::Registry)?;
        let registry = registry.try_lock().map_err(|_| CompletionError::Registry)?;
        if !registry.contains_at(target.manifest_id(), &self.root) {
            return Err(CompletionError::Registry);
        }
        let custody = PublicCustodyStore::open(self.root.clone(), self.limits)
            .map_err(|_| CompletionError::Verification)?;
        let complete = custody
            .inspect_complete(target.manifest_id(), at)
            .map_err(|_| CompletionError::Verification)?
            .is_some();
        Ok(Some(complete))
    }
}
