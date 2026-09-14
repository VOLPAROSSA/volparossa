//! Remote public custody uses the configured contribution cache and its original service owner.

use std::{
    path::PathBuf,
    sync::{Arc, Weak},
};

use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use volparossa_config::ContentContributionConfig;
use volparossa_content::{
    ChunkStore, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    provider::{
        ProviderEndpoint, PublicationRegistry,
        custody::{
            CustodyAdmission, CustodyBackend, CustodyError, CustodyFuture, CustodyService,
            CustodyState,
        },
        custody_storage::PublicCustodyStore,
    },
};

use super::{
    ContributionRuntime,
    publication::{configured_limits, stage},
};
use crate::{
    content::{
        ContentRuntime, Service, now,
        replication::ReplicationRuntime,
        replication_budget::{Foreground, ForegroundLease},
    },
    control::ControlContext,
    state::AgentState,
    unix_millis,
};

#[cfg(test)]
mod tests;

/// The registry owns the protocol service. Its backend retains only weak references back to
/// that exact service/registry, so Stop and restart cannot leave a self-owning listener cycle.
#[derive(Clone)]
struct Backend {
    service: Weak<Mutex<Option<Service>>>,
    registry: Weak<Mutex<PublicationRegistry>>,
    state: Arc<RwLock<AgentState>>,
    replication: Arc<ReplicationRuntime>,
    foreground: Arc<Foreground>,
    config: ContentContributionConfig,
    endpoint: ProviderEndpoint,
}

pub(super) async fn attach(
    owner: &ContentRuntime,
    context: &ControlContext,
    runtime: &Arc<ContributionRuntime>,
    active: &Service,
) {
    let backend = Backend {
        service: Arc::downgrade(&owner.service),
        registry: Arc::downgrade(&active.registry),
        state: Arc::clone(&context.state),
        replication: Arc::clone(&runtime.replication),
        foreground: Arc::clone(&owner.foreground),
        config: runtime.config.clone(),
        endpoint: active.endpoint.clone(),
    };
    active
        .registry
        .lock()
        .await
        .set_custody(Arc::new(CustodyService::new(
            Arc::clone(&owner.signer),
            Arc::new(backend),
        )));
}

impl Backend {
    fn active(&self, active: Option<&Service>) -> Result<(), CustodyError> {
        let active = active.ok_or(CustodyError::Store)?;
        if active.task.is_finished()
            || *active.stop.borrow()
            || !active.name_lookup
            || active.endpoint != self.endpoint
            || !self.registry.ptr_eq(&Arc::downgrade(&active.registry))
            || !active
                .replication
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.replication))
        {
            return Err(CustodyError::Store);
        }
        Ok(())
    }

    async fn policy(&self) -> Result<(), CustodyError> {
        let state = self.state.read().await;
        if !state.roles().relay {
            return Err(CustodyError::Unauthorized);
        }
        state
            .active_policy(unix_millis())
            .ok_or(CustodyError::Unauthorized)?
            .authorize_domain(
                unix_millis(),
                self.endpoint.hostname(),
                volparossa_policy::TransportProtocol::Tcp,
                self.endpoint.port(),
            )
            .map_err(|_| CustodyError::Unauthorized)?;
        Ok(())
    }

    fn storage(&self) -> Result<PublicCustodyStore, CustodyError> {
        PublicCustodyStore::open(
            PathBuf::from(&self.config.cache),
            configured_limits(&self.config),
        )
        .map_err(|_| CustodyError::Store)
    }

    fn manifest(signed: &SignedManifest, manifest: &VerifiedManifest) -> Result<(), CustodyError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(manifest.publisher())
            .map_err(|_| CustodyError::Invalid)?;
        let checked = signed
            .verify(&key, now())
            .map_err(|_| CustodyError::Invalid)?;
        if checked.manifest_id() != manifest.manifest_id()
            || checked.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        {
            return Err(CustodyError::Unauthorized);
        }
        Ok(())
    }
}

struct Admission {
    source: ChunkStore,
    staging: tempfile::TempDir,
    backend: Backend,
    signed: SignedManifest,
    manifest: VerifiedManifest,
    _slot: OwnedMutexGuard<()>,
    _foreground: ForegroundLease,
}

impl CustodyBackend for Backend {
    fn begin_deposit(
        &self,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, Box<dyn CustodyAdmission>> {
        Box::pin(async move {
            Self::manifest(&signed, &manifest)?;
            self.policy().await?;
            let foreground = self.foreground.enter();
            let slot = self
                .replication
                .publication_slot()
                .await
                .map_err(|_| CustodyError::Store)?;
            let service = self.service.upgrade().ok_or(CustodyError::Store)?;
            let current = service.try_lock().map_err(|_| CustodyError::Store)?;
            self.active(current.as_ref())?;
            let (source, staging) =
                stage(&self.config, &manifest).map_err(|_| CustodyError::Store)?;
            Ok(Box::new(Admission {
                source,
                staging,
                backend: self.clone(),
                signed,
                manifest,
                _slot: slot,
                _foreground: foreground,
            }) as Box<dyn CustodyAdmission>)
        })
    }

    fn inspect(
        &self,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, CustodyState> {
        Box::pin(async move {
            Self::manifest(&signed, &manifest)?;
            self.policy().await?;
            let _foreground = self.foreground.enter();
            let _slot = self
                .replication
                .publication_slot()
                .await
                .map_err(|_| CustodyError::Store)?;
            let service = self.service.upgrade().ok_or(CustodyError::Store)?;
            let current = service.try_lock().map_err(|_| CustodyError::Store)?;
            self.active(current.as_ref())?;
            let active = current.as_ref().ok_or(CustodyError::Store)?;
            self.replication
                .reclaim(&active.registry, now())
                .await
                .map_err(|_| CustodyError::Store)?;
            let storage = self.storage()?;
            if storage
                .inspect_complete(manifest.manifest_id(), now())
                .map_err(|_| CustodyError::Store)?
                .is_none()
            {
                return Ok(CustodyState::Missing);
            }
            let registry = active
                .registry
                .try_lock()
                .map_err(|_| CustodyError::Store)?;
            if !registry.contains_at(manifest.manifest_id(), &PathBuf::from(&self.config.cache)) {
                return Err(CustodyError::Store);
            }
            drop(registry);
            self.policy().await?;
            crate::content::check_publication_time(&manifest).map_err(|_| CustodyError::Expired)?;
            Ok(CustodyState::Complete)
        })
    }
}

impl CustodyAdmission for Admission {
    fn store(&mut self) -> &mut ChunkStore {
        &mut self.source
    }

    fn commit(mut self: Box<Self>) -> CustodyFuture<'static, ()> {
        Box::pin(async move {
            Backend::manifest(&self.signed, &self.manifest)?;
            self.backend.policy().await?;
            let service = self.backend.service.upgrade().ok_or(CustodyError::Store)?;
            let current = service.try_lock().map_err(|_| CustodyError::Store)?;
            self.backend.active(current.as_ref())?;
            let active = current.as_ref().ok_or(CustodyError::Store)?;
            self.backend
                .replication
                .reclaim(&active.registry, now())
                .await
                .map_err(|_| CustodyError::Store)?;
            self.backend
                .storage()?
                .admit(&self.signed, &self.manifest, &mut self.source, now())
                .map_err(|_| CustodyError::Store)?;
            // Restore from the durable journal, not the just-received in-memory manifest.
            self.backend
                .replication
                .reclaim(&active.registry, now())
                .await
                .map_err(|_| CustodyError::Store)?;
            let registry = active
                .registry
                .try_lock()
                .map_err(|_| CustodyError::Store)?;
            if !registry.contains_at(
                self.manifest.manifest_id(),
                &PathBuf::from(&self.backend.config.cache),
            ) {
                return Err(CustodyError::Store);
            }
            drop(registry);
            self.backend.policy().await?;
            crate::content::check_publication_time(&self.manifest)
                .map_err(|_| CustodyError::Expired)?;
            drop(self.source);
            self.staging.close().map_err(|_| CustodyError::Store)?;
            Ok(())
        })
    }
}
