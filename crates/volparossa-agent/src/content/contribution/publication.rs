//! Explicit complete public admission through the already configured service and cache owner.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use tokio::sync::OwnedMutexGuard;
use volparossa_content::provider::replication::admit_public_publication;
use volparossa_local_control::ContentReceipt;

use super::{
    Arc, CacheLimits, ChunkStore, ContentContributionConfig, ContentError, ContentRuntime,
    ContributionRuntime, ControlContext, Mutex, PRIVATE_MESSAGE_CONTENT_TYPE, PathBuf,
    ProviderEndpoint, PublicationRegistry, SignedManifest, VerifiedManifest, now, serving_policy,
    unix_millis, watch,
};
use crate::content::{Service, replication_budget::ForegroundLease, serving_receipt};

#[cfg(test)]
mod tests;

/// The source closes before its private directory is removed. Both leases outlive the entire
/// receive/admit/register transaction; dropping this owner cancels it without detached writers.
pub(crate) struct PublicationAdmission {
    source: ChunkStore,
    staging: tempfile::TempDir,
    runtime: Arc<ContributionRuntime>,
    registry: Arc<Mutex<PublicationRegistry>>,
    endpoint: ProviderEndpoint,
    stop: watch::Receiver<bool>,
    signed: SignedManifest,
    manifest: VerifiedManifest,
    _slot: OwnedMutexGuard<()>,
    _foreground: ForegroundLease,
}

impl ContentRuntime {
    pub(crate) async fn begin_publication(
        &self,
        context: &ControlContext,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> Result<PublicationAdmission, ContentError> {
        if !context.config.content_contribution.enabled
            || manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        {
            return Err(ContentError::Policy);
        }
        let runtime = self
            .contribution
            .lock()
            .await
            .clone()
            .ok_or(ContentError::Unavailable)?;
        if runtime.config != context.config.content_contribution {
            return Err(ContentError::Busy);
        }
        let foreground = self.foreground.enter();
        let slot = runtime.replication.publication_slot().await?;
        let current = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let active = current.as_ref().ok_or(ContentError::Unavailable)?;
        if !configured_service(active, &runtime) {
            return Err(ContentError::Unavailable);
        }
        check_endpoint(context, &active.endpoint).await?;
        let (source, staging) = stage(&runtime.config, &manifest)?;
        Ok(PublicationAdmission {
            source,
            staging,
            runtime,
            registry: Arc::clone(&active.registry),
            endpoint: active.endpoint.clone(),
            stop: active.stop.subscribe(),
            signed,
            manifest,
            _slot: slot,
            _foreground: foreground,
        })
    }
}

impl PublicationAdmission {
    pub(crate) fn source(&mut self) -> &mut ChunkStore {
        &mut self.source
    }

    pub(crate) fn stop_receiver(&self) -> watch::Receiver<bool> {
        self.stop.clone()
    }

    pub(crate) async fn complete(
        mut self,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let current = context
            .content
            .service
            .try_lock()
            .map_err(|_| ContentError::Busy)?;
        let active = current.as_ref().ok_or(ContentError::Unavailable)?;
        if *self.stop.borrow()
            || !configured_service(active, &self.runtime)
            || !Arc::ptr_eq(&active.registry, &self.registry)
        {
            return Err(ContentError::Unavailable);
        }
        check_endpoint(context, &self.endpoint).await?;
        self.commit().await?;
        check_endpoint(context, &self.endpoint).await?;
        let mut receipt = serving_receipt(&*self.registry.lock().await)?;
        self.runtime.replication.receipt(&mut receipt).await?;
        // Keep the exact service owner locked until announcement completes; Stop cannot remove
        // its listener and then have this transaction resurrect the old endpoint's offer.
        context
            .discovery
            .register_content_offer(super::super::make_offer(
                &context.content.signer,
                self.endpoint.clone(),
            )?)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        receipt.bytes = self.manifest.length();
        receipt.chunks =
            u32::try_from(self.manifest.chunks().len()).map_err(|_| ContentError::Invalid)?;
        drop(self.source);
        self.staging.close().map_err(|_| ContentError::Invalid)?;
        let validity = self.manifest.validity();
        if !(validity.created..validity.expires).contains(&now())
            || !configured_service(active, &self.runtime)
        {
            return Err(ContentError::Unavailable);
        }
        receipt.network_publication = true;
        Ok(receipt)
    }

    async fn commit(&mut self) -> Result<(), ContentError> {
        self.runtime
            .replication
            .reclaim(&self.registry, now())
            .await?;
        let root = PathBuf::from(&self.runtime.config.cache);
        let id = self.manifest.manifest_id();
        {
            let registry = self.registry.try_lock().map_err(|_| ContentError::Busy)?;
            if (registry.contains(id) && !registry.contains_at(id, &root))
                || (!registry.contains(id) && registry.len() >= 64)
            {
                return Err(ContentError::Busy);
            }
        }
        let mut destination = ChunkStore::open(&root, configured_limits(&self.runtime.config))
            .map_err(|_| ContentError::Busy)?;
        admit_public_publication(
            &self.signed,
            &self.manifest,
            &mut self.source,
            &mut destination,
            now(),
        )
        .map_err(|_| ContentError::Invalid)?;
        drop(destination);
        self.runtime
            .replication
            .reclaim(&self.registry, now())
            .await?;
        let registry = self.registry.try_lock().map_err(|_| ContentError::Busy)?;
        if !registry.contains_at(id, &root) {
            return Err(ContentError::Busy);
        }
        Ok(())
    }
}

fn configured_service(active: &Service, runtime: &Arc<ContributionRuntime>) -> bool {
    !active.task.is_finished()
        && !*active.stop.borrow()
        && active.name_lookup
        && active
            .replication
            .as_ref()
            .is_some_and(|replication| Arc::ptr_eq(replication, &runtime.replication))
        && runtime
            .config
            .bind_address
            .parse()
            .is_ok_and(|bind: std::net::SocketAddr| bind == active.bind)
        && active.endpoint.hostname() == runtime.config.advertised_hostname
}

async fn check_endpoint(
    context: &ControlContext,
    endpoint: &ProviderEndpoint,
) -> Result<(), ContentError> {
    serving_policy(context)
        .await?
        .authorize_domain(
            unix_millis(),
            endpoint.hostname(),
            volparossa_policy::TransportProtocol::Tcp,
            endpoint.port(),
        )
        .map_err(|_| ContentError::Policy)?;
    Ok(())
}

fn configured_limits(config: &ContentContributionConfig) -> CacheLimits {
    CacheLimits {
        max_bytes: config.quota_bytes,
        max_entries: config.max_entries as usize,
        min_free_bytes: config.min_free_bytes,
    }
}

fn stage(
    config: &ContentContributionConfig,
    manifest: &VerifiedManifest,
) -> Result<(ChunkStore, tempfile::TempDir), ContentError> {
    let unique: BTreeMap<_, _> = manifest
        .chunks()
        .iter()
        .map(|chunk| (*chunk.id(), u64::from(chunk.length())))
        .collect();
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE
        || unique.len() > config.max_entries as usize
        || unique.values().sum::<u64>() > config.quota_bytes
    {
        return Err(ContentError::Invalid);
    }
    let parent = Path::new(&config.cache)
        .parent()
        .ok_or(ContentError::Invalid)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ContentError::Invalid)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(ContentError::Invalid);
    }
    let staging = tempfile::Builder::new()
        .prefix(".volparossa-publication-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .map_err(|_| ContentError::Invalid)?;
    let source = ChunkStore::create(&staging.path().join("source"), configured_limits(config))
        .map_err(|_| ContentError::Invalid)?;
    Ok((source, staging))
}
