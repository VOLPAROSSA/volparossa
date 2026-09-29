//! Explicit private custody through the existing protected provider route and same Unix socket.
//! Application signing keys never enter the agent; this local control interface retains its
//! existing operator/admin authority and is not a new least-authority application boundary.

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use ed25519_dalek::{SigningKey, VerifyingKey};
use libp2p::{PeerId, identity};
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::{
    Validity,
    private_storage::{
        PrivateStorageStore, StorageLimits,
        protocol::{
            GrantLimits, MAX_AUTH_SECONDS, SignedStorageGrant, StorageRights, VerifiedStorageGrant,
        },
        provider::PrivateStorageProvider,
        wire::{self, StorageService},
    },
    provider::{ProviderEndpoint, PublicationRegistry},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult, PrivateStorageGrant,
    PrivateStorageGrantRequest, PrivateStorageReady, PrivateStorageRemoteRequest,
    PrivateStorageServeRequest, control_response::Payload, write_response,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{
    ContentError, ContentRuntime, ServiceOptions, cancellation::until_requester_closed,
    custody::checked_policy, now, serving_policy, serving_receipt, tls,
};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(MAX_AUTH_SECONDS);

struct RemoteRequest {
    provider_key: [u8; 32],
    peer: PeerId,
    grant: VerifiedStorageGrant,
}

struct SelectedProvider {
    provider: DiscoveredContentProvider,
    policy: VerifiedPolicy,
    control: PeerId,
}

impl ContentRuntime {
    pub(crate) async fn private_storage_serve(
        &self,
        request: PrivateStorageServeRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let bind: SocketAddr = request
            .bind_address
            .parse()
            .map_err(|_| ContentError::Invalid)?;
        let endpoint = ProviderEndpoint::new(&request.advertised_hostname, bind.port())
            .map_err(|_| ContentError::Invalid)?;
        authorize_endpoint(context, &endpoint).await?;
        let current = Arc::clone(&self.service)
            .try_lock_owned()
            .map_err(|_| ContentError::Busy)?;
        if let Some(active) = current.as_ref() {
            if active.bind != bind
                || active.endpoint != endpoint
                || active.task.is_finished()
                || *active.stop.borrow()
                || active
                    .registry
                    .try_lock()
                    .map_err(|_| ContentError::Busy)?
                    .has_private_storage()
            {
                return Err(ContentError::Busy);
            }
        }
        let provider_key = self.signer.verifying_key();
        // The blocking opener owns admission even if this caller is cancelled. It cannot
        // create an unbounded queue of stores or outlive a released service-setup lock.
        let (mut current, provider) = tokio::task::spawn_blocking(move || {
            let provider = open_provider(&request, provider_key)?;
            Ok::<_, ContentError>((current, provider))
        })
        .await
        .map_err(|_| ContentError::Unavailable)??;
        authorize_endpoint(context, &endpoint).await?;
        let storage = Arc::new(StorageService::new(Arc::clone(&self.signer), provider));
        if let Some(active) = current.as_ref() {
            if active.task.is_finished() || *active.stop.borrow() {
                return Err(ContentError::Unavailable);
            }
            // Reannounce an existing generic listener before installing the private handler.
            // No archive IDs, owners or grant metadata enter this generic content offer.
            context
                .discovery
                .register_content_offer(self.offer(endpoint)?)
                .await
                .map_err(|_| ContentError::Unavailable)?;
            let mut registry = active.registry.try_lock().map_err(|_| ContentError::Busy)?;
            if registry.has_private_storage() {
                return Err(ContentError::Busy);
            }
            registry.set_private_storage(storage);
            return serving_receipt(&registry);
        }
        let mut registry = PublicationRegistry::new();
        registry.set_private_storage(storage);
        let receipt = serving_receipt(&registry)?;
        *current = Some(
            self.start_service(
                context,
                bind,
                endpoint,
                registry,
                ServiceOptions {
                    replication: None,
                    name_lookup: false,
                    automatic: false,
                },
            )
            .await?,
        );
        Ok(receipt)
    }

    pub(crate) async fn private_storage_grant(
        &self,
        request: &PrivateStorageGrantRequest,
        context: &ControlContext,
    ) -> Result<PrivateStorageGrant, ContentError> {
        let current = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let active = current.as_ref().ok_or(ContentError::Unavailable)?;
        if active.task.is_finished()
            || *active.stop.borrow()
            || !active
                .registry
                .try_lock()
                .map_err(|_| ContentError::Busy)?
                .has_private_storage()
        {
            return Err(ContentError::Unavailable);
        }
        authorize_endpoint(context, &active.endpoint).await?;
        issue_grant(&self.signer, request, now())
    }

    pub(crate) async fn private_storage_remote(
        &self,
        request: PrivateStorageRemoteRequest,
        context: &ControlContext,
        local: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let request = validate_remote(&request)?;
        let _foreground = self.foreground.enter();
        timeout(EXCHANGE_TIMEOUT, async {
            let _retrieval = super::named_retrieval(&self.retrieval, local).await?;
            remote(&request, context, local, request_id, ready_sent).await
        })
        .await
        .map_err(|_| ContentError::Unavailable)?
    }
}

fn open_provider(
    request: &PrivateStorageServeRequest,
    provider_key: VerifyingKey,
) -> Result<PrivateStorageProvider, ContentError> {
    let store = if request.reuse_store {
        if request.capacity_bytes != 0 || request.min_free_bytes != 0 {
            return Err(ContentError::Invalid);
        }
        PrivateStorageStore::open_existing(Path::new(&request.store))
    } else {
        PrivateStorageStore::create(
            Path::new(&request.store),
            StorageLimits {
                capacity_bytes: request.capacity_bytes,
                min_free_bytes: request.min_free_bytes,
            },
        )
    }
    .map_err(|_| ContentError::Invalid)?;
    PrivateStorageProvider::new(store, provider_key).map_err(|_| ContentError::Invalid)
}

fn issue_grant(
    signer: &SigningKey,
    request: &PrivateStorageGrantRequest,
    created: u64,
) -> Result<PrivateStorageGrant, ContentError> {
    let owner_bytes: [u8; 32] = request
        .owner_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let owner = VerifyingKey::from_bytes(&owner_bytes).map_err(|_| ContentError::Invalid)?;
    let rights = StorageRights::from_bits(request.rights).map_err(|_| ContentError::Invalid)?;
    let expires = created
        .checked_add(request.lifetime_seconds)
        .ok_or(ContentError::Invalid)?;
    let grant = SignedStorageGrant::issue(
        signer,
        &owner,
        GrantLimits {
            max_payload_bytes: request.max_payload_bytes,
            max_leases: request.max_leases,
            max_retention_seconds: request.max_retention_seconds,
            rights,
        },
        Validity { created, expires },
    )
    .map_err(|_| ContentError::Invalid)?;
    Ok(PrivateStorageGrant {
        provider_key: signer.verifying_key().to_bytes().to_vec(),
        grant: grant.encode(),
    })
}

fn validate_remote(request: &PrivateStorageRemoteRequest) -> Result<RemoteRequest, ContentError> {
    let provider_key: [u8; 32] = request
        .provider_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let trusted = VerifyingKey::from_bytes(&provider_key).map_err(|_| ContentError::Invalid)?;
    let grant = SignedStorageGrant::decode(&request.grant)
        .and_then(|signed| signed.verify(&trusted, now()))
        .map_err(|_| ContentError::Invalid)?;
    let public = identity::ed25519::PublicKey::try_from_bytes(&provider_key)
        .map_err(|_| ContentError::Invalid)?;
    Ok(RemoteRequest {
        provider_key,
        peer: PeerId::from_public_key(&identity::PublicKey::from(public)),
        grant,
    })
}

async fn authorize_endpoint(
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

fn grant_current(grant: &VerifiedStorageGrant) -> Result<(), ContentError> {
    let at = now();
    if at < grant.validity().created || at >= grant.validity().expires {
        return Err(ContentError::Invalid);
    }
    Ok(())
}

async fn route_current(
    context: &ControlContext,
    original: &VerifiedPolicy,
    control: PeerId,
    peer: PeerId,
) -> Result<VerifiedPolicy, ContentError> {
    let policy = checked_policy(context, Some(original)).await?;
    if context.routes.content_discovery_control().await != Some(control)
        || !context.routes.content_provider_is_distinct(&peer).await
    {
        return Err(ContentError::Policy);
    }
    Ok(policy)
}

async fn remote(
    request: &RemoteRequest,
    context: &ControlContext,
    local: &mut UnixStream,
    id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let policy = checked_policy(context, None).await?;
    until_requester_closed(local, async {
        Box::pin(
            context
                .routes
                .connect_tcp(&context.config, &context.discovery, &context.helper),
        )
        .await
        .map_err(|_| ContentError::Unavailable)
    })
    .await?;
    let control = context
        .routes
        .content_discovery_control()
        .await
        .ok_or(ContentError::Unavailable)?;
    route_current(context, &policy, control, request.peer).await?;
    let mut providers = until_requester_closed(local, async {
        context
            .discovery
            .lookup_content_providers(control, &[request.peer])
            .await
            .map_err(|_| ContentError::Unavailable)
    })
    .await?;
    if providers.len() != 1 {
        return Err(ContentError::Unavailable);
    }
    let provider = providers.pop().ok_or(ContentError::Unavailable)?;
    if provider.peer_id != request.peer || provider.offer.provider_key() != &request.provider_key {
        return Err(ContentError::Invalid);
    }
    grant_current(&request.grant)?;
    let remaining = request
        .grant
        .validity()
        .expires
        .min(provider.offer.validity().expires)
        .checked_sub(now())
        .filter(|seconds| *seconds > 0)
        .ok_or(ContentError::Unavailable)?;
    timeout(
        Duration::from_secs(remaining.min(MAX_AUTH_SECONDS)),
        exchange(
            request,
            SelectedProvider {
                provider,
                policy,
                control,
            },
            context,
            local,
            id,
            ready_sent,
        ),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?
}

async fn exchange(
    request: &RemoteRequest,
    selected: SelectedProvider,
    context: &ControlContext,
    local: &mut UnixStream,
    id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let SelectedProvider {
        provider,
        policy,
        control,
    } = selected;
    let current = route_current(context, &policy, control, request.peer).await?;
    let endpoint = provider.offer.endpoint();
    let mut flow = until_requester_closed(local, async {
        context
            .routes
            .open_content_stream(
                &current,
                endpoint.hostname(),
                endpoint.port(),
                unix_millis(),
            )
            .await
            .map_err(|_| ContentError::Unavailable)
    })
    .await?;
    let mut remote = until_requester_closed(local, async {
        tls::connect(flow.stream_mut(), request.peer, &provider.offer)
            .await
            .map_err(|_| ContentError::Unavailable)
    })
    .await?;
    let challenge = until_requester_closed(local, async {
        wire::begin(&mut remote, &request.grant)
            .await
            .map_err(|_| ContentError::Unavailable)
    })
    .await?;
    route_current(context, &policy, control, request.peer).await?;
    grant_current(&request.grant)?;
    *ready_sent = true;
    send(
        local,
        id,
        "PRIVATE_STORAGE_READY",
        Payload::PrivateStorageReady(PrivateStorageReady {
            provider_key: request.provider_key.to_vec(),
            challenge: challenge.encode(),
        }),
    )
    .await?;
    let transfer = wire::bridge(local, &mut remote, &request.grant, &challenge)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    tls::finish(&mut remote)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    drop(remote);
    tls::finish(flow.stream_mut())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    flow.shutdown();
    route_current(context, &policy, control, request.peer).await?;
    grant_current(&request.grant)?;
    if provider.offer.validity().expires <= now() || challenge.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    // This terminal proves route/policy/TLS closure, not custody by itself. Exact lease,
    // stored prefix and expiry are in the owner-verified signed receipt sent beforehand.
    send(
        local,
        id,
        "CONTENT_OK",
        Payload::Content(ContentReceipt {
            bytes: transfer.ciphertext_bytes,
            peer_bytes: transfer.ciphertext_bytes,
            providers_used: 1,
            provider_peer_ids: vec![request.peer.to_string()],
            control_relay_peer_id: control.to_string(),
            ..ContentReceipt::default()
        }),
    )
    .await
}

async fn send(
    local: &mut UnixStream,
    id: &[u8],
    code: &str,
    payload: Payload,
) -> Result<(), ContentError> {
    write_response(
        local,
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
mod tests;
