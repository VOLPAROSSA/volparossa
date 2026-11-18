//! Operator-scoped guest quote attachment, independent of public inference jobs.

use std::{
    net::SocketAddr,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use ed25519_dalek::VerifyingKey;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use volparossa_content::provider::{
    ProviderEndpoint, PublicationRegistry,
    compute::{
        guest::GuestLimits,
        quote::{QuoteAuthority, QuoteAuthorityFuture, QuoteError, QuoteGrant, QuoteService},
    },
};
use volparossa_local_control::{ContentReceipt, QuoteAttachRequest};

use super::{
    ContentError, ContentRuntime, Service, ServiceOptions, now, serving_policy, serving_receipt,
};
use crate::{
    control::ControlContext, discovery::DiscoveryControlHandle, state::AgentState, unix_millis,
};

struct Authority {
    requester: [u8; 32],
    enabled: AtomicBool,
    service: Weak<Mutex<Option<Service>>>,
    registry: OnceLock<Weak<Mutex<PublicationRegistry>>>,
    state: Arc<RwLock<AgentState>>,
    endpoint: ProviderEndpoint,
}

impl QuoteAuthority for Authority {
    fn check(&self, requester: [u8; 32]) -> QuoteAuthorityFuture<'_> {
        Box::pin(async move {
            if requester != self.requester || !self.enabled.load(Ordering::Acquire) {
                return Err(QuoteError::Unauthorized);
            }
            let service = self.service.upgrade().ok_or(QuoteError::Unavailable)?;
            // Attachment setup owns this lock until registry/listener binding is committed.
            // The quote supervisor polls authority without blocking its expiry/cancel branch.
            let current = service.lock().await;
            let active = current.as_ref().ok_or(QuoteError::Unavailable)?;
            if active.task.is_finished()
                || *active.stop.borrow()
                || active.endpoint != self.endpoint
                || !self
                    .registry
                    .get()
                    .is_some_and(|registry| registry.ptr_eq(&Arc::downgrade(&active.registry)))
            {
                return Err(QuoteError::Unavailable);
            }
            drop(current);
            let state = self.state.read().await;
            if !state.roles().relay || !self.enabled.load(Ordering::Acquire) {
                return Err(QuoteError::Unauthorized);
            }
            state
                .active_policy(unix_millis())
                .ok_or(QuoteError::Unauthorized)?
                .authorize_domain(
                    unix_millis(),
                    self.endpoint.hostname(),
                    volparossa_policy::TransportProtocol::Tcp,
                    self.endpoint.port(),
                )
                .map_err(|_| QuoteError::Unauthorized)?;
            Ok(())
        })
    }
}

/// The supervisor is owned and joinable; dropping an unfinished attachment cancels it.
pub(super) struct Attachment {
    authority: Arc<Authority>,
    service: Arc<QuoteService>,
    supervisor: Option<JoinHandle<()>>,
}

impl Attachment {
    pub(super) fn deactivate(&self) {
        self.authority.enabled.store(false, Ordering::Release);
        self.service.deactivate();
    }

    pub(super) async fn stop(mut self) {
        self.deactivate();
        if let Some(task) = self.supervisor.take() {
            // Join the async owner, not an uninterruptible firmware ioctl. Its real
            // worker still owns the process-wide permit until it actually returns.
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.deactivate();
        if let Some(task) = &self.supervisor {
            task.abort();
        }
    }
}

fn requester(request: &QuoteAttachRequest, at: u64) -> Result<[u8; 32], ContentError> {
    let key: [u8; 32] = request
        .requester_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    if key == [0; 32]
        || VerifyingKey::from_bytes(&key).is_err()
        || !matches!(request.confirmation_version, None | Some(1))
        || !(1..=64).contains(&request.maximum_attempts)
        || !request
            .expires_at
            .checked_sub(at)
            .is_some_and(|seconds| (1..=600).contains(&seconds))
    {
        return Err(ContentError::Invalid);
    }
    Ok(key)
}

impl ContentRuntime {
    #[allow(
        clippy::too_many_lines,
        reason = "One attachment transaction retains listener, authority, and supervisor ownership"
    )]
    pub(crate) async fn quote_attach(
        &self,
        request: &QuoteAttachRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let requester_key = requester(request, now())?;
        let bind: SocketAddr = request
            .bind_address
            .parse()
            .map_err(|_| ContentError::Invalid)?;
        if bind.port() == 0 {
            return Err(ContentError::Invalid);
        }
        let endpoint = ProviderEndpoint::new(&request.advertised_hostname, bind.port())
            .map_err(|_| ContentError::Invalid)?;
        serving_policy(context)
            .await?
            .authorize_domain(
                unix_millis(),
                endpoint.hostname(),
                volparossa_policy::TransportProtocol::Tcp,
                endpoint.port(),
            )
            .map_err(|_| ContentError::Policy)?;
        let mut current = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let mut attached = self.quote.try_lock().map_err(|_| ContentError::Busy)?;
        if attached.is_some()
            || current.as_ref().is_some_and(|active| {
                active.bind != bind
                    || active.endpoint != endpoint
                    || active.task.is_finished()
                    || *active.stop.borrow()
            })
        {
            return Err(ContentError::Busy);
        }
        let authority = Arc::new(Authority {
            requester: requester_key,
            enabled: AtomicBool::new(true),
            service: Arc::downgrade(&self.service),
            registry: OnceLock::new(),
            state: Arc::clone(&context.state),
            endpoint: endpoint.clone(),
        });
        let constructor = if request.confirmation_version == Some(1) {
            QuoteService::new_confirmation
        } else {
            QuoteService::new
        };
        let service = constructor(
            Arc::clone(&self.signer),
            QuoteGrant {
                requester_key,
                limits: GuestLimits {
                    expires_at: request.expires_at,
                    maximum_attempts: u16::try_from(request.maximum_attempts)
                        .map_err(|_| ContentError::Invalid)?,
                },
            },
            Arc::clone(&self.quote_firmware),
            authority.clone(),
        )
        .map_err(|_| ContentError::Invalid)?;
        let supervisor = Arc::clone(&service)
            .supervise()
            .map_err(|_| ContentError::Unavailable)?;
        let cleanup_authority = Arc::clone(&authority);
        let discovery = context.discovery.clone();
        let attachment = Attachment {
            authority,
            service: Arc::clone(&service),
            supervisor: Some(tokio::spawn(async move {
                supervisor.await;
                cleanup_authority.enabled.store(false, Ordering::Release);
                withdraw_expired(&cleanup_authority, &discovery).await;
            })),
        };
        let receipt = if let Some(active) = current.as_ref() {
            attachment
                .authority
                .registry
                .set(Arc::downgrade(&active.registry))
                .map_err(|_| ContentError::Invalid)?;
            let mut registry = active.registry.try_lock().map_err(|_| ContentError::Busy)?;
            registry.set_quote(service);
            let receipt = serving_receipt(&registry)?;
            drop(registry);
            if context
                .discovery
                .register_content_offer(self.offer(endpoint)?)
                .await
                .is_err()
            {
                attachment.deactivate();
                active.registry.lock().await.clear_quote();
                return Err(ContentError::Unavailable);
            }
            receipt
        } else {
            let mut registry = PublicationRegistry::new();
            registry.set_quote(service);
            let receipt = serving_receipt(&registry)?;
            let active = self
                .start_service(
                    context,
                    bind,
                    endpoint,
                    registry,
                    ServiceOptions {
                        replication: None,
                        name_lookup: false,
                        automatic: true,
                    },
                )
                .await?;
            attachment
                .authority
                .registry
                .set(Arc::downgrade(&active.registry))
                .map_err(|_| ContentError::Invalid)?;
            *current = Some(active);
            receipt
        };
        *attached = Some(attachment);
        Ok(receipt)
    }

    pub(crate) async fn quote_detach(
        &self,
        discovery: &DiscoveryControlHandle,
    ) -> Result<ContentReceipt, ContentError> {
        let current = self.service.lock().await;
        let mut attached = self.quote.lock().await;
        if let Some(attachment) = attached.take() {
            attachment.stop().await;
        }
        if let Some(active) = current.as_ref() {
            let mut registry = active.registry.lock().await;
            registry.clear_quote();
            let receipt = serving_receipt(&registry)?;
            if !active.name_lookup && empty_service(&registry) {
                discovery
                    .withdraw_content_offer()
                    .await
                    .map_err(|_| ContentError::Unavailable)?;
            }
            return Ok(receipt);
        }
        Ok(ContentReceipt::default())
    }
}

fn empty_service(registry: &PublicationRegistry) -> bool {
    !registry.has_live_publications(now())
        && !registry.has_mailbox()
        && !registry.has_private_storage()
        && !registry.has_custody()
        && !registry.has_compute()
        && !registry.has_quote()
}

async fn withdraw_expired(authority: &Authority, discovery: &DiscoveryControlHandle) {
    let Some(service) = authority.service.upgrade() else {
        return;
    };
    let current = service.lock().await;
    let Some(active) = current.as_ref() else {
        return;
    };
    if !authority
        .registry
        .get()
        .is_some_and(|registry| registry.ptr_eq(&Arc::downgrade(&active.registry)))
    {
        return;
    }
    let mut registry = active.registry.lock().await;
    registry.clear_quote();
    if !active.name_lookup && empty_service(&registry) {
        let _ = discovery.withdraw_content_offer().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tokio::sync::watch;
    use volparossa_config::{Config, RolesConfig, RuntimeMode};
    use volparossa_metrics::MetricsRegistry;
    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
    use volparossa_test_support::verified_development_manifest;

    #[test]
    fn quote_attachment_requires_one_valid_key_and_finite_local_bounds() {
        let key = SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes();
        let request = QuoteAttachRequest {
            bind_address: "127.0.0.1:8443".into(),
            advertised_hostname: "provider.example".into(),
            requester_key: key.to_vec(),
            expires_at: 601,
            maximum_attempts: 64,
            confirmation_version: None,
        };
        assert_eq!(requester(&request, 1).unwrap(), key);
        assert!(requester(&request, 0).is_err());
        assert!(requester(&request, 601).is_err());
        assert_eq!(
            requester(
                &QuoteAttachRequest {
                    confirmation_version: Some(1),
                    ..request.clone()
                },
                1
            )
            .unwrap(),
            key
        );
        for version in [0, 2, u32::MAX] {
            assert!(
                requester(
                    &QuoteAttachRequest {
                        confirmation_version: Some(version),
                        ..request.clone()
                    },
                    1
                )
                .is_err()
            );
        }
        for attempts in [0, 65] {
            assert!(
                requester(
                    &QuoteAttachRequest {
                        maximum_attempts: attempts,
                        ..request.clone()
                    },
                    1
                )
                .is_err()
            );
        }
        assert!(
            requester(
                &QuoteAttachRequest {
                    requester_key: vec![0; 32],
                    ..request
                },
                1
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn firmware_capacity_remains_shared_across_attachment_lifetimes() {
        let runtime = ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
        let replacement = runtime.clone();
        let old_attachment = Arc::clone(&runtime.quote_firmware);
        let permit = old_attachment.try_acquire_owned().unwrap();
        let new_attachment = Arc::clone(&replacement.quote_firmware);
        assert!(Arc::clone(&new_attachment).try_acquire_owned().is_err());
        drop(permit);
        assert!(new_attachment.try_acquire_owned().is_ok());
    }

    fn authority_fixture() -> (Arc<Authority>, Arc<Mutex<Option<Service>>>) {
        let roles = RolesConfig {
            client: false,
            relay: true,
            exit: false,
        };
        let config = Config {
            runtime_mode: RuntimeMode::Development,
            roles,
            ..Config::default()
        };
        let policy = verified_development_manifest(
            unix_millis(),
            vec![
                DestinationRule::exact_domain(
                    "provider.example",
                    [ProtocolPort::new(TransportProtocol::Tcp, 18080).unwrap()],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let state = Arc::new(RwLock::new(
            AgentState::new(&config, roles, Some(policy), MetricsRegistry::new()).unwrap(),
        ));
        let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
        let (stop, mut receiver) = watch::channel(false);
        // A task-lifetime sentinel, not a simulated protected transport or quote.
        let task = tokio::spawn(async move {
            let _ = receiver.changed().await;
        });
        let endpoint = ProviderEndpoint::new("provider.example", 18080).unwrap();
        let service = Arc::new(Mutex::new(Some(Service {
            registry: Arc::clone(&registry),
            endpoint: endpoint.clone(),
            bind: "127.0.0.1:18080".parse().unwrap(),
            stop,
            task,
            replication: None,
            name_lookup: false,
            mailbox: false,
        })));
        let authority = Arc::new(Authority {
            requester: SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes(),
            enabled: AtomicBool::new(true),
            service: Arc::downgrade(&service),
            registry: OnceLock::new(),
            state,
            endpoint,
        });
        authority.registry.set(Arc::downgrade(&registry)).unwrap();
        (authority, service)
    }

    async fn finish_fixture(service: Arc<Mutex<Option<Service>>>) {
        let active = service.lock().await.take().unwrap();
        let _ = active.stop.send(true);
        active.task.await.unwrap();
    }

    #[tokio::test]
    async fn quote_authority_rechecks_exact_requester_live_registry_and_policy() {
        let (authority, service) = authority_fixture();
        assert!(authority.check(authority.requester).await.is_ok());
        assert_eq!(
            authority.check([0; 32]).await,
            Err(QuoteError::Unauthorized)
        );
        authority.state.write().await.set_policy(None);
        assert_eq!(
            authority.check(authority.requester).await,
            Err(QuoteError::Unauthorized)
        );
        finish_fixture(service).await;

        let (authority, service) = authority_fixture();
        service.lock().await.as_mut().unwrap().registry =
            Arc::new(Mutex::new(PublicationRegistry::new()));
        assert_eq!(
            authority.check(authority.requester).await,
            Err(QuoteError::Unavailable)
        );
        finish_fixture(service).await;
    }

    #[tokio::test]
    async fn quote_authority_waits_for_setup_but_detachment_is_not_permission() {
        let (authority, service) = authority_fixture();
        let locked = service.lock().await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                authority.check(authority.requester)
            )
            .await
            .is_err()
        );
        drop(locked);
        assert!(authority.check(authority.requester).await.is_ok());
        authority.enabled.store(false, Ordering::Release);
        assert_eq!(
            authority.check(authority.requester).await,
            Err(QuoteError::Unauthorized)
        );
        finish_fixture(service).await;
    }
}
