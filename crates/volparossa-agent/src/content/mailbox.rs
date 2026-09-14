//! Explicit mailbox storage and typed local handoff through the existing protected route.
//! Application keys remain in the caller; neither invitation labels nor message IDs enter DHT.

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use ed25519_dalek::VerifyingKey;
use libp2p::{PeerId, identity};
use socket2::SockRef;
use tokio::{
    net::{TcpListener, UnixStream},
    sync::{Mutex, watch},
    time::timeout,
};
use volparossa_content::{
    SignedManifest,
    mailbox::{
        SignedMailboxGrant, VerifiedMailboxGrant,
        store::MailboxStore,
        wire::{self, MailboxCommand, MailboxOperation, MailboxService},
    },
    provider::{ProviderEndpoint, PublicationRegistry},
};
use volparossa_core::CONTRIBUTION_SOCKET_PRIORITY;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult, MailboxReady,
    MailboxRemoteRequest, MailboxServeRequest, control_response::Payload, write_response,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{
    ContentError, ContentRuntime, OPERATION_TIMEOUT, Service, limits, now, serving_policy,
    serving_receipt, tls,
};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

struct RemoteRequest {
    provider_key: [u8; 32],
    peer: PeerId,
    grant: VerifiedMailboxGrant,
    command: MailboxCommand,
}

struct SelectedProvider {
    provider: DiscoveredContentProvider,
    policy: VerifiedPolicy,
    control: PeerId,
}

impl ContentRuntime {
    pub(crate) async fn mailbox_serve(
        &self,
        request: MailboxServeRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let mut service = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let bind: SocketAddr = request
            .bind_address
            .parse()
            .map_err(|_| ContentError::Invalid)?;
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
        if service.as_ref().is_some_and(|active| {
            active.bind != bind
                || active.endpoint != endpoint
                || active.task.is_finished()
                || active.mailbox
        }) {
            return Err(ContentError::Busy);
        }
        let cache_limits = limits(request.limits)?;
        let root = Path::new(&request.cache);
        let store = if request.reuse_cache {
            MailboxStore::open(root, cache_limits, now())
        } else {
            MailboxStore::create(root, cache_limits, now())
        }
        .map_err(|_| ContentError::Invalid)?;
        let mailbox = Arc::new(MailboxService::new(Arc::clone(&self.signer), store));
        if let Some(active) = service.as_mut() {
            let mut registry = active.registry.try_lock().map_err(|_| ContentError::Busy)?;
            registry.set_mailbox(mailbox);
            active.mailbox = true;
            return serving_receipt(&registry);
        }
        let mut registry = PublicationRegistry::new();
        registry.set_mailbox(mailbox);
        let receipt = serving_receipt(&registry)?;
        let tls = tls::ContentTlsServer::new(&self.tls_identity, endpoint.hostname())
            .map_err(|_| ContentError::Unavailable)?;
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        SockRef::from(&listener)
            .set_priority(CONTRIBUTION_SOCKET_PRIORITY)
            .map_err(|_| ContentError::Unavailable)?;
        context
            .discovery
            .register_content_offer(self.offer(endpoint.clone())?)
            .await
            .map_err(|_| ContentError::Unavailable)?;
        let registry = Arc::new(Mutex::new(registry));
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(Self::serve_loop(
            listener,
            tls,
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
            replication: None,
            name_lookup: false,
            mailbox: true,
        });
        Ok(receipt)
    }

    pub(crate) async fn mailbox_remote(
        &self,
        request: MailboxRemoteRequest,
        context: &ControlContext,
        stream: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let _foreground = self.foreground.enter();
        let _retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        timeout(
            OPERATION_TIMEOUT,
            remote(request, context, stream, request_id, ready_sent),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?
    }
}

fn validate_request(request: &MailboxRemoteRequest) -> Result<RemoteRequest, ContentError> {
    let provider_key: [u8; 32] = request
        .provider_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let signed = SignedMailboxGrant::decode(&request.grant).map_err(|_| ContentError::Invalid)?;
    // Structural signature validation only. The CLI separately pins its independently known
    // invitation owner; an embedded key is never new origin or publisher authority here.
    let owner =
        VerifyingKey::from_bytes(&signed.owner_key_hint().map_err(|_| ContentError::Invalid)?)
            .map_err(|_| ContentError::Invalid)?;
    let grant = signed
        .verify(&owner, now())
        .map_err(|_| ContentError::Invalid)?;
    if !grant.provider_keys().contains(&provider_key) {
        return Err(ContentError::Invalid);
    }
    let public = identity::ed25519::PublicKey::try_from_bytes(&provider_key)
        .map_err(|_| ContentError::Invalid)?;
    let peer = PeerId::from_public_key(&identity::PublicKey::from(public));
    let operation =
        MailboxOperation::try_from(request.operation).map_err(|_| ContentError::Invalid)?;
    let manifest = if request.manifest.is_empty() {
        None
    } else {
        Some(SignedManifest::decode(&request.manifest).map_err(|_| ContentError::Invalid)?)
    };
    let message_id = if request.message_id.is_empty() {
        None
    } else {
        Some(
            request
                .message_id
                .as_slice()
                .try_into()
                .map_err(|_| ContentError::Invalid)?,
        )
    };
    if !match operation {
        MailboxOperation::Register | MailboxOperation::List => {
            manifest.is_none() && message_id.is_none()
        }
        MailboxOperation::Deposit => manifest.is_some() && message_id.is_none(),
        MailboxOperation::Get | MailboxOperation::Acknowledge => {
            manifest.is_none() && message_id.is_some()
        }
    } {
        return Err(ContentError::Invalid);
    }
    Ok(RemoteRequest {
        provider_key,
        peer,
        grant,
        command: MailboxCommand {
            operation,
            manifest,
            message_id,
        },
    })
}

async fn checked_policy(
    context: &ControlContext,
    original: Option<&VerifiedPolicy>,
) -> Result<VerifiedPolicy, ContentError> {
    let state = context.state.read().await;
    let policy = state
        .active_policy(unix_millis())
        .ok_or(ContentError::Policy)?;
    if !state.roles().client
        || original.is_some_and(|old| old.policy_hash() != policy.policy_hash())
    {
        return Err(ContentError::Policy);
    }
    Ok(policy)
}

async fn remote(
    request: MailboxRemoteRequest,
    context: &ControlContext,
    local: &mut UnixStream,
    id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let request = validate_request(&request)?;
    let policy = checked_policy(context, None).await?;
    Box::pin(
        context
            .routes
            .connect_tcp(&context.config, &context.discovery, &context.helper),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?;
    let control = context
        .routes
        .content_discovery_control()
        .await
        .ok_or(ContentError::Unavailable)?;
    if !context
        .routes
        .content_provider_is_distinct(&request.peer)
        .await
    {
        return Err(ContentError::Policy);
    }
    let mut providers = context
        .discovery
        .lookup_content_providers(control, &[request.peer])
        .await
        .map_err(|_| ContentError::Unavailable)?;
    if providers.len() != 1 {
        return Err(ContentError::Unavailable);
    }
    let provider = providers.pop().ok_or(ContentError::Unavailable)?;
    if provider.peer_id != request.peer || provider.offer.provider_key() != &request.provider_key {
        return Err(ContentError::Invalid);
    }
    let expires = request
        .grant
        .validity()
        .expires
        .min(provider.offer.validity().expires);
    let remaining = expires
        .checked_sub(now())
        .filter(|seconds| *seconds > 0)
        .ok_or(ContentError::Unavailable)?;
    timeout(
        Duration::from_secs(remaining.min(150)),
        exchange(
            &request,
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
    let current = checked_policy(context, Some(&policy)).await?;
    if context.routes.content_discovery_control().await != Some(control)
        || !context
            .routes
            .content_provider_is_distinct(&request.peer)
            .await
    {
        return Err(ContentError::Policy);
    }
    request
        .grant
        .check_time(now())
        .map_err(|_| ContentError::Invalid)?;
    let endpoint = provider.offer.endpoint();
    let mut flow = context
        .routes
        .open_content_stream(
            &current,
            endpoint.hostname(),
            endpoint.port(),
            unix_millis(),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let mut remote = tls::connect(flow.stream_mut(), request.peer, &provider.offer)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let challenge = wire::begin(&mut remote, &request.provider_key)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    checked_policy(context, Some(&policy)).await?;
    request
        .grant
        .check_time(now())
        .map_err(|_| ContentError::Invalid)?;
    *ready_sent = true;
    send(
        local,
        id,
        "MAILBOX_READY",
        Payload::MailboxReady(MailboxReady {
            provider_key: request.provider_key.to_vec(),
            challenge: challenge.encode(),
        }),
    )
    .await?;
    let receipt = wire::bridge(
        local,
        &mut remote,
        &challenge,
        &request.grant,
        &request.command,
    )
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
    checked_policy(context, Some(&policy)).await?;
    request
        .grant
        .check_time(now())
        .map_err(|_| ContentError::Invalid)?;
    if provider.offer.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    send(
        local,
        id,
        "CONTENT_OK",
        Payload::Content(ContentReceipt {
            bytes: receipt.ciphertext_bytes(),
            peer_bytes: if request.command.operation == MailboxOperation::Get {
                receipt.ciphertext_bytes()
            } else {
                0
            },
            providers_used: 1,
            provider_peer_ids: vec![request.peer.to_string()],
            control_relay_peer_id: control.to_string(),
            ..ContentReceipt::default()
        }),
    )
    .await
}

async fn send(
    stream: &mut UnixStream,
    id: &[u8],
    code: &str,
    payload: Payload,
) -> Result<(), ContentError> {
    write_response(
        stream,
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
mod tests {
    use ed25519_dalek::SigningKey;
    use volparossa_content::{Validity, mailbox::MailboxQuota};

    use super::*;

    #[test]
    fn mailbox_remote_binds_exact_invitation_provider_and_typed_command() {
        let owner = SigningKey::from_bytes(&[17; 32]);
        let sender = SigningKey::from_bytes(&[18; 32]);
        let first = SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes();
        let second = SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes();
        let signed = SignedMailboxGrant::sign(
            &owner,
            sender.verifying_key().to_bytes(),
            [21; 32],
            [first, second],
            Validity {
                created: now(),
                expires: now() + 120,
            },
            MailboxQuota {
                max_bytes: 1024,
                max_messages: 2,
            },
        )
        .expect("signed invitation");
        let request = MailboxRemoteRequest {
            provider_key: first.to_vec(),
            grant: signed.encode(),
            operation: MailboxOperation::Register as i32,
            manifest: Vec::new(),
            message_id: Vec::new(),
        };
        let checked = validate_request(&request).expect("structurally bound register");
        assert_eq!(checked.provider_key, first);
        assert_eq!(checked.grant.owner_key(), owner.verifying_key().as_bytes());
        assert_eq!(checked.command.operation, MailboxOperation::Register);
        let public = identity::ed25519::PublicKey::try_from_bytes(&first).expect("provider key");
        assert_eq!(
            checked.peer,
            PeerId::from_public_key(&identity::PublicKey::from(public))
        );
        let mut wrong = request.clone();
        wrong.provider_key = SigningKey::from_bytes(&[22; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert!(validate_request(&wrong).is_err());
        let mut wrong = request.clone();
        wrong.message_id = vec![1; 32];
        assert!(validate_request(&wrong).is_err());
        let mut wrong = request.clone();
        wrong.operation = MailboxOperation::Get as i32;
        assert!(validate_request(&wrong).is_err());
        wrong.message_id = vec![1; 32];
        assert!(validate_request(&wrong).is_ok());
        let mut wrong = request;
        wrong.grant[12] ^= 1;
        assert!(validate_request(&wrong).is_err());
    }
}
