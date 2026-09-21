//! Explicit provider-side public-inference attachment to an owner-configured Unix broker.
//! The authenticated peer never supplies a local path, runtime command or model download.

use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest, Sha256};
use tokio::{
    net::UnixStream,
    sync::{Mutex, RwLock},
    time::timeout,
};
use volparossa_content::{
    model_profile::ModelProfile,
    provider::{
        ProviderEndpoint, PublicationRegistry,
        compute::{ComputeBackend, ComputeError, ComputeFuture, ComputeService, dataset},
    },
};
use volparossa_local_control::{
    ComputeAttachRequest, ContentReceipt,
    compute::{self as rpc, Capabilities, Operation, Outcome, Request, Response},
};

use super::{
    ContentError, ContentRuntime, Service, ServiceOptions, now, serving_policy, serving_receipt,
};
use crate::{control::ControlContext, state::AgentState, unix_millis};

const RPC_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone)]
struct BrokerSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}

/// The service and its snapshots may retain this backend, but never their own strong owner.
pub(super) struct Attachment {
    socket: BrokerSocket,
    service: Weak<Mutex<Option<Service>>>,
    registry: OnceLock<Weak<Mutex<PublicationRegistry>>>,
    state: Arc<RwLock<AgentState>>,
    endpoint: ProviderEndpoint,
    trusted_publishers: BTreeSet<[u8; 32]>,
    model_fingerprint: String,
    task_derivation_v1: bool,
    document_inference_v2: bool,
    derived_inference_v3: bool,
    enabled: AtomicBool,
}

impl ContentRuntime {
    /// Enable only this explicit broker and independently trusted public dataset publishers.
    #[allow(
        clippy::too_many_lines,
        reason = "One attachment transaction preserves broker, publication authority and existing listener ownership"
    )]
    pub(crate) async fn compute_attach(
        &self,
        request: &ComputeAttachRequest,
        context: &ControlContext,
    ) -> Result<ContentReceipt, ContentError> {
        let bind: SocketAddr = request
            .bind_address
            .parse()
            .map_err(|_| ContentError::Invalid)?;
        if bind.port() == 0 || !(1..=64).contains(&request.trusted_dataset_publishers.len()) {
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
        let trusted_publishers = request
            .trusted_dataset_publishers
            .iter()
            .map(|bytes| {
                let key: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ContentError::Invalid)?;
                if key == [0; 32] || VerifyingKey::from_bytes(&key).is_err() {
                    return Err(ContentError::Invalid);
                }
                Ok(key)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if trusted_publishers.len() != request.trusted_dataset_publishers.len() {
            return Err(ContentError::Invalid);
        }
        let socket = BrokerSocket::inspect(Path::new(&request.broker_socket))
            .map_err(|_| ContentError::Invalid)?;
        let capabilities = inspect_capabilities(&socket, self.signer.verifying_key().as_bytes())
            .await
            .map_err(|_| ContentError::Unavailable)?;
        let mut current = self.service.try_lock().map_err(|_| ContentError::Busy)?;
        let mut attached = self.compute.try_lock().map_err(|_| ContentError::Busy)?;
        if attached.is_some() {
            return Err(ContentError::Busy);
        }
        if current.as_ref().is_some_and(|active| {
            active.bind != bind
                || active.endpoint != endpoint
                || active.task.is_finished()
                || *active.stop.borrow()
        }) {
            return Err(ContentError::Busy);
        }
        let backend = Arc::new(Attachment {
            socket,
            service: Arc::downgrade(&self.service),
            registry: OnceLock::new(),
            state: Arc::clone(&context.state),
            endpoint: endpoint.clone(),
            trusted_publishers,
            model_fingerprint: capabilities.model_fingerprint,
            task_derivation_v1: capabilities.task_derivation_v1,
            document_inference_v2: capabilities.document_inference_v2,
            derived_inference_v3: capabilities.derived_inference_v3,
            enabled: AtomicBool::new(true),
        });
        let service = Arc::new(ComputeService::new(
            Arc::clone(&self.signer),
            backend.clone(),
        ));
        let receipt = if let Some(active) = current.as_ref() {
            backend
                .registry
                .set(Arc::downgrade(&active.registry))
                .map_err(|_| ContentError::Invalid)?;
            let mut registry = active.registry.try_lock().map_err(|_| ContentError::Busy)?;
            registry.set_compute(service);
            let receipt = serving_receipt(&registry)?;
            drop(registry);
            // The existing listener may have withdrawn its previously empty generic offer.
            // Roll back only this new compute attachment if announcing it fails.
            if context
                .discovery
                .register_content_offer(self.offer(endpoint.clone())?)
                .await
                .is_err()
            {
                backend.deactivate();
                active.registry.lock().await.clear_compute();
                return Err(ContentError::Unavailable);
            }
            receipt
        } else {
            let mut registry = PublicationRegistry::new();
            registry.set_compute(service);
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
                        automatic: false,
                    },
                )
                .await?;
            backend
                .registry
                .set(Arc::downgrade(&active.registry))
                .map_err(|_| ContentError::Invalid)?;
            *current = Some(active);
            receipt
        };
        *attached = Some(backend);
        // A newly started listener already registered exactly once in start_service.
        Ok(receipt)
    }
}

impl BrokerSocket {
    fn inspect(path: &Path) -> Result<Self, ComputeError> {
        let uid = nix::unistd::geteuid().as_raw();
        if !path.is_absolute() || path.as_os_str().len() > 107 {
            return Err(ComputeError::Invalid);
        }
        let parent = path.parent().ok_or(ComputeError::Invalid)?;
        let directory = fs::symlink_metadata(parent).map_err(|_| ComputeError::Unavailable)?;
        let info = fs::symlink_metadata(path).map_err(|_| ComputeError::Unavailable)?;
        if !directory.is_dir()
            || directory.uid() != uid
            || directory.mode() & 0o777 != 0o700
            || fs::canonicalize(parent).map_err(|_| ComputeError::Unavailable)? != parent
            || !info.file_type().is_socket()
            || info.uid() != uid
            || info.mode() & 0o777 != 0o600
            || info.nlink() != 1
        {
            return Err(ComputeError::Invalid);
        }
        Ok(Self {
            path: path.into(),
            device: info.dev(),
            inode: info.ino(),
            uid,
        })
    }

    fn check(&self) -> Result<(), ComputeError> {
        let current = Self::inspect(&self.path)?;
        if current.device != self.device || current.inode != self.inode || current.uid != self.uid {
            return Err(ComputeError::Unavailable);
        }
        Ok(())
    }

    async fn exchange(&self, request: &Request) -> Result<Response, ComputeError> {
        timeout(RPC_TIMEOUT, async {
            self.check()?;
            let mut stream = UnixStream::connect(&self.path)
                .await
                .map_err(|_| ComputeError::Unavailable)?;
            if stream
                .peer_cred()
                .map_err(|_| ComputeError::Unavailable)?
                .uid()
                != self.uid
            {
                return Err(ComputeError::Authentication);
            }
            self.check()?;
            rpc::write_request(&mut stream, request)
                .await
                .map_err(|_| ComputeError::Unavailable)?;
            rpc::read_response(&mut stream, &request.request_id)
                .await
                .map_err(|_| ComputeError::Unavailable)
        })
        .await
        .map_err(|_| ComputeError::Expired)?
    }
}

impl Attachment {
    pub(super) fn deactivate(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    async fn active(&self) -> Result<(), ComputeError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(ComputeError::Unavailable);
        }
        let service = self.service.upgrade().ok_or(ComputeError::Unavailable)?;
        let owner = service.try_lock().map_err(|_| ComputeError::Unavailable)?;
        let active = owner.as_ref().ok_or(ComputeError::Unavailable)?;
        if active.task.is_finished()
            || *active.stop.borrow()
            || active.endpoint != self.endpoint
            || !self
                .registry
                .get()
                .is_some_and(|registry| registry.ptr_eq(&Arc::downgrade(&active.registry)))
        {
            return Err(ComputeError::Unavailable);
        }
        drop(owner);
        let state = self.state.read().await;
        if !state.roles().relay {
            return Err(ComputeError::Unavailable);
        }
        state
            .active_policy(unix_millis())
            .ok_or(ComputeError::Unavailable)?
            .authorize_domain(
                unix_millis(),
                self.endpoint.hostname(),
                volparossa_policy::TransportProtocol::Tcp,
                self.endpoint.port(),
            )
            .map_err(|_| ComputeError::Unavailable)?;
        Ok(())
    }

    fn validate(&self, requester: &[u8; 32], request: &Request) -> Result<(), ComputeError> {
        request.validate(now()).map_err(|_| ComputeError::Invalid)?;
        if request.requester_key != hex::encode(requester) {
            return Err(ComputeError::Authentication);
        }
        let binding = match &request.operation {
            Operation::Capabilities | Operation::Eligibility(_) => return Ok(()),
            Operation::Submit(submit) => {
                if submit.binding.task.is_some() && !self.task_derivation_v1 {
                    return Err(ComputeError::Invalid);
                }
                if submit.binding.expires_unix_seconds <= now() {
                    return Err(ComputeError::Expired);
                }
                let publisher: [u8; 32] = hex::decode(&submit.publication.publisher_key)
                    .map_err(|_| ComputeError::Invalid)?
                    .try_into()
                    .map_err(|_| ComputeError::Invalid)?;
                if !self.trusted_publishers.contains(&publisher) {
                    return Err(ComputeError::Authentication);
                }
                let source = dataset::verify_source(
                    &hex::decode(&submit.publication.manifest_hex)
                        .map_err(|_| ComputeError::Invalid)?,
                    &VerifyingKey::from_bytes(&publisher)
                        .map_err(|_| ComputeError::Authentication)?,
                    &submit.publication.dataset_json,
                    now(),
                )?;
                if hex::encode(source.manifest_id()) != submit.binding.dataset_manifest_id
                    || (source.is_derived() && !self.derived_inference_v3)
                    || (source.is_document() && !source.is_derived() && !self.document_inference_v2)
                    || submit.binding.expires_unix_seconds > source.expires()
                    || derive_submission(&source, &submit.binding)? != submit.dataset_json
                    || hex::encode(Sha256::digest(submit.dataset_json.as_bytes()))
                        != submit.binding.dataset_sha256
                {
                    return Err(ComputeError::Authentication);
                }
                &submit.binding
            }
            Operation::Poll(binding) | Operation::Cancel(binding) => binding,
        };
        if binding.model_fingerprint != self.model_fingerprint {
            return Err(ComputeError::Authentication);
        }
        Ok(())
    }
}

pub(super) fn derive_submission(
    source: &dataset::VerifiedPublicDataset,
    binding: &rpc::JobBinding,
) -> Result<String, ComputeError> {
    match &binding.task {
        Some(task) => source.derive_question(
            &binding.row_indices,
            task.question().map_err(|_| ComputeError::Invalid)?,
        ),
        None => source.derive(&binding.row_indices),
    }
}

impl ComputeBackend for Attachment {
    fn exchange(&self, requester: [u8; 32], bytes: Vec<u8>) -> ComputeFuture<'_> {
        Box::pin(async move {
            if bytes.is_empty() || bytes.len() > rpc::MAX_REQUEST_BYTES {
                return Err(ComputeError::Invalid);
            }
            let mut request: Request =
                serde_json::from_slice(&bytes).map_err(|_| ComputeError::Invalid)?;
            self.validate(&requester, &request)?;
            self.active().await?;
            let eligibility = match &request.operation {
                Operation::Eligibility(query) => Some(query.clone()),
                _ => None,
            };
            // Publisher authority belongs to this attachment, never to the local model broker.
            if eligibility.is_some() {
                request.operation = Operation::Capabilities;
            }
            let mut response = self.socket.exchange(&request).await?;
            self.active().await?;
            if let Outcome::Capabilities(capabilities) = &response.outcome {
                validate_capabilities(capabilities)?;
                if capabilities.model_fingerprint != self.model_fingerprint
                    || capabilities.task_derivation_v1 != self.task_derivation_v1
                    || capabilities.document_inference_v2 != self.document_inference_v2
                    || capabilities.derived_inference_v3 != self.derived_inference_v3
                {
                    return Err(ComputeError::Authentication);
                }
            }
            if let Some(query) = eligibility {
                let Outcome::Capabilities(capabilities) = response.outcome else {
                    return Err(ComputeError::Invalid);
                };
                let trusted = query.publisher_keys.iter().all(|key| {
                    hex::decode(key)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .is_some_and(|key| self.trusted_publishers.contains(&key))
                });
                response.outcome = Outcome::Eligibility(rpc::Eligibility {
                    eligible: trusted && query.matches(&capabilities),
                    capabilities,
                });
            }
            let response = serde_json::to_vec(&response).map_err(|_| ComputeError::Invalid)?;
            if response.len() > rpc::MAX_RESPONSE_BYTES {
                return Err(ComputeError::Invalid);
            }
            Ok(response)
        })
    }
}

async fn inspect_capabilities(
    socket: &BrokerSocket,
    requester: &[u8; 32],
) -> Result<Capabilities, ComputeError> {
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| ComputeError::Entropy)?;
    let request = Request {
        version: rpc::VERSION,
        request_id: hex::encode(nonce),
        requester_key: hex::encode(requester),
        operation: Operation::Capabilities,
    };
    let response = socket.exchange(&request).await?;
    let Outcome::Capabilities(capabilities) = response.outcome else {
        return Err(ComputeError::Invalid);
    };
    validate_capabilities(&capabilities)?;
    Ok(capabilities)
}

pub(super) fn validate_capabilities(caps: &Capabilities) -> Result<(), ComputeError> {
    let profile = ModelProfile::from_identity(
        &caps.model.model_id,
        &caps.model.model_revision,
        caps.model.base_weights.bytes,
        &caps.model.base_weights.sha256,
    )
    .ok_or(ComputeError::Authentication)?;
    if !caps.public_inference_only
        || caps.runtime_slots != 1
        || !(1..=2).contains(&caps.max_threads)
        || !(1..=600).contains(&caps.max_job_seconds)
        || !(1..=1024 * 1024).contains(&caps.max_dataset_bytes)
        || !(1..=profile.spec().max_rows).contains(&caps.max_rows)
        || (!profile.is_default() && caps.model.adapter_files.is_some())
        || caps.model_fingerprint
            != hex::encode(Sha256::digest(
                serde_json::to_vec(&caps.model).map_err(|_| ComputeError::Invalid)?,
            ))
    {
        return Err(ComputeError::Authentication);
    }
    if let Some(files) = &caps.model.adapter_files {
        if files.len() != 3 {
            return Err(ComputeError::Invalid);
        }
        for name in [
            "README.md",
            "adapter_config.json",
            "adapter_model.safetensors",
        ] {
            let file = files.get(name).ok_or(ComputeError::Invalid)?;
            let maximum = if name == "adapter_model.safetensors" {
                2 * 1024 * 1024
            } else {
                16 * 1024
            };
            if !(1..=maximum).contains(&file.bytes) || !rpc::nonzero_hex(&file.sha256, 64) {
                return Err(ComputeError::Invalid);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
