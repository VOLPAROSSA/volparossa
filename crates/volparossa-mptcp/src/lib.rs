//! Real Linux MPTCP sockets and a generic-netlink kernel path-manager backend.
//!
//! VOLPAROSSA never silently replaces these sockets with ordinary TCP. Linux can still negotiate
//! an RFC 8684 fallback when the *remote endpoint* does not speak MPTCP; the exit listener is also
//! created with `IPPROTO_MPTCP`, and acceptance tests verify the negotiated subflows before any
//! route is considered usable.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod netlink;
mod socket;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, OnceLock},
};

#[cfg(target_os = "linux")]
use std::{fs::File, os::unix::fs::MetadataExt};

#[cfg(target_os = "linux")]
const CURRENT_NETWORK_NAMESPACE_PATH: &str = "/proc/thread-self/ns/net";

use async_trait::async_trait;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

pub use netlink::MptcpNetlinkClient;
pub use socket::{MptcpListener, MptcpStream, connect, listen, probe_kernel_support};
pub use volparossa_linux_uapi::{MptcpInfo, mptcp_info};

/// Upper bound imposed by the v1 protocol and configuration.
pub const MAX_PATHS: u8 = 8;

const MAX_TRACKED_NETWORK_NAMESPACES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct NetworkNamespaceKey {
    device: u64,
    inode: u64,
}

type ManagedContexts = Arc<Mutex<HashMap<String, ManagedContext>>>;
type NamespaceContextRegistry = std::sync::Mutex<HashMap<NetworkNamespaceKey, ManagedContexts>>;

static PROCESS_NAMESPACE_CONTEXTS: OnceLock<NamespaceContextRegistry> = OnceLock::new();

/// MPTCP path-manager errors.
#[derive(Debug, Error)]
pub enum MptcpError {
    /// A kernel socket or generic-netlink operation failed.
    #[error("kernel MPTCP operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// An endpoint or context violates a hard safety bound.
    #[error("invalid MPTCP path configuration: {0}")]
    Invalid(String),
    /// The kernel returned a malformed or unexpected netlink response.
    #[error("invalid MPTCP generic-netlink response: {0}")]
    Netlink(String),
    /// An exact cleanup or rollback must be retried before ownership can be released.
    #[error("MPTCP cleanup is incomplete: {0}")]
    CleanupIncomplete(&'static str),
    #[error("MPTCP path-manager worker failed: {0}")]
    /// A worker task could not finish.
    Worker(String),
}

bitflags! {
    /// Linux kernel MPTCP endpoint flags.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
    pub struct EndpointFlags: u32 {
        /// Announce the endpoint to the remote MPTCP peer.
        const SIGNAL = 1 << 0;
        /// Initiate subflows from this local endpoint.
        const SUBFLOW = 1 << 1;
        /// Use only when non-backup subflows cannot make progress.
        const BACKUP = 1 << 2;
        /// Kernel full-mesh flag. Public VOLPAROSSA endpoint validation deliberately rejects it;
        /// schedulers select every path explicitly.
        const FULLMESH = 1 << 3;
    }
}

/// One selected, WireGuard-bound address exposed to the kernel path manager.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MptcpEndpoint {
    /// Kernel endpoint identifier; zero is reserved for the implicit initial endpoint.
    pub id: u8,
    /// Overlay address assigned to the relevant `WireGuard` link.
    pub address: IpAddr,
    /// Kernel interface index for that `WireGuard` device.
    pub if_index: u32,
    /// Kernel path-manager flags.
    pub flags: EndpointFlags,
    /// Optional TCP listener port carried only by an address-only `SIGNAL` endpoint.
    pub listener_port: Option<u16>,
}

impl MptcpEndpoint {
    /// Validates an endpoint before any privileged operation is attempted.
    ///
    /// # Errors
    ///
    /// Returns an error when any endpoint identifier, address, interface, or flag is unsafe.
    pub fn validate(&self) -> Result<(), MptcpError> {
        if self.id == 0 {
            return Err(MptcpError::Invalid(
                "endpoint id zero is reserved for the implicit initial path".into(),
            ));
        }
        if self.id > MAX_PATHS {
            return Err(MptcpError::Invalid(format!(
                "endpoint id {} exceeds maximum {MAX_PATHS}",
                self.id
            )));
        }
        if self.if_index == 0 || i32::try_from(self.if_index).is_err() {
            return Err(MptcpError::Invalid(
                "endpoint must use a positive Linux WireGuard interface index".into(),
            ));
        }
        let IpAddr::V6(address) = self.address else {
            return Err(MptcpError::Invalid(
                "endpoint must use a VOLPAROSSA IPv6 overlay address".into(),
            ));
        };
        let segments = address.segments();
        if segments[..3] != [0xfd76, 0x6f6c, 0x7061]
            || segments[5] != u16::from(self.id)
            || !matches!(segments[7], 1 | 4)
        {
            return Err(MptcpError::Invalid(
                "endpoint address is outside its client/exit overlay path".into(),
            ));
        }
        let flags = self.flags.bits();
        let behaviours = flags & (EndpointFlags::SIGNAL.bits() | EndpointFlags::SUBFLOW.bits());
        let allowed = EndpointFlags::SIGNAL.bits()
            | EndpointFlags::SUBFLOW.bits()
            | EndpointFlags::BACKUP.bits();
        if behaviours == 0 || flags & !allowed != 0 {
            return Err(MptcpError::Invalid(
                "endpoint flags are outside the closed signal/subflow/backup set".into(),
            ));
        }
        if self.listener_port.is_some_and(|port| port == 0)
            || (self.listener_port.is_some() && self.flags != EndpointFlags::SIGNAL)
        {
            return Err(MptcpError::Invalid(
                "endpoint listener port requires an address-only signal endpoint".into(),
            ));
        }
        Ok(())
    }
}

/// Namespace-local MPTCP path-manager limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MptcpLimits {
    /// Maximum accepted peer `ADD_ADDR` announcements.
    pub accepted_addrs: u32,
    /// Maximum additional subflows.
    pub subflows: u32,
}

impl MptcpLimits {
    /// Validates v1's bounded path range.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit exceeds the v1 maximum or no additional subflow is allowed.
    pub fn validate(self) -> Result<(), MptcpError> {
        if self.accepted_addrs > u32::from(MAX_PATHS) || self.subflows > u32::from(MAX_PATHS) {
            return Err(MptcpError::Invalid(format!(
                "MPTCP limits cannot exceed {MAX_PATHS}"
            )));
        }
        if self.subflows == 0 {
            return Err(MptcpError::Invalid(
                "at least one additional subflow must be permitted".into(),
            ));
        }
        Ok(())
    }
}

/// Abstract path-manager used by the TCP proxy/session orchestrator.
#[async_trait]
pub trait MptcpPathManagerBackend: Send + Sync {
    /// Creates bounded namespace-local limits for a new route context.
    async fn prepare_context(
        &self,
        route_context_id: &str,
        limits: MptcpLimits,
    ) -> Result<(), MptcpError>;

    /// Adds one selected WireGuard-bound path.
    async fn add_path(
        &self,
        route_context_id: &str,
        endpoint: MptcpEndpoint,
    ) -> Result<(), MptcpError>;

    /// Removes a path by its context-local endpoint ID.
    async fn remove_path(&self, route_context_id: &str, endpoint_id: u8) -> Result<(), MptcpError>;

    /// Removes every endpoint owned by one route context.
    async fn cleanup_context(&self, route_context_id: &str) -> Result<(), MptcpError>;
}

/// Kernel path-manager backend bound to one network namespace.
///
/// Namespace-global MPTCP limits mean all instances in one namespace collectively own exactly one
/// route context at a time.
#[derive(Clone)]
pub struct KernelMptcpPathManager {
    contexts: ManagedContexts,
    kernel: Arc<dyn MptcpKernelBackend>,
}

/// Kernel path-manager facade for an externally serialized, single-threaded worker.
///
/// Unlike [`KernelMptcpPathManager`]'s async implementation, these operations execute generic
/// netlink on the calling thread. This is intended for the privileged helper child, whose seccomp
/// policy deliberately forbids creating threads after sandbox installation. The same namespace
/// ownership registry and rollback states are retained; only the execution mechanism differs.
pub struct SynchronousKernelMptcpPathManager {
    backend: KernelMptcpPathManager,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedEndpoint {
    Adding(MptcpEndpoint),
    Active(MptcpEndpoint),
    Removing(MptcpEndpoint),
    CleanupRequired(MptcpEndpoint),
}

impl ManagedEndpoint {
    const fn endpoint(&self) -> &MptcpEndpoint {
        match self {
            Self::Adding(endpoint)
            | Self::Active(endpoint)
            | Self::Removing(endpoint)
            | Self::CleanupRequired(endpoint) => endpoint,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedContext {
    Preparing(MptcpLimits),
    Active(HashMap<u8, ManagedEndpoint>),
    Cleaning(HashMap<u8, MptcpEndpoint>),
}

trait MptcpKernelBackend: Send + Sync {
    fn set_limits(&self, limits: MptcpLimits) -> Result<(), MptcpError>;

    fn add_endpoint(&self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError>;

    fn delete_endpoint(&self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError>;
}

struct NetlinkMptcpKernel;

impl MptcpKernelBackend for NetlinkMptcpKernel {
    fn set_limits(&self, limits: MptcpLimits) -> Result<(), MptcpError> {
        MptcpNetlinkClient::connect()?.set_limits(limits)
    }

    fn add_endpoint(&self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
        MptcpNetlinkClient::connect()?.add_endpoint(endpoint)
    }

    fn delete_endpoint(&self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
        match MptcpNetlinkClient::connect()?.delete_endpoint(endpoint) {
            Ok(()) => Ok(()),
            Err(error) if is_errno(&error, libc::ENOENT) || is_errno(&error, libc::ESRCH) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl KernelMptcpPathManager {
    /// Creates a backend bound to the calling thread's current network namespace.
    ///
    /// Independent constructors in the same namespace share one process-wide ownership slot, so
    /// they cannot overwrite namespace-global MPTCP limits. The kernel is not touched until a
    /// context is prepared.
    ///
    /// # Errors
    ///
    /// Returns an error when the current network namespace cannot be identified or the bounded
    /// process registry cannot safely reserve its namespace key.
    pub fn new() -> Result<Self, MptcpError> {
        Self::for_namespace(
            Arc::new(NetlinkMptcpKernel),
            current_network_namespace_key()?,
            process_namespace_contexts(),
            MAX_TRACKED_NETWORK_NAMESPACES,
        )
    }

    #[cfg(test)]
    fn with_kernel(kernel: Arc<dyn MptcpKernelBackend>) -> Self {
        let registry = NamespaceContextRegistry::default();
        Self::for_namespace(
            kernel,
            NetworkNamespaceKey {
                device: 1,
                inode: 1,
            },
            &registry,
            MAX_TRACKED_NETWORK_NAMESPACES,
        )
        .expect("isolated test namespace")
    }

    async fn kernel_call<T, F>(&self, operation: F) -> Result<T, MptcpError>
    where
        T: Send + 'static,
        F: FnOnce(&dyn MptcpKernelBackend) -> Result<T, MptcpError> + Send + 'static,
    {
        let kernel = Arc::clone(&self.kernel);
        tokio::task::spawn_blocking(move || operation(kernel.as_ref()))
            .await
            .map_err(|error| MptcpError::Worker(error.to_string()))?
    }

    async fn mark_add_cleanup_required(
        &self,
        route_context_id: &str,
        endpoint: MptcpEndpoint,
    ) -> Result<(), MptcpError> {
        let mut contexts = self.contexts.lock().await;
        let Some(state) = contexts.get_mut(route_context_id) else {
            return Err(MptcpError::CleanupIncomplete(
                "route context vanished while retaining endpoint ownership",
            ));
        };
        match state {
            ManagedContext::Active(endpoints) => {
                endpoints.insert(endpoint.id, ManagedEndpoint::CleanupRequired(endpoint));
            }
            ManagedContext::Cleaning(endpoints) => {
                endpoints.insert(endpoint.id, endpoint);
            }
            ManagedContext::Preparing(_) => {
                return Err(MptcpError::CleanupIncomplete(
                    "route context returned to preparation while retaining endpoint ownership",
                ));
            }
        }
        Ok(())
    }

    fn for_namespace(
        kernel: Arc<dyn MptcpKernelBackend>,
        namespace: NetworkNamespaceKey,
        registry: &NamespaceContextRegistry,
        maximum_namespaces: usize,
    ) -> Result<Self, MptcpError> {
        Ok(Self {
            contexts: contexts_for_namespace(registry, namespace, maximum_namespaces)?,
            kernel,
        })
    }
}

impl SynchronousKernelMptcpPathManager {
    /// Creates a synchronous backend bound to the calling thread's current network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when the namespace cannot be identified or the bounded namespace registry
    /// cannot admit it.
    pub fn new() -> Result<Self, MptcpError> {
        Ok(Self {
            backend: KernelMptcpPathManager::new()?,
        })
    }

    #[cfg(test)]
    fn with_kernel(kernel: Arc<dyn MptcpKernelBackend>) -> Self {
        Self {
            backend: KernelMptcpPathManager::with_kernel(kernel),
        }
    }

    /// Reserves namespace-global limits and applies them without creating an executor task.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or conflicting ownership and for kernel netlink failures.
    pub fn prepare_context(
        &self,
        route_context_id: &str,
        limits: MptcpLimits,
    ) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        limits.validate()?;
        {
            let mut contexts = self.backend.contexts.blocking_lock();
            if !contexts.is_empty() {
                return Err(MptcpError::Invalid(
                    "backend already owns its namespace context".into(),
                ));
            }
            contexts.insert(
                route_context_id.to_owned(),
                ManagedContext::Preparing(limits),
            );
        }

        let result = self.backend.kernel.set_limits(limits);
        let mut contexts = self.backend.contexts.blocking_lock();
        match result {
            Ok(())
                if matches!(
                    contexts.get(route_context_id),
                    Some(ManagedContext::Preparing(current)) if *current == limits
                ) =>
            {
                contexts.insert(
                    route_context_id.to_owned(),
                    ManagedContext::Active(HashMap::new()),
                );
                Ok(())
            }
            Ok(()) => Err(MptcpError::CleanupIncomplete(
                "prepared context state changed before limits commit",
            )),
            Err(error) => {
                if matches!(contexts.get(route_context_id), Some(ManagedContext::Preparing(current)) if *current == limits)
                {
                    contexts.remove(route_context_id);
                }
                Err(error)
            }
        }
    }

    /// Adds one selected WireGuard-bound endpoint without creating an executor task.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ownership, kernel mutation failure, or incomplete rollback.
    pub fn add_path(
        &self,
        route_context_id: &str,
        endpoint: MptcpEndpoint,
    ) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        endpoint.validate()?;
        {
            let mut contexts = self.backend.contexts.blocking_lock();
            let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id) else {
                return Err(MptcpError::Invalid(
                    "route context is absent or busy".into(),
                ));
            };
            if let Some(current) = endpoints.get(&endpoint.id) {
                return if matches!(current, ManagedEndpoint::Active(_))
                    && current.endpoint() == &endpoint
                {
                    Ok(())
                } else {
                    Err(MptcpError::Invalid(
                        "endpoint id has a conflicting or pending owner".into(),
                    ))
                };
            }
            if endpoints.len() >= usize::from(MAX_PATHS) {
                return Err(MptcpError::Invalid(
                    "route context path limit reached".into(),
                ));
            }
            endpoints.insert(endpoint.id, ManagedEndpoint::Adding(endpoint.clone()));
        }

        if let Err(error) = self.backend.kernel.add_endpoint(&endpoint) {
            if is_errno(&error, libc::EEXIST) {
                let mut contexts = self.backend.contexts.blocking_lock();
                if let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id)
                {
                    if matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Adding(current)) if current == &endpoint)
                    {
                        endpoints.remove(&endpoint.id);
                    }
                }
                return Err(error);
            }
            if self.backend.kernel.delete_endpoint(&endpoint).is_ok() {
                let mut contexts = self.backend.contexts.blocking_lock();
                if let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id)
                {
                    if matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Adding(current)) if current == &endpoint)
                    {
                        endpoints.remove(&endpoint.id);
                    }
                }
                return Err(error);
            }
            let _cleanup_state = self.mark_add_cleanup_required(route_context_id, endpoint);
            return Err(MptcpError::CleanupIncomplete(
                "failed endpoint add could not be rolled back",
            ));
        }

        let committed = {
            let mut contexts = self.backend.contexts.blocking_lock();
            match contexts.get_mut(route_context_id) {
                Some(ManagedContext::Active(endpoints)) if matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Adding(current)) if current == &endpoint) =>
                {
                    endpoints.insert(endpoint.id, ManagedEndpoint::Active(endpoint.clone()));
                    true
                }
                Some(_) | None => false,
            }
        };
        if committed {
            return Ok(());
        }
        if self.backend.kernel.delete_endpoint(&endpoint).is_ok() {
            return Err(MptcpError::Worker(
                "endpoint state commit failed; exact kernel rollback completed".into(),
            ));
        }
        let _cleanup_state = self.mark_add_cleanup_required(route_context_id, endpoint);
        Err(MptcpError::CleanupIncomplete(
            "endpoint state commit and exact rollback failed",
        ))
    }

    fn mark_add_cleanup_required(
        &self,
        route_context_id: &str,
        endpoint: MptcpEndpoint,
    ) -> Result<(), MptcpError> {
        let mut contexts = self.backend.contexts.blocking_lock();
        match contexts.get_mut(route_context_id) {
            Some(ManagedContext::Active(endpoints)) => {
                endpoints.insert(endpoint.id, ManagedEndpoint::CleanupRequired(endpoint));
            }
            Some(ManagedContext::Cleaning(endpoints)) => {
                endpoints.insert(endpoint.id, endpoint);
            }
            Some(ManagedContext::Preparing(_)) | None => {
                return Err(MptcpError::CleanupIncomplete(
                    "route context vanished while retaining endpoint ownership",
                ));
            }
        }
        Ok(())
    }

    /// Removes one owned endpoint without creating an executor task.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ownership or when exact endpoint cleanup remains pending.
    pub fn remove_path(&self, route_context_id: &str, endpoint_id: u8) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        if endpoint_id == 0 || endpoint_id > MAX_PATHS {
            return Err(MptcpError::Invalid("invalid endpoint id".into()));
        }
        let endpoint = {
            let mut contexts = self.backend.contexts.blocking_lock();
            let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id) else {
                return Err(MptcpError::Invalid(
                    "route context is absent or busy".into(),
                ));
            };
            let Some(current) = endpoints.get(&endpoint_id).cloned() else {
                return Ok(());
            };
            let endpoint = match current {
                ManagedEndpoint::Active(endpoint) | ManagedEndpoint::CleanupRequired(endpoint) => {
                    endpoint
                }
                ManagedEndpoint::Adding(_) | ManagedEndpoint::Removing(_) => {
                    return Err(MptcpError::Invalid(
                        "endpoint mutation is already pending".into(),
                    ));
                }
            };
            endpoints.insert(endpoint_id, ManagedEndpoint::Removing(endpoint.clone()));
            endpoint
        };
        let result = self.backend.kernel.delete_endpoint(&endpoint);
        let mut contexts = self.backend.contexts.blocking_lock();
        let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id) else {
            return Err(MptcpError::CleanupIncomplete(
                "context state changed during endpoint removal",
            ));
        };
        if !matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Removing(current)) if current == &endpoint)
        {
            return Err(MptcpError::CleanupIncomplete(
                "endpoint state changed during removal",
            ));
        }
        match result {
            Ok(()) => {
                endpoints.remove(&endpoint.id);
                Ok(())
            }
            Err(error) => {
                tracing::warn!(endpoint_id, %error, "MPTCP endpoint removal will be retried");
                endpoints.insert(endpoint.id, ManagedEndpoint::CleanupRequired(endpoint));
                Err(MptcpError::CleanupIncomplete(
                    "endpoint removal failed and remains owned",
                ))
            }
        }
    }

    /// Removes all endpoints owned by one context without creating an executor task.
    ///
    /// # Errors
    ///
    /// Returns an error while any exact endpoint cleanup remains pending.
    pub fn cleanup_context(&self, route_context_id: &str) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        let endpoints = {
            let mut contexts = self.backend.contexts.blocking_lock();
            let Some(context) = contexts.get_mut(route_context_id) else {
                return Ok(());
            };
            match context {
                ManagedContext::Preparing(_) => {
                    return Err(MptcpError::Invalid(
                        "context preparation is still pending".into(),
                    ));
                }
                ManagedContext::Active(endpoints) => {
                    if endpoints.values().any(|state| {
                        matches!(
                            state,
                            ManagedEndpoint::Adding(_) | ManagedEndpoint::Removing(_)
                        )
                    }) {
                        return Err(MptcpError::Invalid(
                            "endpoint mutation is still pending".into(),
                        ));
                    }
                    let owned = endpoints
                        .values()
                        .map(|state| (state.endpoint().id, state.endpoint().clone()))
                        .collect::<HashMap<_, _>>();
                    *context = ManagedContext::Cleaning(owned.clone());
                    owned
                }
                ManagedContext::Cleaning(endpoints) => endpoints.clone(),
            }
        };

        let mut endpoints = endpoints.into_values().collect::<Vec<_>>();
        endpoints.sort_unstable_by_key(|endpoint| endpoint.id);
        for endpoint in endpoints {
            let endpoint_id = endpoint.id;
            if let Err(error) = self.backend.kernel.delete_endpoint(&endpoint) {
                tracing::warn!(endpoint_id, %error, "MPTCP cleanup will be retried");
                return Err(MptcpError::CleanupIncomplete(
                    "context endpoint cleanup failed",
                ));
            }
            let mut contexts = self.backend.contexts.blocking_lock();
            let Some(ManagedContext::Cleaning(remaining)) = contexts.get_mut(route_context_id)
            else {
                return Err(MptcpError::CleanupIncomplete(
                    "context cleanup state changed unexpectedly",
                ));
            };
            if remaining.get(&endpoint_id) != Some(&endpoint) {
                return Err(MptcpError::CleanupIncomplete(
                    "owned endpoint changed during cleanup",
                ));
            }
            remaining.remove(&endpoint_id);
        }
        let mut contexts = self.backend.contexts.blocking_lock();
        if matches!(contexts.get(route_context_id), Some(ManagedContext::Cleaning(remaining)) if remaining.is_empty())
        {
            contexts.remove(route_context_id);
            Ok(())
        } else {
            Err(MptcpError::CleanupIncomplete(
                "context retained endpoint ownership after cleanup",
            ))
        }
    }
}

fn process_namespace_contexts() -> &'static NamespaceContextRegistry {
    PROCESS_NAMESPACE_CONTEXTS.get_or_init(NamespaceContextRegistry::default)
}

fn contexts_for_namespace(
    registry: &NamespaceContextRegistry,
    namespace: NetworkNamespaceKey,
    maximum_namespaces: usize,
) -> Result<ManagedContexts, MptcpError> {
    if maximum_namespaces == 0 {
        return Err(MptcpError::Invalid(
            "network namespace registry has no capacity".into(),
        ));
    }
    let mut namespaces = registry.lock().map_err(|_| {
        MptcpError::CleanupIncomplete("network namespace ownership registry is poisoned")
    })?;
    if let Some(contexts) = namespaces.get(&namespace) {
        return Ok(Arc::clone(contexts));
    }
    if namespaces.len() >= maximum_namespaces {
        return Err(MptcpError::Invalid(
            "network namespace ownership registry capacity reached".into(),
        ));
    }
    let contexts = Arc::new(Mutex::new(HashMap::new()));
    namespaces.insert(namespace, Arc::clone(&contexts));
    Ok(contexts)
}

#[cfg(target_os = "linux")]
fn current_network_namespace_key() -> Result<NetworkNamespaceKey, MptcpError> {
    // Network namespaces are per-thread. Keep this bound to the caller when a future dedicated
    // worker enters a namespace with setns(2).
    let namespace = File::open(CURRENT_NETWORK_NAMESPACE_PATH)?;
    let metadata = namespace.metadata()?;
    if metadata.ino() == 0 {
        return Err(MptcpError::Invalid(
            "current network namespace has no stable inode".into(),
        ));
    }
    Ok(NetworkNamespaceKey {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(target_os = "linux"))]
fn current_network_namespace_key() -> Result<NetworkNamespaceKey, MptcpError> {
    Err(MptcpError::Invalid(
        "kernel MPTCP requires a Linux network namespace".into(),
    ))
}

#[async_trait]
impl MptcpPathManagerBackend for KernelMptcpPathManager {
    async fn prepare_context(
        &self,
        route_context_id: &str,
        limits: MptcpLimits,
    ) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        limits.validate()?;
        {
            let mut contexts = self.contexts.lock().await;
            if !contexts.is_empty() {
                return Err(MptcpError::Invalid(
                    "backend already owns its namespace context".into(),
                ));
            }
            contexts.insert(
                route_context_id.to_owned(),
                ManagedContext::Preparing(limits),
            );
        }
        let result = self
            .kernel_call(move |kernel| kernel.set_limits(limits))
            .await;
        let mut contexts = self.contexts.lock().await;
        match result {
            Ok(())
                if matches!(
                    contexts.get(route_context_id),
                    Some(ManagedContext::Preparing(current)) if *current == limits
                ) =>
            {
                contexts.insert(
                    route_context_id.to_owned(),
                    ManagedContext::Active(HashMap::new()),
                );
                Ok(())
            }
            Ok(()) => Err(MptcpError::CleanupIncomplete(
                "prepared context state changed before limits commit",
            )),
            Err(error) => {
                if matches!(contexts.get(route_context_id), Some(ManagedContext::Preparing(current)) if *current == limits)
                {
                    contexts.remove(route_context_id);
                }
                Err(error)
            }
        }
    }

    async fn add_path(
        &self,
        route_context_id: &str,
        endpoint: MptcpEndpoint,
    ) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        endpoint.validate()?;
        {
            let mut contexts = self.contexts.lock().await;
            let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id) else {
                return Err(MptcpError::Invalid(
                    "route context is absent or busy".into(),
                ));
            };
            if let Some(current) = endpoints.get(&endpoint.id) {
                return if matches!(current, ManagedEndpoint::Active(_))
                    && current.endpoint() == &endpoint
                {
                    Ok(())
                } else {
                    Err(MptcpError::Invalid(
                        "endpoint id has a conflicting or pending owner".into(),
                    ))
                };
            }
            if endpoints.len() >= usize::from(MAX_PATHS) {
                return Err(MptcpError::Invalid(
                    "route context path limit reached".into(),
                ));
            }
            endpoints.insert(endpoint.id, ManagedEndpoint::Adding(endpoint.clone()));
        }

        let kernel_endpoint = endpoint.clone();
        if let Err(error) = self
            .kernel_call(move |kernel| kernel.add_endpoint(&kernel_endpoint))
            .await
        {
            if is_errno(&error, libc::EEXIST) {
                let mut contexts = self.contexts.lock().await;
                if let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id)
                {
                    if matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Adding(current)) if current == &endpoint)
                    {
                        endpoints.remove(&endpoint.id);
                    }
                }
                return Err(error);
            }
            let rollback_endpoint = endpoint.clone();
            let rollback = self
                .kernel_call(move |kernel| kernel.delete_endpoint(&rollback_endpoint))
                .await;
            if rollback.is_ok() {
                let mut contexts = self.contexts.lock().await;
                if let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id)
                {
                    if matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Adding(current)) if current == &endpoint)
                    {
                        endpoints.remove(&endpoint.id);
                    }
                }
                return Err(error);
            }
            let _cleanup_state = self
                .mark_add_cleanup_required(route_context_id, endpoint)
                .await;
            return Err(MptcpError::CleanupIncomplete(
                "failed endpoint add could not be rolled back",
            ));
        }

        let committed = {
            let mut contexts = self.contexts.lock().await;
            match contexts.get_mut(route_context_id) {
                Some(ManagedContext::Active(endpoints)) if matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Adding(current)) if current == &endpoint) =>
                {
                    endpoints.insert(endpoint.id, ManagedEndpoint::Active(endpoint.clone()));
                    true
                }
                Some(_) | None => false,
            }
        };
        if committed {
            return Ok(());
        }
        let rollback_endpoint = endpoint.clone();
        if self
            .kernel_call(move |kernel| kernel.delete_endpoint(&rollback_endpoint))
            .await
            .is_ok()
        {
            return Err(MptcpError::Worker(
                "endpoint state commit failed; exact kernel rollback completed".into(),
            ));
        }
        let _cleanup_state = self
            .mark_add_cleanup_required(route_context_id, endpoint)
            .await;
        Err(MptcpError::CleanupIncomplete(
            "endpoint state commit and exact rollback failed",
        ))
    }

    async fn remove_path(&self, route_context_id: &str, endpoint_id: u8) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        if endpoint_id == 0 || endpoint_id > MAX_PATHS {
            return Err(MptcpError::Invalid("invalid endpoint id".into()));
        }
        let endpoint = {
            let mut contexts = self.contexts.lock().await;
            let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id) else {
                return Err(MptcpError::Invalid(
                    "route context is absent or busy".into(),
                ));
            };
            let Some(current) = endpoints.get(&endpoint_id).cloned() else {
                return Ok(());
            };
            let endpoint = match current {
                ManagedEndpoint::Active(endpoint) | ManagedEndpoint::CleanupRequired(endpoint) => {
                    endpoint
                }
                ManagedEndpoint::Adding(_) | ManagedEndpoint::Removing(_) => {
                    return Err(MptcpError::Invalid(
                        "endpoint mutation is already pending".into(),
                    ));
                }
            };
            endpoints.insert(endpoint_id, ManagedEndpoint::Removing(endpoint.clone()));
            endpoint
        };
        let kernel_endpoint = endpoint.clone();
        let result = self
            .kernel_call(move |kernel| kernel.delete_endpoint(&kernel_endpoint))
            .await;
        let mut contexts = self.contexts.lock().await;
        let Some(ManagedContext::Active(endpoints)) = contexts.get_mut(route_context_id) else {
            return Err(MptcpError::CleanupIncomplete(
                "context state changed during endpoint removal",
            ));
        };
        if !matches!(endpoints.get(&endpoint.id), Some(ManagedEndpoint::Removing(current)) if current == &endpoint)
        {
            return Err(MptcpError::CleanupIncomplete(
                "endpoint state changed during removal",
            ));
        }
        match result {
            Ok(()) => {
                endpoints.remove(&endpoint.id);
                Ok(())
            }
            Err(error) => {
                tracing::warn!(endpoint_id, %error, "MPTCP endpoint removal will be retried");
                endpoints.insert(endpoint.id, ManagedEndpoint::CleanupRequired(endpoint));
                Err(MptcpError::CleanupIncomplete(
                    "endpoint removal failed and remains owned",
                ))
            }
        }
    }

    async fn cleanup_context(&self, route_context_id: &str) -> Result<(), MptcpError> {
        validate_context_id(route_context_id)?;
        let endpoints = {
            let mut contexts = self.contexts.lock().await;
            let Some(context) = contexts.get_mut(route_context_id) else {
                return Ok(());
            };
            match context {
                ManagedContext::Preparing(_) => {
                    return Err(MptcpError::Invalid(
                        "context preparation is still pending".into(),
                    ));
                }
                ManagedContext::Active(endpoints) => {
                    if endpoints.values().any(|state| {
                        matches!(
                            state,
                            ManagedEndpoint::Adding(_) | ManagedEndpoint::Removing(_)
                        )
                    }) {
                        return Err(MptcpError::Invalid(
                            "endpoint mutation is still pending".into(),
                        ));
                    }
                    let owned = endpoints
                        .values()
                        .map(|state| (state.endpoint().id, state.endpoint().clone()))
                        .collect::<HashMap<_, _>>();
                    *context = ManagedContext::Cleaning(owned.clone());
                    owned
                }
                ManagedContext::Cleaning(endpoints) => endpoints.clone(),
            }
        };

        let mut endpoints = endpoints.into_values().collect::<Vec<_>>();
        endpoints.sort_unstable_by_key(|endpoint| endpoint.id);
        for endpoint in endpoints {
            let endpoint_id = endpoint.id;
            let kernel_endpoint = endpoint.clone();
            let result = self
                .kernel_call(move |kernel| kernel.delete_endpoint(&kernel_endpoint))
                .await;
            if let Err(error) = result {
                tracing::warn!(endpoint_id, %error, "MPTCP cleanup will be retried");
                return Err(MptcpError::CleanupIncomplete(
                    "context endpoint cleanup failed",
                ));
            }
            let mut contexts = self.contexts.lock().await;
            let Some(ManagedContext::Cleaning(remaining)) = contexts.get_mut(route_context_id)
            else {
                return Err(MptcpError::CleanupIncomplete(
                    "context cleanup state changed unexpectedly",
                ));
            };
            if remaining.get(&endpoint_id) != Some(&endpoint) {
                return Err(MptcpError::CleanupIncomplete(
                    "owned endpoint changed during cleanup",
                ));
            }
            remaining.remove(&endpoint_id);
        }
        let mut contexts = self.contexts.lock().await;
        if matches!(contexts.get(route_context_id), Some(ManagedContext::Cleaning(remaining)) if remaining.is_empty())
        {
            contexts.remove(route_context_id);
            Ok(())
        } else {
            Err(MptcpError::CleanupIncomplete(
                "context retained endpoint ownership after cleanup",
            ))
        }
    }
}

fn is_errno(error: &MptcpError, expected: i32) -> bool {
    matches!(error, MptcpError::Io(error) if error.raw_os_error() == Some(expected))
}

fn validate_context_id(value: &str) -> Result<(), MptcpError> {
    if value.is_empty() || value.len() > 64 {
        return Err(MptcpError::Invalid(
            "route context ID length must be 1..=64".into(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MptcpError::Invalid(
            "route context ID contains a forbidden character".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::{BufRead as _, BufReader, Read as _, Write as _},
        net::SocketAddr,
        process::{Command, Stdio},
        time::Duration,
    };

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    const LIVE_MULTIPATH_ROLE: &str = "VOLPAROSSA_MPTCP_LIVE_MULTIPATH_ROLE";
    const LIVE_MULTIPATH_TEST: &str =
        "tests::kernel_backend_drives_two_data_carrying_subflows_in_disposable_namespaces";

    fn overlay_address(path_id: u8, host: u16) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(
            0xfd76,
            0x6f6c,
            0x7061,
            0x1111,
            0x2222,
            u16::from(path_id),
            0x3333,
            host,
        ))
    }

    #[test]
    fn endpoint_accepts_only_closed_signal_subflow_and_backup_flags() {
        for flags in [
            EndpointFlags::SIGNAL,
            EndpointFlags::SUBFLOW,
            EndpointFlags::SIGNAL | EndpointFlags::SUBFLOW,
            EndpointFlags::SIGNAL | EndpointFlags::BACKUP,
            EndpointFlags::SUBFLOW | EndpointFlags::BACKUP,
            EndpointFlags::SIGNAL | EndpointFlags::SUBFLOW | EndpointFlags::BACKUP,
        ] {
            selected_endpoint(1)
                .with_flags(flags)
                .validate()
                .expect("closed flags");
        }
        for flags in [
            EndpointFlags::empty(),
            EndpointFlags::BACKUP,
            EndpointFlags::SUBFLOW | EndpointFlags::FULLMESH,
            EndpointFlags::SUBFLOW | EndpointFlags::from_bits_retain(1 << 31),
        ] {
            assert!(selected_endpoint(1).with_flags(flags).validate().is_err());
        }
    }

    #[test]
    fn endpoint_listener_port_requires_an_address_only_signal() {
        let mut endpoint = selected_endpoint(2).with_flags(EndpointFlags::SIGNAL);
        endpoint.listener_port = Some(44_443);
        endpoint.validate().expect("signal listener endpoint");

        endpoint.flags = EndpointFlags::SIGNAL | EndpointFlags::SUBFLOW;
        assert!(endpoint.validate().is_err());
        endpoint.flags = EndpointFlags::SUBFLOW;
        assert!(endpoint.validate().is_err());
        endpoint.flags = EndpointFlags::SIGNAL;
        endpoint.listener_port = Some(0);
        assert!(endpoint.validate().is_err());
    }

    #[test]
    fn endpoint_requires_structured_overlay_address_and_signed_linux_ifindex() {
        let valid = selected_endpoint(1);
        valid.validate().expect("client overlay endpoint");
        let mut exit = valid.clone();
        exit.address = overlay_address(1, 4);
        exit.validate().expect("exit overlay endpoint");

        let mut invalid = valid.clone();
        invalid.address = "10.0.0.1".parse().expect("IPv4");
        assert!(invalid.validate().is_err());
        invalid.address = "fd77:6f6c:7061:1111:2222:1:3333:1"
            .parse()
            .expect("wrong overlay prefix");
        assert!(invalid.validate().is_err());
        invalid.address = overlay_address(2, 1);
        assert!(invalid.validate().is_err());
        invalid.address = overlay_address(1, 2);
        assert!(invalid.validate().is_err());
        invalid = valid;
        invalid.if_index = 0;
        assert!(invalid.validate().is_err());
        invalid.if_index = u32::try_from(i32::MAX).expect("positive maximum") + 1;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn context_ids_are_bounded_and_not_paths_or_commands() {
        assert!(validate_context_id("01926f8e_route-1").is_ok());
        assert!(validate_context_id("../../host").is_err());
        assert!(validate_context_id("route;shutdown").is_err());
        assert!(validate_context_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn kernel_backend_drives_two_data_carrying_subflows_in_disposable_namespaces() {
        match env::var(LIVE_MULTIPATH_ROLE).as_deref() {
            Ok("server") => {
                tokio::runtime::Runtime::new()
                    .expect("server runtime")
                    .block_on(live_multipath_server());
                return;
            }
            Ok("client") => {
                tokio::runtime::Runtime::new()
                    .expect("client runtime")
                    .block_on(live_multipath_client());
                return;
            }
            Ok("orchestrator") => {
                run_live_multipath_topology();
                return;
            }
            Ok(_) => panic!("invalid live multipath role"),
            Err(_) => {}
        }

        let executable = env::current_exe().expect("current MPTCP test executable");
        let output = Command::new("/usr/bin/timeout")
            .args([
                "60",
                "unshare",
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--fork",
            ])
            .arg(executable)
            .arg("--exact")
            .arg(LIVE_MULTIPATH_TEST)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_MULTIPATH_ROLE, "orchestrator")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .expect("spawn disposable MPTCP topology");
        let denied = output.status.code() == Some(1)
            && output.stdout.is_empty()
            && matches!(
                output.stderr.as_slice(),
                b"unshare: unshare failed: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
            );
        if denied {
            eprintln!("skipped live MPTCP topology: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "live MPTCP topology failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn command(program: &str, arguments: &[&str]) {
        let output = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("run {program} {arguments:?}: {error}"));
        assert!(
            output.status.success(),
            "{program} {arguments:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn netns_command(namespace: &str, arguments: &[&str]) {
        let mut command_arguments = vec!["netns", "exec", namespace, "ip"];
        command_arguments.extend_from_slice(arguments);
        command("ip", &command_arguments);
    }

    fn create_link(
        left_namespace: &str,
        left_name: &str,
        left_address: &str,
        right_namespace: &str,
        right_name: &str,
        right_address: &str,
    ) {
        let temporary_left = format!("t{left_name}");
        let temporary_right = format!("t{right_name}");
        command(
            "ip",
            &[
                "link",
                "add",
                &temporary_left,
                "type",
                "veth",
                "peer",
                "name",
                &temporary_right,
            ],
        );
        command(
            "ip",
            &["link", "set", &temporary_left, "netns", left_namespace],
        );
        command(
            "ip",
            &["link", "set", &temporary_right, "netns", right_namespace],
        );
        netns_command(
            left_namespace,
            &["link", "set", &temporary_left, "name", left_name],
        );
        netns_command(
            right_namespace,
            &["link", "set", &temporary_right, "name", right_name],
        );
        netns_command(
            left_namespace,
            &["address", "add", left_address, "dev", left_name, "nodad"],
        );
        netns_command(
            right_namespace,
            &["address", "add", right_address, "dev", right_name, "nodad"],
        );
        netns_command(left_namespace, &["link", "set", left_name, "up"]);
        netns_command(right_namespace, &["link", "set", right_name, "up"]);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the disposable topology is intentionally linear so setup mirrors teardown"
    )]
    fn run_live_multipath_topology() {
        command("mount", &["--make-rprivate", "/"]);
        command(
            "mount",
            &[
                "-t",
                "tmpfs",
                "-o",
                "mode=0755,nosuid,nodev",
                "tmpfs",
                "/run",
            ],
        );
        fs::create_dir_all("/run/netns").expect("create private netns directory");
        for namespace in ["vp-c", "vp-r1", "vp-r2", "vp-x"] {
            command("ip", &["netns", "add", namespace]);
            netns_command(namespace, &["link", "set", "lo", "up"]);
        }
        create_link("vp-c", "c1", "fd42:1::1/64", "vp-r1", "r1c", "fd42:1::2/64");
        create_link("vp-r1", "r1x", "fd42:2::1/64", "vp-x", "x1", "fd42:2::2/64");
        create_link("vp-c", "c2", "fd42:3::1/64", "vp-r2", "r2c", "fd42:3::2/64");
        create_link("vp-r2", "r2x", "fd42:4::1/64", "vp-x", "x2", "fd42:4::2/64");
        let client_one = "fd76:6f6c:7061:1111:2222:1:3333:1";
        let client_two = "fd76:6f6c:7061:1111:2222:2:3333:1";
        let exit_one = "fd76:6f6c:7061:1111:2222:1:3333:4";
        let exit_two = "fd76:6f6c:7061:1111:2222:3:3333:4";
        netns_command(
            "vp-c",
            &[
                "address",
                "add",
                &format!("{client_one}/128"),
                "dev",
                "c1",
                "nodad",
            ],
        );
        netns_command(
            "vp-c",
            &[
                "address",
                "add",
                &format!("{client_two}/128"),
                "dev",
                "c2",
                "nodad",
            ],
        );
        netns_command(
            "vp-x",
            &[
                "address",
                "add",
                &format!("{exit_one}/128"),
                "dev",
                "x1",
                "nodad",
            ],
        );
        netns_command(
            "vp-x",
            &[
                "address",
                "add",
                &format!("{exit_two}/128"),
                "dev",
                "x2",
                "nodad",
            ],
        );
        for relay in ["vp-r1", "vp-r2"] {
            command(
                "ip",
                &[
                    "netns",
                    "exec",
                    relay,
                    "/bin/sh",
                    "-c",
                    "printf 1 >/proc/sys/net/ipv6/conf/all/forwarding",
                ],
            );
        }
        netns_command(
            "vp-c",
            &[
                "-6",
                "route",
                "add",
                &format!("{exit_one}/128"),
                "via",
                "fd42:1::2",
                "dev",
                "c1",
                "src",
                client_one,
                "cwnd",
                "2",
            ],
        );
        netns_command(
            "vp-c",
            &[
                "-6",
                "rule",
                "add",
                "from",
                &format!("{client_one}/128"),
                "table",
                "101",
            ],
        );
        netns_command(
            "vp-c",
            &[
                "-6",
                "route",
                "add",
                "table",
                "101",
                &format!("{exit_one}/128"),
                "via",
                "fd42:1::2",
                "dev",
                "c1",
                "src",
                client_one,
                "cwnd",
                "2",
            ],
        );
        netns_command(
            "vp-c",
            &[
                "-6",
                "rule",
                "add",
                "from",
                &format!("{client_two}/128"),
                "table",
                "102",
            ],
        );
        netns_command(
            "vp-c",
            &[
                "-6",
                "route",
                "add",
                "table",
                "102",
                &format!("{exit_two}/128"),
                "via",
                "fd42:3::2",
                "dev",
                "c2",
                "src",
                client_two,
            ],
        );
        netns_command(
            "vp-r1",
            &[
                "-6",
                "route",
                "add",
                &format!("{client_one}/128"),
                "via",
                "fd42:1::1",
                "dev",
                "r1c",
            ],
        );
        netns_command(
            "vp-r1",
            &[
                "-6",
                "route",
                "add",
                &format!("{exit_one}/128"),
                "via",
                "fd42:2::2",
                "dev",
                "r1x",
            ],
        );
        netns_command(
            "vp-r2",
            &[
                "-6",
                "route",
                "add",
                &format!("{client_two}/128"),
                "via",
                "fd42:3::1",
                "dev",
                "r2c",
            ],
        );
        netns_command(
            "vp-r2",
            &[
                "-6",
                "route",
                "add",
                &format!("{exit_two}/128"),
                "via",
                "fd42:4::2",
                "dev",
                "r2x",
            ],
        );
        netns_command(
            "vp-x",
            &[
                "-6",
                "route",
                "add",
                &format!("{client_one}/128"),
                "via",
                "fd42:2::1",
                "dev",
                "x1",
            ],
        );
        netns_command(
            "vp-x",
            &[
                "-6",
                "route",
                "add",
                &format!("{client_two}/128"),
                "via",
                "fd42:4::1",
                "dev",
                "x2",
            ],
        );

        let executable = env::current_exe().expect("current MPTCP test executable");
        let mut server = Command::new("ip")
            .args(["netns", "exec", "vp-x", "env"])
            .arg(format!("{LIVE_MULTIPATH_ROLE}=server"))
            .args(["/usr/bin/timeout", "25"])
            .arg(&executable)
            .args([
                "--exact",
                LIVE_MULTIPATH_TEST,
                "--test-threads=1",
                "--nocapture",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn MPTCP Exit server");
        let mut server_stdout = BufReader::new(server.stdout.take().expect("server stdout"));
        let mut line = String::new();
        loop {
            line.clear();
            if server_stdout
                .read_line(&mut line)
                .expect("server readiness")
                == 0
            {
                let mut error = String::new();
                server
                    .stderr
                    .take()
                    .expect("server stderr")
                    .read_to_string(&mut error)
                    .expect("read server stderr");
                panic!("MPTCP Exit exited before readiness: {error}");
            }
            if line.contains("MPTCP_SERVER_READY") {
                break;
            }
        }
        let client = Command::new("ip")
            .args(["netns", "exec", "vp-c", "env"])
            .arg(format!("{LIVE_MULTIPATH_ROLE}=client"))
            .args(["/usr/bin/timeout", "20"])
            .arg(&executable)
            .args([
                "--exact",
                LIVE_MULTIPATH_TEST,
                "--test-threads=1",
                "--nocapture",
            ])
            .stdin(Stdio::null())
            .output()
            .expect("run MPTCP Client proof");
        assert!(
            client.status.success(),
            "client failed: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        let server_status = server.wait().expect("wait MPTCP Exit server");
        let mut remaining_server_output = String::new();
        server_stdout
            .read_to_string(&mut remaining_server_output)
            .expect("remaining server output");
        assert!(
            server_status.success(),
            "server failed: {remaining_server_output}"
        );
        for namespace in ["vp-c", "vp-r1", "vp-r2", "vp-x"] {
            command("ip", &["netns", "delete", namespace]);
        }
    }

    async fn live_multipath_server() {
        let address: SocketAddr = "[::]:40123".parse().expect("Exit address");
        let manager = KernelMptcpPathManager::new().expect("kernel MPTCP path manager");
        manager
            .prepare_context(
                "live_exit_signal",
                MptcpLimits {
                    accepted_addrs: 4,
                    subflows: 4,
                },
            )
            .await
            .expect("prepare Exit kernel path manager");
        let listener = listen(address, 8).expect("MPTCP listener");
        println!("MPTCP_SERVER_READY");
        std::io::stdout().flush().expect("flush server readiness");
        let (mut stream, _) = listener.accept().await.expect("accept genuine MPTCP");
        eprintln!("server: accepted MPTCP");
        let mut initial_block = vec![0_u8; 1024 * 1024];
        stream
            .as_tcp_stream_mut()
            .read_exact(&mut initial_block)
            .await
            .expect("initial path data");
        assert!(initial_block.iter().all(|byte| *byte == 0x51));
        stream
            .as_tcp_stream_mut()
            .write_all(&[1])
            .await
            .expect("initial acknowledgement");
        manager
            .add_path(
                "live_exit_signal",
                MptcpEndpoint {
                    id: 3,
                    address: "fd76:6f6c:7061:1111:2222:3:3333:4"
                        .parse()
                        .expect("Exit path two"),
                    if_index: fs::read_to_string("/sys/class/net/x2/ifindex")
                        .expect("Exit path ifindex")
                        .trim()
                        .parse()
                        .expect("numeric Exit path ifindex"),
                    flags: EndpointFlags::SIGNAL,
                    listener_port: None,
                },
            )
            .await
            .expect("signal Exit MPTCP address");
        let mut second_block = vec![0_u8; 64 * 1024 * 1024];
        stream
            .as_tcp_stream_mut()
            .read_exact(&mut second_block)
            .await
            .expect("second path data");
        assert!(second_block.iter().all(|byte| *byte == 0xa2));
        stream
            .as_tcp_stream_mut()
            .write_all(&[2])
            .await
            .expect("second acknowledgement");
        manager
            .cleanup_context("live_exit_signal")
            .await
            .expect("Exit MPTCP endpoint cleanup");
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the live client proof keeps ordered socket, subflow, and byte evidence together"
    )]
    async fn live_multipath_client() {
        let client_one: SocketAddr = "[fd76:6f6c:7061:1111:2222:1:3333:1]:40124"
            .parse()
            .expect("Client path one");
        let remote: SocketAddr = "[fd76:6f6c:7061:1111:2222:1:3333:4]:40123"
            .parse()
            .expect("Exit address");
        let manager = KernelMptcpPathManager::new().expect("kernel MPTCP path manager");
        manager
            .prepare_context(
                "live_two_subflows",
                MptcpLimits {
                    accepted_addrs: 4,
                    subflows: 4,
                },
            )
            .await
            .expect("prepare kernel path manager");
        eprintln!("client: path manager prepared");
        for (id, address, interface) in [(
            2,
            "fd76:6f6c:7061:1111:2222:2:3333:1"
                .parse()
                .expect("Client path two"),
            "c2",
        )] {
            let if_index = fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
                .expect("path ifindex")
                .trim()
                .parse()
                .expect("numeric ifindex");
            manager
                .add_path(
                    "live_two_subflows",
                    MptcpEndpoint {
                        id,
                        address,
                        if_index,
                        flags: EndpointFlags::SUBFLOW,
                        listener_port: None,
                    },
                )
                .await
                .expect("register selected MPTCP subflow path");
            eprintln!("client: registered path {id}");
        }
        let c1_before = interface_counter("c1", "tx_bytes");
        let c2_before = interface_counter("c2", "tx_bytes");
        let mut stream = connect(remote, Some(client_one), Duration::from_secs(5))
            .await
            .expect("connect genuine MPTCP");
        eprintln!("client: MPTCP connected");
        stream
            .as_tcp_stream_mut()
            .write_all(&vec![0x51; 1024 * 1024])
            .await
            .expect("initial path payload");
        let mut acknowledgement = [0_u8; 1];
        stream
            .as_tcp_stream_mut()
            .read_exact(&mut acknowledgement)
            .await
            .expect("initial acknowledgement");
        assert_eq!(acknowledgement, [1]);
        let c1_after_initial = interface_counter("c1", "tx_bytes");
        assert!(
            c1_after_initial.saturating_sub(c1_before) > 512 * 1024,
            "initial subflow carried no application-scale data"
        );
        let evidence = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let info = stream.require_negotiated().expect("genuine MPTCP");
                if info.total_subflows >= 2 {
                    break info;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("second MPTCP subflow");
        assert!(evidence.total_subflows >= 2 && !evidence.fallback);
        eprintln!("client: {} subflows active", evidence.total_subflows);

        stream
            .as_tcp_stream_mut()
            .write_all(&vec![0xa2; 64 * 1024 * 1024])
            .await
            .expect("second path payload");
        stream
            .as_tcp_stream_mut()
            .read_exact(&mut acknowledgement)
            .await
            .expect("second acknowledgement");
        assert_eq!(acknowledgement, [2]);
        let c2_after = interface_counter("c2", "tx_bytes");
        assert!(
            c2_after.saturating_sub(c2_before) > 1024 * 1024,
            "second subflow carried no application-scale data"
        );
        let final_info = stream
            .require_negotiated()
            .expect("MPTCP remained negotiated");
        assert!(final_info.bytes_sent >= 65 * 1024 * 1024);
        manager
            .cleanup_context("live_two_subflows")
            .await
            .expect("MPTCP endpoint cleanup");
    }

    fn interface_counter(interface: &str, counter: &str) -> u64 {
        fs::read_to_string(format!("/sys/class/net/{interface}/statistics/{counter}"))
            .expect("interface counter")
            .trim()
            .parse()
            .expect("numeric interface counter")
    }

    #[derive(Default)]
    struct FakeKernelState {
        limit_calls: usize,
        fail_limits: usize,
        limits: Vec<MptcpLimits>,
        active: HashMap<u8, MptcpEndpoint>,
        fail_adds: usize,
        fail_deletes: usize,
    }

    #[derive(Default)]
    struct AddGate {
        state: std::sync::Mutex<(bool, bool)>,
        changed: std::sync::Condvar,
    }

    impl AddGate {
        fn block_add(&self) {
            let mut state = self.state.lock().expect("gate");
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self.changed.wait(state).expect("gate wait");
            }
        }

        fn wait_started(&self) {
            let mut state = self.state.lock().expect("gate");
            while !state.0 {
                state = self.changed.wait(state).expect("gate wait");
            }
        }

        fn release(&self) {
            let mut state = self.state.lock().expect("gate");
            state.1 = true;
            self.changed.notify_all();
        }
    }

    #[derive(Default)]
    struct FakeKernel {
        state: std::sync::Mutex<FakeKernelState>,
        add_gate: Option<Arc<AddGate>>,
        after_add: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl FakeKernel {
        fn with_gate(gate: Arc<AddGate>) -> Self {
            Self {
                add_gate: Some(gate),
                ..Self::default()
            }
        }

        fn fail_next_limit(&self) {
            self.state.lock().expect("state").fail_limits += 1;
        }

        fn fail_next_add(&self) {
            self.state.lock().expect("state").fail_adds += 1;
        }

        fn fail_next_delete(&self) {
            self.state.lock().expect("state").fail_deletes += 1;
        }

        fn set_after_add(&self, hook: impl FnOnce() + Send + 'static) {
            *self.after_add.lock().expect("hook") = Some(Box::new(hook));
        }
    }

    impl MptcpKernelBackend for FakeKernel {
        fn set_limits(&self, limits: MptcpLimits) -> Result<(), MptcpError> {
            let mut state = self.state.lock().expect("state");
            state.limit_calls += 1;
            if state.fail_limits > 0 {
                state.fail_limits -= 1;
                return Err(MptcpError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
            }
            state.limits.push(limits);
            Ok(())
        }

        fn add_endpoint(&self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
            if let Some(gate) = self.add_gate.as_ref() {
                gate.block_add();
            }
            {
                let mut state = self.state.lock().expect("state");
                if state.fail_adds > 0 {
                    state.fail_adds -= 1;
                    return Err(MptcpError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
                }
                if state.active.insert(endpoint.id, endpoint.clone()).is_some() {
                    return Err(MptcpError::Io(std::io::Error::from_raw_os_error(
                        libc::EEXIST,
                    )));
                }
            }
            if let Some(hook) = self.after_add.lock().expect("hook").take() {
                hook();
            }
            Ok(())
        }

        fn delete_endpoint(&self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
            let mut state = self.state.lock().expect("state");
            if state.fail_deletes > 0 {
                state.fail_deletes -= 1;
                return Err(MptcpError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
            }
            if state.active.get(&endpoint.id) == Some(endpoint) {
                state.active.remove(&endpoint.id);
            }
            Ok(())
        }
    }

    fn limits() -> MptcpLimits {
        MptcpLimits {
            accepted_addrs: 2,
            subflows: 4,
        }
    }

    trait EndpointTestExt {
        fn with_flags(self, flags: EndpointFlags) -> Self;
    }

    impl EndpointTestExt for MptcpEndpoint {
        fn with_flags(mut self, flags: EndpointFlags) -> Self {
            self.flags = flags;
            self
        }
    }

    fn selected_endpoint(id: u8) -> MptcpEndpoint {
        MptcpEndpoint {
            id,
            address: overlay_address(id, 1),
            if_index: u32::from(id) + 20,
            flags: EndpointFlags::SUBFLOW,
            listener_port: None,
        }
    }

    fn namespace_key(inode: u64) -> NetworkNamespaceKey {
        NetworkNamespaceKey { device: 7, inode }
    }

    fn manager_in_registry(
        kernel: Arc<dyn MptcpKernelBackend>,
        namespace: NetworkNamespaceKey,
        registry: &NamespaceContextRegistry,
    ) -> KernelMptcpPathManager {
        KernelMptcpPathManager::for_namespace(
            kernel,
            namespace,
            registry,
            MAX_TRACKED_NETWORK_NAMESPACES,
        )
        .expect("test namespace")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_network_namespace_identity_is_stable_and_nonzero() {
        assert_eq!(CURRENT_NETWORK_NAMESPACE_PATH, "/proc/thread-self/ns/net");
        let first = current_network_namespace_key().expect("network namespace");
        let second = current_network_namespace_key().expect("network namespace");
        assert_eq!(first, second);
        assert_ne!(first.inode, 0);
    }

    #[test]
    fn synchronous_backend_needs_no_runtime_and_preserves_exact_cleanup_ownership() {
        let kernel = Arc::new(FakeKernel::default());
        let manager = SynchronousKernelMptcpPathManager::with_kernel(kernel.clone());
        manager
            .prepare_context("worker-route", limits())
            .expect("prepare synchronously");

        let first = selected_endpoint(1);
        manager
            .add_path("worker-route", first.clone())
            .expect("add synchronously");
        manager
            .remove_path("worker-route", first.id)
            .expect("remove synchronously");

        let retained = selected_endpoint(2);
        kernel.fail_next_add();
        kernel.fail_next_delete();
        assert!(matches!(
            manager.add_path("worker-route", retained.clone()),
            Err(MptcpError::CleanupIncomplete(_))
        ));
        assert_eq!(
            kernel.state.lock().expect("state").active.get(&retained.id),
            None
        );
        assert!(matches!(
            manager
                .backend
                .contexts
                .blocking_lock()
                .get("worker-route"),
            Some(ManagedContext::Active(endpoints))
                if matches!(endpoints.get(&retained.id), Some(ManagedEndpoint::CleanupRequired(endpoint)) if endpoint == &retained)
        ));

        manager
            .cleanup_context("worker-route")
            .expect("retry retained cleanup synchronously");
        assert!(manager.backend.contexts.blocking_lock().is_empty());
        assert!(kernel.state.lock().expect("state").active.is_empty());
    }

    #[tokio::test]
    async fn duplicate_prepare_never_mutates_kernel_limits() {
        let kernel = Arc::new(FakeKernel::default());
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        manager
            .prepare_context("route-1", limits())
            .await
            .expect("prepare");
        assert!(manager.prepare_context("route-1", limits()).await.is_err());
        assert_eq!(kernel.state.lock().expect("state").limits, vec![limits()]);
    }

    #[tokio::test]
    async fn concurrent_contexts_cannot_overwrite_namespace_global_limits() {
        let kernel = Arc::new(FakeKernel::default());
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        let alternate = MptcpLimits {
            accepted_addrs: 7,
            subflows: 8,
        };
        let first = manager.clone();
        let second = manager.clone();
        let (first_result, second_result) = tokio::join!(
            first.prepare_context("route-first", limits()),
            second.prepare_context("route-second", alternate),
        );
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        {
            let state = kernel.state.lock().expect("state");
            assert_eq!(state.limit_calls, 1);
            assert_eq!(state.limits.len(), 1);
        }
        assert_eq!(manager.contexts.lock().await.len(), 1);

        let owner = if first_result.is_ok() {
            "route-first"
        } else {
            "route-second"
        };
        assert!(
            manager
                .prepare_context("route-third", limits())
                .await
                .is_err()
        );
        assert_eq!(kernel.state.lock().expect("state").limit_calls, 1);
        manager.cleanup_context(owner).await.expect("release owner");
        manager
            .prepare_context("route-after-cleanup", alternate)
            .await
            .expect("reuse backend after complete cleanup");
        assert_eq!(kernel.state.lock().expect("state").limit_calls, 2);
    }

    #[tokio::test]
    async fn independent_managers_in_one_namespace_cannot_overwrite_global_limits() {
        let registry = NamespaceContextRegistry::default();
        let first_kernel = Arc::new(FakeKernel::default());
        let second_kernel = Arc::new(FakeKernel::default());
        let first = manager_in_registry(first_kernel.clone(), namespace_key(10), &registry);
        let second = manager_in_registry(second_kernel.clone(), namespace_key(10), &registry);
        assert!(Arc::ptr_eq(&first.contexts, &second.contexts));

        let alternate = MptcpLimits {
            accepted_addrs: 7,
            subflows: 8,
        };
        let (first_result, second_result) = tokio::join!(
            first.prepare_context("route-first-instance", limits()),
            second.prepare_context("route-second-instance", alternate),
        );
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        assert_eq!(
            first_kernel.state.lock().expect("first state").limit_calls
                + second_kernel
                    .state
                    .lock()
                    .expect("second state")
                    .limit_calls,
            1
        );
        assert_eq!(first.contexts.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn different_namespace_keys_can_prepare_in_parallel() {
        let registry = NamespaceContextRegistry::default();
        let first_kernel = Arc::new(FakeKernel::default());
        let second_kernel = Arc::new(FakeKernel::default());
        let first = manager_in_registry(first_kernel.clone(), namespace_key(11), &registry);
        let second = manager_in_registry(second_kernel.clone(), namespace_key(12), &registry);

        let (first_result, second_result) = tokio::join!(
            first.prepare_context("route-one", limits()),
            second.prepare_context("route-two", limits()),
        );
        first_result.expect("first namespace");
        second_result.expect("second namespace");
        assert_eq!(
            first_kernel.state.lock().expect("first state").limit_calls,
            1
        );
        assert_eq!(
            second_kernel
                .state
                .lock()
                .expect("second state")
                .limit_calls,
            1
        );
        assert!(!Arc::ptr_eq(&first.contexts, &second.contexts));
    }

    #[tokio::test]
    async fn failed_limit_mutation_releases_shared_namespace_for_independent_retry() {
        let registry = NamespaceContextRegistry::default();
        let failing_kernel = Arc::new(FakeKernel::default());
        failing_kernel.fail_next_limit();
        let retry_kernel = Arc::new(FakeKernel::default());
        let failing = manager_in_registry(failing_kernel.clone(), namespace_key(13), &registry);
        let retry = manager_in_registry(retry_kernel.clone(), namespace_key(13), &registry);

        assert!(
            failing
                .prepare_context("route-failing-instance", limits())
                .await
                .is_err()
        );
        assert!(failing.contexts.lock().await.is_empty());
        retry
            .prepare_context("route-retry-instance", limits())
            .await
            .expect("independent retry");
        assert_eq!(
            failing_kernel
                .state
                .lock()
                .expect("failing state")
                .limit_calls,
            1
        );
        assert_eq!(
            retry_kernel.state.lock().expect("retry state").limit_calls,
            1
        );
    }

    #[test]
    fn namespace_registry_key_count_is_bounded_and_existing_keys_remain_available() {
        let registry = NamespaceContextRegistry::default();
        let first = contexts_for_namespace(&registry, namespace_key(20), 2).expect("first key");
        contexts_for_namespace(&registry, namespace_key(21), 2).expect("second key");
        assert!(contexts_for_namespace(&registry, namespace_key(22), 2).is_err());
        let existing =
            contexts_for_namespace(&registry, namespace_key(20), 2).expect("existing key");
        assert!(Arc::ptr_eq(&first, &existing));
        assert_eq!(registry.lock().expect("registry").len(), 2);
    }

    #[tokio::test]
    async fn failed_limit_mutation_releases_reservation_for_exact_retry() {
        let kernel = Arc::new(FakeKernel::default());
        kernel.fail_next_limit();
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        assert!(
            manager
                .prepare_context("route-retry", limits())
                .await
                .is_err()
        );
        assert!(manager.contexts.lock().await.is_empty());
        manager
            .prepare_context("route-retry", limits())
            .await
            .expect("retry");
        let state = kernel.state.lock().expect("state");
        assert_eq!(state.limit_calls, 2);
        assert_eq!(state.limits, vec![limits()]);
    }

    #[tokio::test]
    async fn first_add_failure_rolls_back_reservation_and_retry_succeeds() {
        let kernel = Arc::new(FakeKernel::default());
        kernel.fail_next_add();
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        manager
            .prepare_context("route-2", limits())
            .await
            .expect("prepare");
        let endpoint = selected_endpoint(1);
        assert!(manager.add_path("route-2", endpoint.clone()).await.is_err());
        assert!(kernel.state.lock().expect("state").active.is_empty());
        manager
            .add_path("route-2", endpoint.clone())
            .await
            .expect("retry add");
        manager
            .add_path("route-2", endpoint)
            .await
            .expect("idempotent add");
        assert_eq!(kernel.state.lock().expect("state").active.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_cleanup_cannot_remove_context_while_add_is_reserved() {
        let gate = Arc::new(AddGate::default());
        let kernel = Arc::new(FakeKernel::with_gate(gate.clone()));
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        manager
            .prepare_context("route-3", limits())
            .await
            .expect("prepare");
        let adding = manager.clone();
        let add_task =
            tokio::spawn(async move { adding.add_path("route-3", selected_endpoint(2)).await });
        gate.wait_started();
        assert!(manager.cleanup_context("route-3").await.is_err());
        assert!(manager.contexts.lock().await.contains_key("route-3"));
        gate.release();
        add_task.await.expect("join").expect("add");
        manager.cleanup_context("route-3").await.expect("cleanup");
        assert!(!manager.contexts.lock().await.contains_key("route-3"));
        assert!(kernel.state.lock().expect("state").active.is_empty());
    }

    #[tokio::test]
    async fn commit_failure_performs_exact_kernel_rollback() {
        let kernel = Arc::new(FakeKernel::default());
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        manager
            .prepare_context("route-4", limits())
            .await
            .expect("prepare");
        let contexts = Arc::clone(&manager.contexts);
        kernel.set_after_add(move || {
            contexts.blocking_lock().remove("route-4");
        });
        assert!(
            manager
                .add_path("route-4", selected_endpoint(3))
                .await
                .is_err()
        );
        assert!(kernel.state.lock().expect("state").active.is_empty());
    }

    #[tokio::test]
    async fn failed_cleanup_retains_state_and_global_retry_cannot_false_green() {
        let kernel = Arc::new(FakeKernel::default());
        let manager = KernelMptcpPathManager::with_kernel(kernel.clone());
        manager
            .prepare_context("route-5", limits())
            .await
            .expect("prepare");
        manager
            .add_path("route-5", selected_endpoint(4))
            .await
            .expect("add");
        kernel.fail_next_delete();
        assert!(manager.cleanup_context("route-5").await.is_err());
        assert!(matches!(
            manager.contexts.lock().await.get("route-5"),
            Some(ManagedContext::Cleaning(remaining)) if remaining.len() == 1
        ));
        assert_eq!(kernel.state.lock().expect("state").active.len(), 1);
        manager
            .cleanup_context("route-5")
            .await
            .expect("retry cleanup");
        assert!(!manager.contexts.lock().await.contains_key("route-5"));
        assert!(kernel.state.lock().expect("state").active.is_empty());
    }
}
