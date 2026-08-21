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
pub use volparossa_linux_uapi::MptcpInfo;

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
    use super::*;

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
