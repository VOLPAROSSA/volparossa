//! Bounded namespace-local MPTCP endpoint derivation and ownership transactions.

use std::collections::BTreeMap;

use thiserror::Error;
use volparossa_mptcp::{EndpointFlags, MAX_PATHS, MptcpEndpoint, MptcpError, MptcpNetlinkClient};
use volparossa_routing::{
    AddMptcpEndpoint, ContextRole, MptcpEndpointMode, RemoveMptcpEndpoint, WireguardRole,
};

use crate::lease_spec::WireguardLeaseSpec;

/// Stable failures for derived endpoint operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum MptcpEndpointError {
    /// Request context, role, path, mode, or derived endpoint was invalid.
    #[error("invalid MPTCP endpoint topology")]
    Invalid,
    /// The selected `WireGuard` path is not configured in this worker.
    #[error("selected WireGuard path is absent")]
    MissingLink,
    /// The endpoint ID has a different or pending owner.
    #[error("MPTCP endpoint ownership conflict")]
    Conflict,
    /// The kernel rejected an operation without retained ownership ambiguity.
    #[error("kernel MPTCP endpoint operation failed")]
    Kernel,
    /// Exact rollback or cleanup must be retried.
    #[error("MPTCP endpoint cleanup is incomplete")]
    CleanupIncomplete,
}

/// Successful idempotent mutation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MptcpEndpointMutation {
    /// The endpoint was added now.
    Added,
    /// The exact endpoint was already active.
    Present,
    /// The exact owned endpoint was removed now.
    Removed,
    /// No endpoint was owned for that path.
    Absent,
}

/// Secret-free path identity derived from a committed helper-v3 endpoint lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DerivedMptcpPath {
    specification: WireguardLeaseSpec,
    flags: EndpointFlags,
}

impl DerivedMptcpPath {
    /// Returns the prior validated, secret-free `WireGuard` specification.
    pub(crate) fn specification(&self) -> &WireguardLeaseSpec {
        &self.specification
    }

    /// Binds the derived path to the namespace-local index resolved by the helper.
    pub(crate) fn bind(self, if_index: u32) -> Result<MptcpEndpoint, MptcpEndpointError> {
        let endpoint = MptcpEndpoint {
            id: self.specification.key().0,
            address: self.specification.local_address().into(),
            if_index,
            flags: self.flags,
        };
        endpoint
            .validate()
            .map_err(|_| MptcpEndpointError::Invalid)?;
        Ok(endpoint)
    }
}

/// Derives an add target without accepting an address, interface, ifindex, or endpoint ID.
pub(crate) fn derive_add_path(
    route_context_id: [u8; 16],
    context_role: ContextRole,
    request: &AddMptcpEndpoint,
    configured_links: &std::collections::HashMap<(u8, i32), WireguardLeaseSpec>,
) -> Result<DerivedMptcpPath, MptcpEndpointError> {
    let (path_id, role, specification) = configured_path(
        route_context_id,
        context_role,
        &request.route_context_id,
        request.path_id,
        configured_links,
    )?;
    let mode =
        MptcpEndpointMode::try_from(request.mode).map_err(|_| MptcpEndpointError::Invalid)?;
    let mut flags = match mode {
        MptcpEndpointMode::Unspecified => return Err(MptcpEndpointError::Invalid),
        MptcpEndpointMode::Signal => EndpointFlags::SIGNAL,
        MptcpEndpointMode::Subflow => EndpointFlags::SUBFLOW,
        MptcpEndpointMode::SignalAndSubflow => EndpointFlags::SIGNAL | EndpointFlags::SUBFLOW,
    };
    if request.backup {
        flags.insert(EndpointFlags::BACKUP);
    }
    if specification.key() != (path_id, role) {
        return Err(MptcpEndpointError::Invalid);
    }
    Ok(DerivedMptcpPath {
        specification: specification.clone(),
        flags,
    })
}

/// Validates removal against an existing configured client/exit path.
pub(crate) fn derive_remove_id(
    route_context_id: [u8; 16],
    context_role: ContextRole,
    request: &RemoveMptcpEndpoint,
    configured_links: &std::collections::HashMap<(u8, i32), WireguardLeaseSpec>,
) -> Result<u8, MptcpEndpointError> {
    configured_path(
        route_context_id,
        context_role,
        &request.route_context_id,
        request.path_id,
        configured_links,
    )
    .map(|(path_id, _, _)| path_id)
}

fn configured_path<'a>(
    route_context_id: [u8; 16],
    context_role: ContextRole,
    request_context_id: &[u8],
    requested_path_id: u32,
    configured_links: &'a std::collections::HashMap<(u8, i32), WireguardLeaseSpec>,
) -> Result<(u8, i32, &'a WireguardLeaseSpec), MptcpEndpointError> {
    if request_context_id != route_context_id {
        return Err(MptcpEndpointError::Invalid);
    }
    let path_id = u8::try_from(requested_path_id).map_err(|_| MptcpEndpointError::Invalid)?;
    if path_id == 0 || path_id > MAX_PATHS {
        return Err(MptcpEndpointError::Invalid);
    }
    let role = match context_role {
        ContextRole::Unspecified | ContextRole::Relay => {
            return Err(MptcpEndpointError::Invalid);
        }
        ContextRole::Client => WireguardRole::Client as i32,
        ContextRole::Exit => WireguardRole::Exit as i32,
    };
    let specification = configured_links
        .get(&(path_id, role))
        .ok_or(MptcpEndpointError::MissingLink)?;
    Ok((path_id, role, specification))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OwnedEndpointState {
    Adding(MptcpEndpoint),
    Active(MptcpEndpoint),
    Removing(MptcpEndpoint),
    CleanupRequired(MptcpEndpoint),
}

impl OwnedEndpointState {
    const fn endpoint(&self) -> &MptcpEndpoint {
        match self {
            Self::Adding(endpoint)
            | Self::Active(endpoint)
            | Self::Removing(endpoint)
            | Self::CleanupRequired(endpoint) => endpoint,
        }
    }
}

enum AddPlan {
    Present,
    Reserved,
}

enum RemovePlan {
    Absent,
    Reserved(MptcpEndpoint),
}

/// At most eight exactly owned namespace-local endpoints.
#[derive(Debug, Default)]
pub(crate) struct MptcpEndpointRegistry {
    endpoints: BTreeMap<u8, OwnedEndpointState>,
}

impl MptcpEndpointRegistry {
    fn reserve_add(&mut self, endpoint: &MptcpEndpoint) -> Result<AddPlan, MptcpEndpointError> {
        endpoint
            .validate()
            .map_err(|_| MptcpEndpointError::Invalid)?;
        if let Some(current) = self.endpoints.get(&endpoint.id) {
            return if matches!(current, OwnedEndpointState::Active(_))
                && current.endpoint() == endpoint
            {
                Ok(AddPlan::Present)
            } else {
                Err(MptcpEndpointError::Conflict)
            };
        }
        if self.endpoints.len() >= usize::from(MAX_PATHS) {
            return Err(MptcpEndpointError::Conflict);
        }
        self.endpoints
            .insert(endpoint.id, OwnedEndpointState::Adding(endpoint.clone()));
        Ok(AddPlan::Reserved)
    }

    fn commit_add(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpEndpointError> {
        if !matches!(self.endpoints.get(&endpoint.id), Some(OwnedEndpointState::Adding(current)) if current == endpoint)
        {
            return Err(MptcpEndpointError::CleanupIncomplete);
        }
        self.endpoints
            .insert(endpoint.id, OwnedEndpointState::Active(endpoint.clone()));
        Ok(())
    }

    fn finish_failed_add(&mut self, endpoint: &MptcpEndpoint, kernel_absent: bool) {
        if !matches!(self.endpoints.get(&endpoint.id), Some(OwnedEndpointState::Adding(current)) if current == endpoint)
        {
            return;
        }
        if kernel_absent {
            self.endpoints.remove(&endpoint.id);
        } else {
            self.endpoints.insert(
                endpoint.id,
                OwnedEndpointState::CleanupRequired(endpoint.clone()),
            );
        }
    }

    fn reserve_remove(&mut self, endpoint_id: u8) -> Result<RemovePlan, MptcpEndpointError> {
        let Some(current) = self.endpoints.get(&endpoint_id).cloned() else {
            return Ok(RemovePlan::Absent);
        };
        let endpoint = match current {
            OwnedEndpointState::Active(endpoint)
            | OwnedEndpointState::CleanupRequired(endpoint) => endpoint,
            OwnedEndpointState::Adding(_) | OwnedEndpointState::Removing(_) => {
                return Err(MptcpEndpointError::Conflict);
            }
        };
        self.endpoints
            .insert(endpoint_id, OwnedEndpointState::Removing(endpoint.clone()));
        Ok(RemovePlan::Reserved(endpoint))
    }

    fn finish_remove(&mut self, endpoint: &MptcpEndpoint, kernel_absent: bool) {
        if !matches!(self.endpoints.get(&endpoint.id), Some(OwnedEndpointState::Removing(current)) if current == endpoint)
        {
            return;
        }
        if kernel_absent {
            self.endpoints.remove(&endpoint.id);
        } else {
            self.endpoints.insert(
                endpoint.id,
                OwnedEndpointState::CleanupRequired(endpoint.clone()),
            );
        }
    }

    fn cleanup_snapshot(&self) -> Result<Vec<MptcpEndpoint>, MptcpEndpointError> {
        if self.endpoints.values().any(|state| {
            matches!(
                state,
                OwnedEndpointState::Adding(_) | OwnedEndpointState::Removing(_)
            )
        }) {
            return Err(MptcpEndpointError::CleanupIncomplete);
        }
        Ok(self
            .endpoints
            .values()
            .map(|state| state.endpoint().clone())
            .collect())
    }

    fn release_cleaned(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpEndpointError> {
        if self
            .endpoints
            .get(&endpoint.id)
            .map(OwnedEndpointState::endpoint)
            != Some(endpoint)
        {
            return Err(MptcpEndpointError::CleanupIncomplete);
        }
        self.endpoints.remove(&endpoint.id);
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Whether this path ID still has exact owned or pending state.
    pub(crate) fn contains(&self, endpoint_id: u8) -> bool {
        self.endpoints.contains_key(&endpoint_id)
    }
}

pub(crate) trait MptcpEndpointKernel {
    fn add(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError>;

    fn delete(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError>;
}

impl MptcpEndpointKernel for MptcpNetlinkClient {
    fn add(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
        self.add_endpoint(endpoint)
    }

    fn delete(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
        match self.delete_endpoint(endpoint) {
            Ok(()) => Ok(()),
            Err(MptcpError::Io(error))
                if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn add_owned_endpoint<K: MptcpEndpointKernel>(
    registry: &mut MptcpEndpointRegistry,
    kernel: &mut K,
    endpoint: &MptcpEndpoint,
) -> Result<MptcpEndpointMutation, MptcpEndpointError> {
    match registry.reserve_add(endpoint)? {
        AddPlan::Present => return Ok(MptcpEndpointMutation::Present),
        AddPlan::Reserved => {}
    }
    match kernel.add(endpoint) {
        Ok(()) => {
            if registry.commit_add(endpoint).is_ok() {
                Ok(MptcpEndpointMutation::Added)
            } else {
                let rolled_back = kernel.delete(endpoint).is_ok();
                registry.finish_failed_add(endpoint, rolled_back);
                Err(if rolled_back {
                    MptcpEndpointError::Kernel
                } else {
                    MptcpEndpointError::CleanupIncomplete
                })
            }
        }
        Err(MptcpError::Io(error)) if error.raw_os_error() == Some(libc::EEXIST) => {
            registry.finish_failed_add(endpoint, true);
            Err(MptcpEndpointError::Conflict)
        }
        Err(_) => {
            let rolled_back = kernel.delete(endpoint).is_ok();
            registry.finish_failed_add(endpoint, rolled_back);
            Err(if rolled_back {
                MptcpEndpointError::Kernel
            } else {
                MptcpEndpointError::CleanupIncomplete
            })
        }
    }
}

pub(crate) fn remove_owned_endpoint<K: MptcpEndpointKernel>(
    registry: &mut MptcpEndpointRegistry,
    kernel: &mut K,
    endpoint_id: u8,
) -> Result<MptcpEndpointMutation, MptcpEndpointError> {
    let RemovePlan::Reserved(endpoint) = registry.reserve_remove(endpoint_id)? else {
        return Ok(MptcpEndpointMutation::Absent);
    };
    let removed = kernel.delete(&endpoint).is_ok();
    registry.finish_remove(&endpoint, removed);
    if removed {
        Ok(MptcpEndpointMutation::Removed)
    } else {
        Err(MptcpEndpointError::CleanupIncomplete)
    }
}

pub(crate) fn cleanup_owned_endpoints<K: MptcpEndpointKernel>(
    registry: &mut MptcpEndpointRegistry,
    kernel: &mut K,
) -> Result<(), MptcpEndpointError> {
    for endpoint in registry.cleanup_snapshot()? {
        if kernel.delete(&endpoint).is_err() {
            return Err(MptcpEndpointError::CleanupIncomplete);
        }
        registry.release_cleaned(&endpoint)?;
    }
    if registry.is_empty() {
        Ok(())
    } else {
        Err(MptcpEndpointError::CleanupIncomplete)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use volparossa_wireguard::overlay_prefix;

    use super::*;

    #[derive(Default)]
    struct FakeKernel {
        active: BTreeMap<u8, MptcpEndpoint>,
        fail_adds: usize,
        fail_deletes: usize,
        add_calls: usize,
        delete_calls: usize,
    }

    impl MptcpEndpointKernel for FakeKernel {
        fn add(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
            self.add_calls += 1;
            if self.fail_adds > 0 {
                self.fail_adds -= 1;
                return Err(MptcpError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
            }
            if self.active.insert(endpoint.id, endpoint.clone()).is_some() {
                return Err(MptcpError::Io(std::io::Error::from_raw_os_error(
                    libc::EEXIST,
                )));
            }
            Ok(())
        }

        fn delete(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
            self.delete_calls += 1;
            if self.fail_deletes > 0 {
                self.fail_deletes -= 1;
                return Err(MptcpError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
            }
            if self.active.get(&endpoint.id) == Some(endpoint) {
                self.active.remove(&endpoint.id);
            }
            Ok(())
        }
    }

    fn endpoint(id: u8, flags: EndpointFlags) -> MptcpEndpoint {
        let mut address = overlay_prefix([id; 16], id)
            .expect("overlay")
            .network()
            .octets();
        address[15] = 1;
        MptcpEndpoint {
            id,
            address: std::net::Ipv6Addr::from(address).into(),
            if_index: u32::from(id) + 10,
            flags,
        }
    }

    fn configured_client_link(route: [u8; 16]) -> HashMap<(u8, i32), WireguardLeaseSpec> {
        let specification =
            WireguardLeaseSpec::derive(route, ContextRole::Client, 1, WireguardRole::Client as i32)
                .expect("specification");
        HashMap::from([(specification.key(), specification)])
    }

    #[test]
    fn derivation_uses_only_authorised_client_or_exit_wireguard_state() {
        let route = [7; 16];
        let links = configured_client_link(route);
        let request = AddMptcpEndpoint {
            route_context_id: route.to_vec(),
            context_handle: vec![1; 32],
            path_id: 1,
            mode: MptcpEndpointMode::SignalAndSubflow as i32,
            backup: true,
        };
        let derived =
            derive_add_path(route, ContextRole::Client, &request, &links).expect("derived path");
        assert_eq!(
            derived.specification(),
            links.values().next().expect("link")
        );
        let endpoint = derived.bind(42).expect("bound endpoint");
        assert_eq!(endpoint.id, 1);
        assert_eq!(endpoint.if_index, 42);
        assert_eq!(
            endpoint.address,
            links.values().next().expect("link").local_address()
        );
        assert!(endpoint.flags.contains(EndpointFlags::SIGNAL));
        assert!(endpoint.flags.contains(EndpointFlags::SUBFLOW));
        assert!(endpoint.flags.contains(EndpointFlags::BACKUP));
        assert!(!endpoint.flags.contains(EndpointFlags::FULLMESH));

        assert_eq!(
            derive_add_path(route, ContextRole::Relay, &request, &links),
            Err(MptcpEndpointError::Invalid)
        );
        let mut wrong_context = request;
        wrong_context.route_context_id = vec![8; 16];
        assert_eq!(
            derive_add_path(route, ContextRole::Client, &wrong_context, &links),
            Err(MptcpEndpointError::Invalid)
        );
        assert_eq!(
            derive_remove_id(
                route,
                ContextRole::Client,
                &RemoveMptcpEndpoint {
                    route_context_id: route.to_vec(),
                    context_handle: vec![1; 32],
                    path_id: 2,
                },
                &links,
            ),
            Err(MptcpEndpointError::MissingLink)
        );
    }

    #[test]
    fn failed_add_rolls_back_then_retry_and_idempotence_are_exact() {
        let selected = endpoint(1, EndpointFlags::SUBFLOW);
        let mut registry = MptcpEndpointRegistry::default();
        let mut kernel = FakeKernel {
            fail_adds: 1,
            ..FakeKernel::default()
        };

        assert_eq!(
            add_owned_endpoint(&mut registry, &mut kernel, &selected),
            Err(MptcpEndpointError::Kernel)
        );
        assert!(registry.is_empty());
        assert!(kernel.active.is_empty());
        assert_eq!(kernel.delete_calls, 1);

        assert_eq!(
            add_owned_endpoint(&mut registry, &mut kernel, &selected),
            Ok(MptcpEndpointMutation::Added)
        );
        assert_eq!(
            add_owned_endpoint(&mut registry, &mut kernel, &selected),
            Ok(MptcpEndpointMutation::Present)
        );
        assert_eq!(kernel.add_calls, 2);

        let conflicting = endpoint(1, EndpointFlags::SIGNAL);
        assert_eq!(
            add_owned_endpoint(&mut registry, &mut kernel, &conflicting),
            Err(MptcpEndpointError::Conflict)
        );
        assert_eq!(kernel.active.get(&1), Some(&selected));

        assert_eq!(
            remove_owned_endpoint(&mut registry, &mut kernel, 1),
            Ok(MptcpEndpointMutation::Removed)
        );
        assert_eq!(
            remove_owned_endpoint(&mut registry, &mut kernel, 1),
            Ok(MptcpEndpointMutation::Absent)
        );
        assert!(registry.is_empty());
        assert!(kernel.active.is_empty());
    }

    #[test]
    fn cleanup_failure_retains_exact_ownership_for_global_retry() {
        let mut registry = MptcpEndpointRegistry::default();
        let mut kernel = FakeKernel::default();
        for id in 1..=2 {
            add_owned_endpoint(
                &mut registry,
                &mut kernel,
                &endpoint(id, EndpointFlags::SUBFLOW),
            )
            .expect("add");
        }
        kernel.fail_deletes = 1;
        assert_eq!(
            cleanup_owned_endpoints(&mut registry, &mut kernel),
            Err(MptcpEndpointError::CleanupIncomplete)
        );
        assert!(!registry.is_empty());
        assert_eq!(kernel.active.len(), 2);

        cleanup_owned_endpoints(&mut registry, &mut kernel).expect("retry cleanup");
        assert!(registry.is_empty());
        assert!(kernel.active.is_empty());
    }

    #[test]
    fn state_commit_failure_is_followed_by_exact_kernel_rollback() {
        let selected = endpoint(3, EndpointFlags::SUBFLOW);
        let mut registry = MptcpEndpointRegistry::default();
        let mut kernel = FakeKernel::default();
        assert!(matches!(
            registry.reserve_add(&selected),
            Ok(AddPlan::Reserved)
        ));
        kernel.add(&selected).expect("kernel add");
        registry.endpoints.clear();
        assert_eq!(
            registry.commit_add(&selected),
            Err(MptcpEndpointError::CleanupIncomplete)
        );
        kernel.delete(&selected).expect("exact rollback");
        assert!(kernel.active.is_empty());
    }
}
