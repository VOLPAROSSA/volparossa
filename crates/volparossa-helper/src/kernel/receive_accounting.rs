//! Count-only accounting on one pinned physical NETDEV ingress hook.
//!
//! TOTAL and managed UDP tuples use the same nft counter (`skb->len`) basis, never NIC
//! counters minus decrypted `WireGuard` counters. A tuple is helper-derived routing metadata,
//! not authentication of each received packet. Client-role downloads remain owner traffic.
//! No verdict, policing, redirect, interface wildcard or caller-provided nft program exists.
//! The exclusive socket-owned table is removed by Linux on socket loss; explicit removal
//! still verifies absence. Counters are not an atomic cross-rule snapshot: consumers must
//! reject counter regressions/inconsistent deltas and reset baselines when tuple sets change.

use std::{fs::File, net::SocketAddr, os::unix::fs::MetadataExt};

use volparossa_routing::WireguardRole;

use super::{HardDeadline, KernelError, LinkDetails, NETLINK_ROUTE, NetlinkClient};

mod netlink;
use netlink::{Nft, Rule};

/// Finite registration capacity, shared by all contexts on this receiving interface.
pub(crate) const MAX_RECEIVE_TUPLES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveAccountingConfig {
    pub(crate) runtime_id: [u8; 16],
    pub(crate) interface_name: String,
    pub(crate) ifindex: u32,
}

/// Exact activated socket endpoints, supplied only by the helper's lease authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveTuple {
    pub(crate) context_id: [u8; 16],
    pub(crate) path_id: u8,
    pub(crate) role: WireguardRole,
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
}

impl ReceiveTuple {
    fn validate(&self) -> Result<(), KernelError> {
        let valid_address = |address: SocketAddr| {
            address.port() != 0
                && !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && !address.ip().is_loopback()
                && match address {
                    SocketAddr::V4(value) => !value.ip().is_broadcast(),
                    SocketAddr::V6(value) => value.scope_id() == 0 && value.flowinfo() == 0,
                }
        };
        if self.context_id == [0; 16]
            || !(1..=8).contains(&self.path_id)
            || self.role == WireguardRole::Unspecified
            || self.local.is_ipv4() != self.remote.is_ipv4()
            || self.local.ip() == self.remote.ip()
            || !valid_address(self.local)
            || !valid_address(self.remote)
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    fn tag(&self) -> Vec<u8> {
        let mut tag = self.context_id.to_vec();
        tag.push(self.path_id);
        tag.push(self.role as u8);
        tag
    }

    fn key_matches(&self, context: [u8; 16], path: u8, role: WireguardRole) -> bool {
        self.context_id == context && self.path_id == path && self.role == role
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReceiveCounters {
    pub(crate) bytes: u64,
    pub(crate) packets: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveTupleCounters {
    pub(crate) tuple: ReceiveTuple,
    pub(crate) counters: ReceiveCounters,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveAccountingSnapshot {
    pub(crate) total: ReceiveCounters,
    pub(crate) tuples: Vec<ReceiveTupleCounters>,
}

pub(crate) struct InstallFailure {
    pub(crate) source: KernelError,
    pub(crate) cleanup: Option<Box<ReceiveAccountingOwner>>,
}

impl std::fmt::Debug for InstallFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallFailure")
            .field("source", &self.source)
            .field("cleanup_required", &self.cleanup.is_some())
            .finish()
    }
}

/// Affine namespace, link and socket-owned counter table. Never transported to a worker.
pub(crate) struct ReceiveAccountingOwner {
    config: ReceiveAccountingConfig,
    namespace: File,
    link: LinkDetails,
    nft: Option<Nft>,
    table: String,
    table_handle: Option<u64>,
    tuples: Vec<ReceiveTuple>,
    uncertain: bool,
    removed: bool,
}

pub(crate) fn install(
    config: ReceiveAccountingConfig,
    deadline: HardDeadline,
) -> Result<ReceiveAccountingOwner, InstallFailure> {
    let prepare = || -> Result<ReceiveAccountingOwner, KernelError> {
        if config.runtime_id == [0; 16]
            || config.ifindex <= 1
            || config.interface_name.is_empty()
            || config.interface_name.len() > 15
            || !config
                .interface_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(KernelError::Invalid);
        }
        let namespace = File::open("/proc/thread-self/ns/net")?;
        let link = NetlinkClient::connect(NETLINK_ROUTE, deadline)?
            .link_details_by_index(config.ifindex, deadline)?;
        if link.name.as_deref() != Some(config.interface_name.as_str())
            || link.flags & libc::IFF_LOOPBACK as u32 != 0
            || matches!(link.kind.as_deref(), Some("wireguard" | "tun" | "dummy"))
        {
            return Err(KernelError::Invalid);
        }
        let mut identity = config.runtime_id.to_vec();
        identity.extend(config.ifindex.to_be_bytes());
        let table = format!("vprx_{}", &blake3::hash(&identity).to_hex()[..24]);
        let mut nft = Nft::connect(deadline)?;
        if nft.table(&table, deadline)?.is_some() {
            return Err(KernelError::Invalid);
        }
        Ok(ReceiveAccountingOwner {
            config,
            namespace,
            link,
            nft: Some(nft),
            table,
            table_handle: None,
            tuples: Vec::new(),
            uncertain: false,
            removed: false,
        })
    };
    let mut owner = prepare().map_err(|source| InstallFailure {
        source,
        cleanup: None,
    })?;
    let result = owner
        .nft
        .as_mut()
        .ok_or(KernelError::Invalid)
        .and_then(|nft| nft.install(&owner.table, &owner.config, deadline))
        .and_then(|()| owner.inspect(deadline).map(|_| ()));
    match result {
        Ok(()) => Ok(owner),
        Err(source) => {
            owner.uncertain = true;
            Err(InstallFailure {
                source,
                cleanup: Some(Box::new(owner)),
            })
        }
    }
}

impl ReceiveAccountingOwner {
    pub(crate) fn config(&self) -> &ReceiveAccountingConfig {
        &self.config
    }

    fn check_namespace(&self) -> Result<(), KernelError> {
        let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
        let pinned = self.namespace.metadata()?;
        if current.dev() != pinned.dev() || current.ino() != pinned.ino() {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    fn check_link(&self, deadline: HardDeadline) -> Result<(), KernelError> {
        self.check_namespace()?;
        let current = NetlinkClient::connect(NETLINK_ROUTE, deadline)?
            .link_details_by_index(self.config.ifindex, deadline)?;
        if current.index != self.link.index
            || current.name != self.link.name
            || current.alias != self.link.alias
            || current.kind != self.link.kind
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    fn current_rules(&mut self, deadline: HardDeadline) -> Result<Vec<Rule>, KernelError> {
        if self.uncertain || self.removed {
            return Err(KernelError::Invalid);
        }
        self.check_link(deadline)?;
        let nft = self.nft.as_mut().ok_or(KernelError::Invalid)?;
        let handle = nft.verify_table(&self.table, &self.config, deadline)?;
        if self.table_handle.is_some_and(|expected| expected != handle) {
            return Err(KernelError::Invalid);
        }
        self.table_handle = Some(handle);
        nft.verify_chain(&self.table, &self.config.interface_name, deadline)?;
        let rules = nft.rules(&self.table, deadline)?;
        verify_rules(&rules, &self.tuples)?;
        Ok(rules)
    }

    pub(crate) fn register(
        &mut self,
        tuple: ReceiveTuple,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        tuple.validate()?;
        self.current_rules(deadline)?;
        if self.tuples.contains(&tuple) {
            return Ok(());
        }
        validate_new_tuple(&self.tuples, &tuple)?;
        self.uncertain = true;
        self.nft
            .as_mut()
            .ok_or(KernelError::Invalid)?
            .add_tuple(&self.table, &tuple, deadline)?;
        self.tuples.push(tuple);
        self.uncertain = false;
        self.inspect(deadline)?;
        Ok(())
    }

    pub(crate) fn unregister(
        &mut self,
        context: [u8; 16],
        path: u8,
        role: WireguardRole,
        deadline: HardDeadline,
    ) -> Result<bool, KernelError> {
        let rules = self.current_rules(deadline)?;
        let Some(index) = self
            .tuples
            .iter()
            .position(|tuple| tuple.key_matches(context, path, role))
        else {
            return Ok(false);
        };
        let tag = self.tuples[index].tag();
        let handle = rules
            .iter()
            .find(|rule| rule.tag == tag)
            .ok_or(KernelError::Invalid)?
            .handle;
        self.uncertain = true;
        self.nft.as_mut().ok_or(KernelError::Invalid)?.delete_rule(
            &self.table,
            handle,
            deadline,
        )?;
        self.tuples.remove(index);
        self.uncertain = false;
        self.inspect(deadline)?;
        Ok(true)
    }

    pub(crate) fn inspect(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<ReceiveAccountingSnapshot, KernelError> {
        let rules = self.current_rules(deadline)?;
        let total = rules
            .iter()
            .find(|rule| rule.tag == b"total")
            .ok_or(KernelError::Invalid)?
            .counters;
        let tuples = self
            .tuples
            .iter()
            .map(|tuple| {
                let rule = rules
                    .iter()
                    .find(|rule| rule.tag == tuple.tag())
                    .ok_or(KernelError::Invalid)?;
                Ok(ReceiveTupleCounters {
                    tuple: tuple.clone(),
                    counters: rule.counters,
                })
            })
            .collect::<Result<Vec<_>, KernelError>>()?;
        Ok(ReceiveAccountingSnapshot { total, tuples })
    }

    /// Only the retained netlink socket's own table can be deleted. An uncertain batch closes
    /// that socket (kernel-owned cleanup), then independently verifies exact-name absence.
    pub(crate) fn remove(&mut self, deadline: HardDeadline) -> Result<bool, KernelError> {
        self.check_namespace()?;
        if self.removed {
            return Ok(false);
        }
        if !self.uncertain {
            let nft = self.nft.as_mut().ok_or(KernelError::Invalid)?;
            let handle = nft.verify_table(&self.table, &self.config, deadline)?;
            if self.table_handle != Some(handle) {
                return Err(KernelError::Invalid);
            }
            self.uncertain = true;
            nft.delete_table(handle, deadline)?;
        }
        drop(self.nft.take());
        if Nft::connect(deadline)?
            .table(&self.table, deadline)?
            .is_some()
        {
            return Err(KernelError::Invalid);
        }
        self.removed = true;
        self.tuples.clear();
        Ok(true)
    }
}

fn validate_new_tuple(current: &[ReceiveTuple], tuple: &ReceiveTuple) -> Result<(), KernelError> {
    if current.len() >= MAX_RECEIVE_TUPLES
        || current.iter().any(|old| {
            old.key_matches(tuple.context_id, tuple.path_id, tuple.role)
                || (old.local == tuple.local && old.remote == tuple.remote)
        })
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn verify_rules(rules: &[Rule], tuples: &[ReceiveTuple]) -> Result<(), KernelError> {
    if rules.len() != tuples.len() + 1 {
        return Err(KernelError::Invalid);
    }
    let mut handles = std::collections::BTreeSet::new();
    let mut tags = std::collections::BTreeSet::new();
    for rule in rules {
        if rule.handle == 0 || !handles.insert(rule.handle) || !tags.insert(&rule.tag) {
            return Err(KernelError::Invalid);
        }
        let expected = if rule.tag == b"total" {
            netlink::expressions(None)
        } else {
            let tuple = tuples
                .iter()
                .find(|tuple| tuple.tag() == rule.tag)
                .ok_or(KernelError::Invalid)?;
            netlink::expressions(Some(tuple))
        };
        if rule.expressions != expected {
            return Err(KernelError::Invalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
