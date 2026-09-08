//! Exact owned Exit-WireGuard sender queue. The separate worker gate controls admission/expiry.
//!
//! This queue acts before encryption and before the receiving Relay's underlay. Queue counters
//! count inner skb bytes, not receive-side NETDEV bytes or an ISP's billing units.

use super::{
    File, HardDeadline, KernelError, LinkDetails, MetadataExt, NETLINK_ROUTE, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REPLACE, NetlinkClient, QdiscKind, QdiscSpec, QueueCounters, RTM_DELQDISC,
    RTM_GETQDISC, RTM_GETTFILTER, RTM_NEWQDISC, TC_ROOT, TCA_KIND, TCA_OPTIONS, TcRecord, dump,
    observe_link, push_attribute, push_string_attribute, tc_message,
};
use crate::ownership_journal::DurableWireguardResource;
use volparossa_routing::WireguardRole;

// Linux v6.12 WireGuard messages.h/send.c: maximum IPv6 outer IP 40 + UDP 8 +
// message_data header 16 + Poly1305 tag 16 + at most 15 bytes padding. This is
// conservative for IPv4 too; Linux TBF charges it per queued skb, including small datagrams.
const WIREGUARD_OVERHEAD: u16 = 95;

/// A rate change is accepted only behind the worker's already-closed expiry gate.
pub(crate) struct DownlinkQueue {
    namespace: File,
    link: LinkDetails,
    mtu: u32,
    maximum_queued_bytes: u32,
    specifications: [QdiscSpec; 2],
    /// Set before dispatch: partial installation remains exact cleanup authority.
    may_exist: bool,
}

pub(crate) struct InstallFailure {
    pub(crate) source: KernelError,
    pub(crate) cleanup: Option<Box<DownlinkQueue>>,
}

impl DownlinkQueue {
    /// Prepare a finite placeholder queue while admission is CLOSED, before peer activation.
    pub(crate) fn install(
        resource: &DurableWireguardResource,
        ifindex: u32,
        deadline: HardDeadline,
    ) -> Result<Self, InstallFailure> {
        let prepare = || -> Result<Self, KernelError> {
            if resource.key().1 != WireguardRole::Exit as i32 || ifindex <= 1 {
                return Err(KernelError::Invalid);
            }
            let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
            let (link, geometry) = observe_link(&mut route, ifindex, deadline)?;
            if link.name.as_deref() != Some(resource.interface())
                || link.alias.as_deref() != Some(resource.ownership_alias())
                || link.kind.as_deref() != Some("wireguard")
                || !(1280..=4096).contains(&geometry.mtu)
            {
                return Err(KernelError::Invalid);
            }
            let records = dump(&mut route, RTM_GETQDISC, ifindex, 0, deadline)?;
            verify_default(&records)?;
            if !dump(&mut route, RTM_GETTFILTER, ifindex, TC_ROOT, deadline)?.is_empty() {
                return Err(KernelError::Invalid);
            }
            let root = (0x6000 + u32::from(resource.key().0) * 2) << 16;
            let mtu = geometry.mtu;
            Ok(Self {
                namespace: File::open("/proc/thread-self/ns/net")?,
                link,
                mtu,
                maximum_queued_bytes: 131_072,
                specifications: [
                    QdiscSpec {
                        handle: root,
                        parent: TC_ROOT,
                        kind: QdiscKind::Tbf {
                            bytes_per_second: 125_000,
                            burst: mtu,
                            limit: 131_072,
                            overhead: WIREGUARD_OVERHEAD,
                        },
                    },
                    QdiscSpec {
                        handle: root + (1 << 16),
                        parent: root | 1,
                        kind: QdiscKind::BudgetContribution {
                            quantum: mtu,
                            memory_limit: 131_072,
                        },
                    },
                ],
                may_exist: false,
            })
        };
        let mut owner = prepare().map_err(|source| InstallFailure {
            source,
            cleanup: None,
        })?;
        if let Err(source) = owner.install_tree(deadline) {
            return Err(InstallFailure {
                source,
                cleanup: Some(Box::new(owner)),
            });
        }
        Ok(owner)
    }

    pub(crate) const fn maximum_queued_bytes(&self) -> u32 {
        self.maximum_queued_bytes
    }

    fn route(&self, deadline: HardDeadline) -> Result<NetlinkClient, KernelError> {
        let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
        let pinned = self.namespace.metadata()?;
        if current.dev() != pinned.dev() || current.ino() != pinned.ino() {
            return Err(KernelError::Invalid);
        }
        let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let (link, geometry) = observe_link(&mut route, self.link.index, deadline)?;
        if link.index != self.link.index
            || link.name != self.link.name
            || link.alias != self.link.alias
            || link.kind != self.link.kind
            || geometry.mtu != self.mtu
        {
            return Err(KernelError::Invalid);
        }
        Ok(route)
    }

    fn install_tree(&mut self, deadline: HardDeadline) -> Result<(), KernelError> {
        let mut route = self.route(deadline)?;
        self.may_exist = true;
        for (index, spec) in self.specifications.iter().enumerate() {
            route.request_ack(
                RTM_NEWQDISC,
                NLM_F_CREATE
                    | if index == 0 {
                        NLM_F_EXCL
                    } else {
                        NLM_F_REPLACE
                    },
                &spec.encode(self.link.index)?,
                deadline,
            )?;
        }
        self.inspect(deadline)?;
        Ok(())
    }

    /// Change only this exact queue while the owning worker has closed its admission gate.
    /// A zero budget never enters TBF; it leaves the finite previous queue behind a closed gate.
    pub(crate) fn set_rate(
        &mut self,
        rate: u64,
        burst: u32,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        if !(1..=125_000_000_000).contains(&rate) || !(self.mtu..=65_536).contains(&burst) {
            return Err(KernelError::Invalid);
        }
        self.inspect(deadline)?;
        let mut route = self.route(deadline)?;
        let mut next = self.specifications[0].clone();
        let maximum_queued_bytes = (burst * 2).max(self.mtu * 2);
        if matches!(next.kind,QdiscKind::Tbf{bytes_per_second,..} if bytes_per_second==rate)
            && self.maximum_queued_bytes == maximum_queued_bytes
        {
            return Ok(());
        }
        // sch_tbf segments GSO above max_size (= burst) before the inner qdisc. Capping
        // this token bucket at the owned device MTU makes overhead apply to every future
        // encrypted packet, not only once to a multi-packet GSO skb. The signed burst and
        // returned queue-memory bound remain conservative upper bounds, never enlarged.
        next.kind = QdiscKind::Tbf {
            bytes_per_second: rate,
            burst: self.mtu,
            limit: maximum_queued_bytes,
            overhead: WIREGUARD_OVERHEAD,
        };
        // On ambiguity the worker retains both this exact handle and a CLOSED gate; cleanup may
        // delete that root but must never open admission or silently use the old requested rate.
        let result = route.request_ack(
            RTM_NEWQDISC,
            NLM_F_REPLACE,
            &next.encode(self.link.index)?,
            deadline,
        );
        self.specifications[0] = next;
        result?;
        let mut child = self.specifications[1].clone();
        child.kind = QdiscKind::BudgetContribution {
            quantum: self.mtu,
            memory_limit: maximum_queued_bytes,
        };
        // FQ-CoDel's flow count is immutable after creation. Change only its bounded memory
        // limit, then prove every unchanged field as well; resending FLOWS is rejected by Linux.
        let mut change = tc_message(self.link.index, child.handle, child.parent, 0);
        push_string_attribute(&mut change, TCA_KIND, child.name())?;
        let mut options = Vec::new();
        push_attribute(&mut options, 9, &maximum_queued_bytes.to_ne_bytes())?;
        push_attribute(&mut change, TCA_OPTIONS, &options)?;
        let result = route.request_ack(RTM_NEWQDISC, 0, &change, deadline);
        self.specifications[1] = child;
        self.maximum_queued_bytes = maximum_queued_bytes;
        result?;
        self.inspect(deadline)?;
        Ok(())
    }

    pub(crate) fn inspect(&self, deadline: HardDeadline) -> Result<QueueCounters, KernelError> {
        if !self.may_exist {
            return Err(KernelError::Invalid);
        }
        let mut route = self.route(deadline)?;
        let records = dump(&mut route, RTM_GETQDISC, self.link.index, 0, deadline)?;
        if records.len() != 2 {
            return Err(KernelError::Invalid);
        }
        for expected in &self.specifications {
            let record = records
                .iter()
                .find(|record| record.handle == expected.handle)
                .ok_or(KernelError::Invalid)?;
            expected.verify(record)?;
        }
        if !dump(
            &mut route,
            RTM_GETTFILTER,
            self.link.index,
            self.specifications[0].handle,
            deadline,
        )?
        .is_empty()
            || !dump(
                &mut route,
                RTM_GETTFILTER,
                self.link.index,
                self.specifications[1].handle,
                deadline,
            )?
            .is_empty()
        {
            return Err(KernelError::Invalid);
        }
        records
            .iter()
            .find(|record| record.handle == self.specifications[0].handle)
            .map(|record| record.counters)
            .ok_or(KernelError::Invalid)
    }

    /// Remove only a matching owned root, including a partially installed two-node tree.
    pub(crate) fn remove(&mut self, deadline: HardDeadline) -> Result<(), KernelError> {
        let mut route = self.route(deadline)?;
        let records = dump(&mut route, RTM_GETQDISC, self.link.index, 0, deadline)?;
        if verify_default(&records).is_ok() {
            self.may_exist = false;
            return Ok(());
        }
        if !self.may_exist
            || records.is_empty()
            || records.len() > 2
            || records.iter().any(|record| {
                self.specifications.iter().all(|expected| {
                    record.handle != expected.handle
                        || record.parent != expected.parent
                        || record.kind != expected.name()
                })
            })
        {
            return Err(KernelError::Invalid);
        }
        route.request_ack(
            RTM_DELQDISC,
            0,
            &tc_message(self.link.index, self.specifications[0].handle, TC_ROOT, 0),
            deadline,
        )?;
        verify_default(&dump(
            &mut route,
            RTM_GETQDISC,
            self.link.index,
            0,
            deadline,
        )?)?;
        self.may_exist = false;
        Ok(())
    }
}

fn verify_default(records: &[TcRecord]) -> Result<(), KernelError> {
    let [record] = records else {
        return Err(KernelError::Invalid);
    };
    if record.handle != 0
        || record.parent != TC_ROOT
        || record.kind != "noqueue"
        || !record.options.is_empty()
        || record.extra_configuration
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}
