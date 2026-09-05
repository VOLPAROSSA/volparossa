//! One bounded, shared upload scheduler in the actual egress namespace.
//!
//! TBF(total) -> PRIO(owner, contribution) -> bounded owner FIFO / contribution TBF+FQ-CoDel.
//! No route is inferred from an address-bearing interface: the caller supplies the already
//! kernel-proven output ifindex. This is local upload scheduling, not download/airtime control.
//! A partially installed tree remains owned in `InstallFailure::cleanup`; dropping an owner is
//! not cleanup. Only an unchanged default root may be replaced, and its restoration is verified.

use std::{collections::BTreeSet, fs::File, os::unix::fs::MetadataExt};

use volparossa_core::{CONTRIBUTION_MARK_BIT, CONTRIBUTION_SOCKET_PRIORITY};

use super::{
    HardDeadline, KernelError, LinkDetails, NETLINK_ROUTE, NLA_TYPE_MASK, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REQUEST, NLMSG_ERROR, NLMSG_HEADER_LEN, NetlinkClient, RTM_GETLINK, RTM_NEWLINK,
    attributes, build_netlink_message, frames, interface_info, parse_ack, parse_link_details_frame,
    push_attribute, push_string_attribute, read_i32, read_u16, read_u32, validate_kernel_header,
    validate_kernel_sender,
};

const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_GETQDISC: u16 = 38;
const RTM_NEWTFILTER: u16 = 44;
const RTM_GETTFILTER: u16 = 46;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_DONE: u16 = 3;
const TC_ROOT: u32 = u32::MAX;
const TC_MESSAGE_BYTES: usize = 20;
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_STATS2: u16 = 7;
const MAX_OBJECTS: usize = 64;
const MAX_DUMP_BYTES: usize = 256 * 1024;
const MAX_OPTIONS_BYTES: usize = 4096;
const FILTER_INFO: u32 = (1 << 16) | (3_u16.to_be() as u32); // priority 1, ETH_P_ALL.

mod defaults;
use defaults::{DefaultTree, LinkGeometry};

/// Explicit operator capacities; this structure is not an interface-selection authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharingConfig {
    pub(crate) egress_ifindex: u32,
    pub(crate) total_upload_mbps: u32,
    pub(crate) contribution_upload_mbps: u32,
    pub(crate) runtime_id: [u8; 16],
}

impl SharingConfig {
    fn validate(self) -> Result<(), KernelError> {
        if self.egress_ifindex <= 1
            || self.egress_ifindex > i32::MAX as u32
            || self.runtime_id == [0; 16]
            || !(1..=1_000_000).contains(&self.total_upload_mbps)
            || self.contribution_upload_mbps == 0
            || self.contribution_upload_mbps > self.total_upload_mbps
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }
}

/// Kernel counters only. The caller derives rates from differences and its monotone sample times.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct QueueCounters {
    pub(crate) bytes: u64,
    pub(crate) packets: u64,
    pub(crate) drops: u32,
    pub(crate) overlimits: u32,
    pub(crate) backlog_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharingCounters {
    pub(crate) total: QueueCounters,
    pub(crate) owner: QueueCounters,
    pub(crate) contribution: QueueCounters,
}

/// Opaque, non-cloneable ownership of the exact namespace, link and derived qdisc tree.
pub(crate) struct SharingOwner {
    config: SharingConfig,
    namespace: File,
    link: LinkDetails,
    geometry: LinkGeometry,
    baseline: DefaultTree,
    specifications: Vec<QdiscSpec>,
    removed: bool,
}

pub(crate) struct InstallFailure {
    pub(crate) source: KernelError,
    pub(crate) cleanup: Option<Box<SharingOwner>>,
}

impl std::fmt::Debug for InstallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallFailure")
            .field("source", &self.source)
            .field("cleanup_required", &self.cleanup.is_some())
            .finish()
    }
}

/// Resolve a typed operator-selected interface without accepting an untrusted ifindex.
pub(crate) fn resolve_interface(name: &str, deadline: HardDeadline) -> Result<u32, KernelError> {
    if name.is_empty()
        || name.len() > 15
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(KernelError::Invalid);
    }
    NetlinkClient::connect(NETLINK_ROUTE, deadline)?.link_index(name, deadline)
}

/// Install a real shared scheduler. Every possibly-created tree is returned for exact retirement.
pub(crate) fn install(
    config: SharingConfig,
    deadline: HardDeadline,
) -> Result<SharingOwner, InstallFailure> {
    let setup = || -> Result<SharingOwner, KernelError> {
        config.validate()?;
        let namespace = File::open("/proc/thread-self/ns/net")?;
        let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let (link, geometry) = observe_link(&mut route, config.egress_ifindex, deadline)?;
        if link.flags & (libc::IFF_LOOPBACK as u32) != 0 || !(1280..=65_535).contains(&geometry.mtu)
        {
            return Err(KernelError::Invalid);
        }
        let records = dump(&mut route, RTM_GETQDISC, config.egress_ifindex, 0, deadline)?;
        let baseline = DefaultTree::from_records(&records, geometry)?;
        baseline.verify_no_filters(&mut route, config.egress_ifindex, deadline)?;
        Ok(SharingOwner {
            config,
            namespace,
            link,
            geometry,
            baseline,
            specifications: specifications(config, geometry.mtu),
            removed: false,
        })
    };
    let mut owner = setup().map_err(|source| InstallFailure {
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

impl SharingOwner {
    pub(crate) fn config(&self) -> SharingConfig {
        self.config
    }

    fn checked_route(&self, deadline: HardDeadline) -> Result<NetlinkClient, KernelError> {
        let now = File::open("/proc/thread-self/ns/net")?.metadata()?;
        let pinned = self.namespace.metadata()?;
        if now.dev() != pinned.dev() || now.ino() != pinned.ino() {
            return Err(KernelError::Invalid);
        }
        let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let (current, geometry) = observe_link(&mut route, self.config.egress_ifindex, deadline)?;
        if current.index != self.link.index
            || current.name != self.link.name
            || current.alias != self.link.alias
            || current.kind != self.link.kind
            || geometry != self.geometry
        {
            return Err(KernelError::Invalid);
        }
        Ok(route)
    }

    fn install_tree(&mut self, deadline: HardDeadline) -> Result<(), KernelError> {
        let mut route = self.checked_route(deadline)?;
        let before = dump(
            &mut route,
            RTM_GETQDISC,
            self.config.egress_ifindex,
            0,
            deadline,
        )?;
        if !self.baseline.matches(&before, self.geometry) {
            return Err(KernelError::Invalid);
        }
        self.baseline
            .verify_no_filters(&mut route, self.config.egress_ifindex, deadline)?;
        for (index, specification) in self.specifications.iter().enumerate() {
            let flags = if index == 0 {
                NLM_F_CREATE | NLM_F_EXCL
            } else {
                NLM_F_CREATE | NLM_F_REPLACE
            };
            route.request_ack(
                RTM_NEWQDISC,
                flags,
                &specification.encode(self.config.egress_ifindex)?,
                deadline,
            )?;
        }
        route.request_ack(
            RTM_NEWTFILTER,
            NLM_F_CREATE | NLM_F_EXCL,
            &filter_request(self.config.egress_ifindex, self.specifications[1].handle)?,
            deadline,
        )?;
        self.inspect(deadline)?;
        Ok(())
    }

    /// Verify exact policy before returning counters; never invent a measured bandwidth estimate.
    pub(crate) fn inspect(&self, deadline: HardDeadline) -> Result<SharingCounters, KernelError> {
        if self.removed {
            return Err(KernelError::Invalid);
        }
        let mut route = self.checked_route(deadline)?;
        let records = dump(
            &mut route,
            RTM_GETQDISC,
            self.config.egress_ifindex,
            0,
            deadline,
        )?;
        self.verify_tree(&records, true)?;
        self.verify_filters(&mut route, true, deadline)?;
        let counters = |index: usize| {
            records
                .iter()
                .find(|record| record.handle == self.specifications[index].handle)
                .map(|record| record.counters)
                .ok_or(KernelError::Malformed)
        };
        Ok(SharingCounters {
            total: counters(0)?,
            owner: counters(2)?,
            contribution: counters(3)?,
        })
    }

    /// Idempotently retire only this exact tree and prove the original default was restored.
    pub(crate) fn remove(&mut self, deadline: HardDeadline) -> Result<(), KernelError> {
        let mut route = self.checked_route(deadline)?;
        let before = dump(
            &mut route,
            RTM_GETQDISC,
            self.config.egress_ifindex,
            0,
            deadline,
        )?;
        if self.baseline.matches(&before, self.geometry) {
            self.baseline
                .verify_no_filters(&mut route, self.config.egress_ifindex, deadline)?;
            self.removed = true;
            return Ok(());
        }
        self.verify_tree(&before, false)?;
        if before
            .iter()
            .any(|record| record.handle == self.specifications[1].handle)
        {
            self.verify_filters(&mut route, false, deadline)?;
        }
        let root = &self.specifications[0];
        route.request_ack(
            RTM_DELQDISC,
            0,
            &tc_message(self.config.egress_ifindex, root.handle, TC_ROOT, 0),
            deadline,
        )?;
        let after = dump(
            &mut route,
            RTM_GETQDISC,
            self.config.egress_ifindex,
            0,
            deadline,
        )?;
        if !self.baseline.matches(&after, self.geometry) {
            return Err(KernelError::Malformed);
        }
        self.baseline
            .verify_no_filters(&mut route, self.config.egress_ifindex, deadline)?;
        self.removed = true;
        Ok(())
    }

    fn verify_tree(&self, records: &[TcRecord], complete: bool) -> Result<(), KernelError> {
        if records.is_empty() || (complete && records.len() != self.specifications.len()) {
            return Err(KernelError::Malformed);
        }
        let mut handles = BTreeSet::new();
        for record in records {
            if !handles.insert(record.handle) {
                return Err(KernelError::Malformed);
            }
            let specification = self
                .specifications
                .iter()
                .find(|item| item.handle == record.handle)
                .ok_or(KernelError::Invalid)?;
            specification.verify(record)?;
        }
        if !records
            .iter()
            .any(|record| record.handle == self.specifications[0].handle)
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    fn verify_filters(
        &self,
        route: &mut NetlinkClient,
        required: bool,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let prio = self.specifications[1].handle;
        let filters = dump(
            route,
            RTM_GETTFILTER,
            self.config.egress_ifindex,
            prio,
            deadline,
        )?;
        let mut found = false;
        for filter in &filters {
            if filter.parent != prio || filter.info != FILTER_INFO || filter.kind != "fw" {
                return Err(KernelError::Invalid);
            }
            // A dump may include the classifier head before its one actual filter.
            if filter.handle == 0 && filter.options.is_empty() {
                continue;
            }
            if found || filter.handle != CONTRIBUTION_MARK_BIT {
                return Err(KernelError::Invalid);
            }
            let options = attributes(&filter.options)?;
            if options.len() != 2
                || exact_u32(&options, 1)? != prio | 2
                || exact_u32(&options, 5)? != CONTRIBUTION_MARK_BIT
            {
                return Err(KernelError::Invalid);
            }
            found = true;
        }
        if required && !found {
            return Err(KernelError::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TcRecord {
    handle: u32,
    parent: u32,
    info: u32,
    kind: String,
    options: Vec<u8>,
    counters: QueueCounters,
    extra_configuration: bool,
}

impl TcRecord {
    fn same_configuration(&self, other: &Self) -> bool {
        self.handle == other.handle
            && self.parent == other.parent
            && self.kind == other.kind
            && self.options == other.options
            && self.extra_configuration == other.extra_configuration
    }
}

#[derive(Clone, Debug)]
enum QdiscKind {
    Tbf {
        bytes_per_second: u64,
        burst: u32,
        limit: u32,
    },
    Prio,
    Fifo(u32),
    FairContribution {
        quantum: u32,
    },
}

#[derive(Clone, Debug)]
struct QdiscSpec {
    handle: u32,
    parent: u32,
    kind: QdiscKind,
}

fn specifications(config: SharingConfig, mtu: u32) -> Vec<QdiscSpec> {
    let mut input = config.runtime_id.to_vec();
    input.extend_from_slice(&config.egress_ifindex.to_ne_bytes());
    let digest = blake3::hash(&input);
    let major = 0x7000
        + (u32::from(u16::from_be_bytes([
            digest.as_bytes()[0],
            digest.as_bytes()[1],
        ])) & 0x0fff);
    let handles = [
        major << 16,
        (major + 1) << 16,
        (major + 2) << 16,
        (major + 3) << 16,
        (major + 4) << 16,
    ];
    let tbf = |mbps: u32| {
        let rate = u64::from(mbps) * 125_000;
        let burst =
            u32::try_from((rate / 1000).clamp(u64::from(mtu) * 2, 131_072)).expect("bounded burst");
        QdiscKind::Tbf {
            bytes_per_second: rate,
            burst,
            limit: burst * 4,
        }
    };
    let total = tbf(config.total_upload_mbps);
    let contribution = tbf(config.contribution_upload_mbps);
    let limit = |kind: &QdiscKind| match kind {
        QdiscKind::Tbf { limit, .. } => *limit,
        _ => 0,
    };
    vec![
        QdiscSpec {
            handle: handles[0],
            parent: TC_ROOT,
            kind: total.clone(),
        },
        QdiscSpec {
            handle: handles[1],
            parent: handles[0] | 1,
            kind: QdiscKind::Prio,
        },
        QdiscSpec {
            handle: handles[2],
            parent: handles[1] | 1,
            kind: QdiscKind::Fifo(limit(&total)),
        },
        QdiscSpec {
            handle: handles[3],
            parent: handles[1] | 2,
            kind: contribution.clone(),
        },
        QdiscSpec {
            handle: handles[4],
            parent: handles[3] | 1,
            // Exit payload sockets and encrypted tunnel feedback share this one capped band.
            // A single tail-drop FIFO lets a busy unresponsive datagram flow starve the other
            // flows needed for recovery. Kernel flow queuing does not promote any contribution
            // above the owner, and neither physical nor aggregate contribution ceilings change.
            kind: QdiscKind::FairContribution {
                quantum: (mtu + 14).min(65_535),
            },
        },
    ]
}

fn prio_options() -> Vec<u8> {
    let mut result = 2_i32.to_ne_bytes().to_vec();
    result.extend_from_slice(&[0; 16]);
    result[4 + CONTRIBUTION_SOCKET_PRIORITY as usize] = 1;
    result
}

impl QdiscSpec {
    fn name(&self) -> &'static str {
        match self.kind {
            QdiscKind::Tbf { .. } => "tbf",
            QdiscKind::Prio => "prio",
            QdiscKind::Fifo(_) => "bfifo",
            QdiscKind::FairContribution { .. } => "fq_codel",
        }
    }

    fn encode(&self, ifindex: u32) -> Result<Vec<u8>, KernelError> {
        let mut result = tc_message(ifindex, self.handle, self.parent, 0);
        push_string_attribute(&mut result, TCA_KIND, self.name())?;
        let options = match self.kind {
            QdiscKind::Prio => prio_options(),
            QdiscKind::Fifo(limit) => limit.to_ne_bytes().to_vec(),
            QdiscKind::FairContribution { quantum } => fair_contribution_options(quantum)?,
            QdiscKind::Tbf {
                bytes_per_second,
                burst,
                limit,
            } => {
                let mut parameters = vec![0; 36];
                parameters[1] = 1; // Ethernet accounting; no obsolete rate-table lookup.
                parameters[8..12].copy_from_slice(
                    &u32::try_from(bytes_per_second.min(u64::from(u32::MAX)))
                        .expect("clamped rate")
                        .to_ne_bytes(),
                );
                parameters[24..28].copy_from_slice(&limit.to_ne_bytes());
                let mut options = Vec::new();
                push_attribute(&mut options, 1, &parameters)?;
                push_attribute(&mut options, 4, &bytes_per_second.to_ne_bytes())?;
                push_attribute(&mut options, 6, &burst.to_ne_bytes())?;
                options
            }
        };
        push_attribute(&mut result, TCA_OPTIONS, &options)?;
        Ok(result)
    }

    fn verify(&self, record: &TcRecord) -> Result<(), KernelError> {
        if record.handle != self.handle
            || record.parent != self.parent
            || record.kind != self.name()
            || record.extra_configuration
        {
            return Err(KernelError::Invalid);
        }
        let correct = match self.kind {
            QdiscKind::Prio => record.options == prio_options(),
            QdiscKind::Fifo(limit) => record.options == limit.to_ne_bytes(),
            QdiscKind::FairContribution { quantum } => {
                verify_fair_contribution(&record.options, quantum)?
            }
            QdiscKind::Tbf {
                bytes_per_second,
                burst,
                limit,
            } => {
                let fields = attributes(&record.options)?;
                let parameters = exact_attribute(&fields, 1)?;
                let rate = fields
                    .iter()
                    .find(|(kind, _)| kind & NLA_TYPE_MASK == 4)
                    .map_or_else(
                        || read_u32(parameters, 8).map(u64::from),
                        |(_, bytes)| read_u64(bytes, 0),
                    )
                    .ok_or(KernelError::Malformed)?;
                // Kernel converts the burst to nanosecond duration, then dumps legacy 64ns ticks.
                // Compare the exact Linux 6.12 representation, allowing one integer rounding tick.
                let ticks = u64::from(read_u32(parameters, 28).ok_or(KernelError::Malformed)?);
                let expected_ticks = u64::from(burst) * 1_000_000_000 / bytes_per_second / 64;
                parameters.len() == 36
                    && rate == bytes_per_second
                    && read_u32(parameters, 24) == Some(limit)
                    && parameters[12..24].iter().all(|byte| *byte == 0)
                    && read_u32(parameters, 32) == Some(0)
                    && ticks.abs_diff(expected_ticks) <= 1
            }
        };
        if correct {
            Ok(())
        } else {
            Err(KernelError::Invalid)
        }
    }
}

// Linux v6.12 net/sched/sch_fq_codel.c and include/uapi/linux/pkt_sched.h.
// Bounded real kernel flow queuing/AQM, not path equalization, duplication or extra cover traffic.
fn fair_contribution_fields(quantum: u32) -> [(u16, u32); 8] {
    [
        (1, 5_000),
        (2, 64),
        (3, 100_000),
        (4, 1),
        (5, 64),
        (6, quantum),
        (8, 1),
        (9, 256 * 1024),
    ]
}

fn fair_contribution_options(quantum: u32) -> Result<Vec<u8>, KernelError> {
    let mut result = Vec::new();
    for (kind, value) in fair_contribution_fields(quantum) {
        push_attribute(&mut result, kind, &value.to_ne_bytes())?;
    }
    Ok(result)
}

fn verify_fair_contribution(options: &[u8], quantum: u32) -> Result<bool, KernelError> {
    let fields = attributes(options)?;
    let expected = fair_contribution_fields(quantum);
    if fields.len() != expected.len() {
        return Ok(false);
    }
    for (kind, mut value) in expected {
        if kind == 1 || kind == 3 {
            // CoDel stores 1024ns ticks and truncates to microseconds on dump.
            value = (((value * 1000) >> 10) << 10) / 1000;
        }
        if exact_u32(&fields, kind)? != value {
            return Ok(false);
        }
    }
    Ok(true)
}

fn filter_request(ifindex: u32, prio: u32) -> Result<Vec<u8>, KernelError> {
    let mut result = tc_message(ifindex, CONTRIBUTION_MARK_BIT, prio, FILTER_INFO);
    push_string_attribute(&mut result, TCA_KIND, "fw")?;
    let mut options = Vec::new();
    push_attribute(&mut options, 1, &(prio | 2).to_ne_bytes())?;
    push_attribute(&mut options, 5, &CONTRIBUTION_MARK_BIT.to_ne_bytes())?;
    push_attribute(&mut result, TCA_OPTIONS, &options)?;
    Ok(result)
}

fn tc_message(ifindex: u32, handle: u32, parent: u32, info: u32) -> Vec<u8> {
    let mut result = vec![0; 4];
    for value in [ifindex, handle, parent, info] {
        result.extend_from_slice(&value.to_ne_bytes());
    }
    result
}

fn observe_link(
    route: &mut NetlinkClient,
    ifindex: u32,
    deadline: HardDeadline,
) -> Result<(LinkDetails, LinkGeometry), KernelError> {
    let (reply, sequence) =
        route.request_reply(RTM_GETLINK, &interface_info(ifindex, 0, 0)?, deadline)?;
    validate_kernel_sender(&reply.sender)?;
    let messages = frames(&reply.message)?;
    let [frame] = messages.as_slice() else {
        return Err(KernelError::Malformed);
    };
    if read_u16(frame, 4) == Some(NLMSG_ERROR) {
        parse_ack(&reply, sequence, RTM_GETLINK, route.local_port_id)?;
        return Err(KernelError::Malformed);
    }
    validate_kernel_header(frame, sequence, RTM_NEWLINK, route.local_port_id)?;
    let link = parse_link_details_frame(frame)?;
    let fields = attributes(&frame[NLMSG_HEADER_LEN + 16..])?;
    let geometry = LinkGeometry {
        mtu: exact_u32(&fields, super::IFLA_MTU)?,
        hardware_type: read_u16(frame, NLMSG_HEADER_LEN + 2).ok_or(KernelError::Malformed)?,
        tx_queues: exact_u32(&fields, 31)?, // IFLA_NUM_TX_QUEUES.
        tx_queue_length: exact_u32(&fields, 13)?, // IFLA_TXQLEN.
    };
    if link.index != ifindex {
        return Err(KernelError::Malformed);
    }
    Ok((link, geometry))
}

fn exact_attribute<'a>(fields: &[(u16, &'a [u8])], wanted: u16) -> Result<&'a [u8], KernelError> {
    let mut matches = fields
        .iter()
        .filter(|(kind, _)| kind & NLA_TYPE_MASK == wanted);
    let (_, bytes) = matches.next().ok_or(KernelError::Malformed)?;
    if matches.next().is_some() {
        return Err(KernelError::Malformed);
    }
    Ok(bytes)
}

fn exact_u32(fields: &[(u16, &[u8])], wanted: u16) -> Result<u32, KernelError> {
    let bytes = exact_attribute(fields, wanted)?;
    if bytes.len() != 4 {
        return Err(KernelError::Malformed);
    }
    read_u32(bytes, 0).ok_or(KernelError::Malformed)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)?
        .try_into()
        .ok()
        .map(u64::from_ne_bytes)
}

fn dump(
    route: &mut NetlinkClient,
    request_type: u16,
    ifindex: u32,
    parent: u32,
    deadline: HardDeadline,
) -> Result<Vec<TcRecord>, KernelError> {
    let sequence = route.next_sequence();
    route.send(
        &build_netlink_message(
            request_type,
            NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            &tc_message(ifindex, 0, parent, 0),
        )?,
        deadline,
    )?;
    let expected = if request_type == RTM_GETQDISC {
        RTM_NEWQDISC
    } else {
        RTM_NEWTFILTER
    };
    let mut total_bytes = 0_usize;
    let mut records = Vec::new();
    loop {
        let reply = route.receive(deadline)?;
        total_bytes += reply.message.len();
        if total_bytes > MAX_DUMP_BYTES {
            return Err(KernelError::Malformed);
        }
        validate_kernel_sender(&reply.sender)?;
        for frame in frames(&reply.message)? {
            let kind = read_u16(frame, 4).ok_or(KernelError::Malformed)?;
            validate_kernel_header(frame, sequence, kind, route.local_port_id)?;
            if read_u16(frame, 6).is_none_or(|flags| flags & NLM_F_DUMP_INTR != 0) {
                return Err(KernelError::Malformed);
            }
            if kind == NLMSG_DONE {
                if read_i32(frame, NLMSG_HEADER_LEN) != Some(0) {
                    return Err(KernelError::Malformed);
                }
                deadline.ensure_remaining()?;
                return Ok(records);
            }
            if kind == NLMSG_ERROR {
                parse_ack(&reply, sequence, request_type, route.local_port_id)?;
                return Err(KernelError::Malformed);
            }
            if kind != expected || frame.len() < NLMSG_HEADER_LEN + TC_MESSAGE_BYTES {
                return Err(KernelError::Malformed);
            }
            if read_u32(frame, NLMSG_HEADER_LEN + 4) != Some(ifindex) {
                continue;
            }
            if records.len() >= MAX_OBJECTS {
                return Err(KernelError::Malformed);
            }
            records.push(parse_tc(frame)?);
        }
    }
}

fn parse_tc(frame: &[u8]) -> Result<TcRecord, KernelError> {
    let payload = frame
        .get(NLMSG_HEADER_LEN..)
        .filter(|p| p.len() >= TC_MESSAGE_BYTES)
        .ok_or(KernelError::Malformed)?;
    let fields = attributes(&payload[TC_MESSAGE_BYTES..])?;
    let extra_configuration = fields
        .iter()
        .any(|(kind, bytes)| match kind & NLA_TYPE_MASK {
            1..=4 | 6 | 7 | 9 => false, // Kind, options, statistics and padding.
            12 => *bytes != [0], // Hardware offload is not a software-default restoration authority.
            _ => true, // Reject estimators, STAB, shared blocks and unknown configuration.
        });
    let kind = super::parse_string_attribute(exact_attribute(&fields, TCA_KIND)?, 16)?;
    let options = fields
        .iter()
        .find(|(kind, _)| kind & NLA_TYPE_MASK == TCA_OPTIONS)
        .map_or(&[][..], |(_, v)| *v);
    if options.len() > MAX_OPTIONS_BYTES {
        return Err(KernelError::Malformed);
    }
    let mut counters = QueueCounters::default();
    if let Some((_, stats)) = fields
        .iter()
        .find(|(kind, _)| kind & NLA_TYPE_MASK == TCA_STATS2)
    {
        let stats = attributes(stats)?;
        if let Ok(basic) = exact_attribute(&stats, 1) {
            counters.bytes = read_u64(basic, 0).ok_or(KernelError::Malformed)?;
            counters.packets = u64::from(read_u32(basic, 8).ok_or(KernelError::Malformed)?);
        }
        if let Ok(queue) = exact_attribute(&stats, 3) {
            counters.backlog_bytes = read_u32(queue, 4).ok_or(KernelError::Malformed)?;
            counters.drops = read_u32(queue, 8).ok_or(KernelError::Malformed)?;
            counters.overlimits = read_u32(queue, 16).ok_or(KernelError::Malformed)?;
        }
        if let Ok(packets) = exact_attribute(&stats, 8) {
            counters.packets = read_u64(packets, 0).ok_or(KernelError::Malformed)?;
        }
    }
    Ok(TcRecord {
        handle: read_u32(payload, 8).ok_or(KernelError::Malformed)?,
        parent: read_u32(payload, 12).ok_or(KernelError::Malformed)?,
        info: read_u32(payload, 16).ok_or(KernelError::Malformed)?,
        kind,
        options: options.to_vec(),
        counters,
        extra_configuration,
    })
}

#[cfg(test)]
mod tests;
