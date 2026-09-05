//! Bounded Linux rtnetlink and `WireGuard` generic-netlink operations.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr as InternetSocketAddr},
    os::fd::RawFd,
    time::Duration,
};

use netlink_sys::{
    Socket, SocketAddr,
    protocols::{NETLINK_GENERIC, NETLINK_ROUTE},
};
use nix::poll::PollFlags;
use nix::setsockopt_impl;
use nix::sockopt_impl;
use nix::sys::socket::setsockopt;
use thiserror::Error;
use volparossa_routing::WireguardRole;
use zeroize::Zeroizing;

use crate::{
    deadline::{HardDeadline, wait_for_fd},
    lease_spec::WireguardLeaseSpec,
    ownership_journal::{DurableWireguardResource, RestartNetworkPlan},
};

#[allow(dead_code)] // GET_DEVICE is wired into the v3 lease state machine in phase 2.
mod wireguard_probe;

pub(crate) mod underlay_sharing;
pub(crate) mod wifi_mesh;

use wireguard_probe::WireguardDeviceState;

sockopt_impl!(
    #[allow(missing_docs)]
    NetlinkCapAck,
    SetOnly,
    libc::SOL_NETLINK,
    libc::NETLINK_CAP_ACK,
    bool
);

const NLMSG_HEADER_LEN: usize = 16;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const NLMSG_ERROR_CODE_LEN: usize = 4;
const GENL_HEADER_LEN: usize = 4;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const MAX_NETLINK_MESSAGE: usize = 64 * 1024;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_IFALIAS: u16 = 20;
const IFLA_NEW_IFINDEX: u16 = 49;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_PREF: u16 = 20;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_IIFNAME: u16 = 3;
const FRA_UID_RANGE: u16 = 20;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTM_F_FIB_MATCH: u32 = 0x2000;
const IPV6_ROUTER_PREF_MEDIUM: u8 = 0;
const IPV6_USER_ROUTE_PRIORITY: u32 = 1024;
const RTA_CACHEINFO_LEN: usize = 32;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_VERSION: u8 = 2;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const MAX_IFNAME_BYTES: usize = 15;
const MAX_IFALIAS_BYTES: usize = 255;
const MAX_LINK_KIND_BYTES: usize = 16;
const BIRTH_LINK_PROGRESS_TAIL: Duration = Duration::from_millis(500);
const BIRTH_LINK_RECONCILE_TAIL: Duration = Duration::from_millis(250);
const BIRTH_LINK_IFINDEX_PREFIX: u32 = 0x4000_0000;
const BIRTH_LINK_IFINDEX_MASK: u32 = 0x3fff_ffff;
const RTMSG_LEN: usize = 12;
const FIB_RULE_HDR_LEN: usize = 12;

pub(crate) const CLIENT_INGRESS_IPV4_MARK: u32 = 0x5650_1001;
pub(crate) const CONTRIBUTION_WIREGUARD_MARK: u32 =
    CLIENT_INGRESS_IPV4_MARK | volparossa_core::CONTRIBUTION_MARK_BIT;
pub(crate) const CLIENT_INGRESS_PARENT_IPV4_MARK: u32 = 0x5650_1002;
pub(crate) const CLIENT_INGRESS_IPV6_MARK: u32 = 0x5650_1003;
pub(crate) const CLIENT_INGRESS_PARENT_IPV6_MARK: u32 = 0x5650_1004;
const CLIENT_INGRESS_ROUTE_TABLE: u8 = 100;
const CLIENT_INGRESS_RULE_PRIORITY: u32 = 10_000;
const CLIENT_INGRESS_PARENT_ROUTE_TABLE: u8 = 101;
const CLIENT_INGRESS_PARENT_RULE_PRIORITY: u32 = 9_999;
const CLIENT_INGRESS_INITIAL_RULE_PRIORITY: u32 = 9_997;
const FR_ACT_TO_TBL: u8 = 1;
const RTNH_F_ONLINK: u32 = 4;

const WG_GENL_NAME: &str = "wireguard";
const VETH_LINK_KIND: &str = "veth";
const CLIENT_INGRESS_PARENT_ADDRESS: [u8; 4] = [169, 254, 240, 1];
const CLIENT_INGRESS_WORKER_ADDRESS: [u8; 4] = [169, 254, 240, 2];
// Keep application QUIC datagrams within the native CONNECT-IP path's outer-packet budget.
// The tunnel assignment may negotiate up to 1420 bytes, but that is the inner-IP ceiling: using
// it on the application-facing link lets QUIC probe a 1392-byte UDP payload whose wrapped packet
// cannot fit through the IPv6/UDP/MASQUE transport. IPv6's minimum link MTU keeps both families
// usable while bounding an IPv4 UDP payload to 1252 bytes and its inner packet to 1280 bytes.
const CLIENT_INGRESS_MTU: u32 = 1_280;
const CLIENT_INGRESS_PARENT_IPV6_ADDRESS: [u8; 16] = [
    0xfd, 0x56, 0x4f, 0x4c, 0x50, 0x41, 0x52, 0x4f, 0x53, 0x53, 0x41, 0, 0, 0, 0, 1,
];
const CLIENT_INGRESS_WORKER_IPV6_ADDRESS: [u8; 16] = [
    0xfd, 0x56, 0x4f, 0x4c, 0x50, 0x41, 0x52, 0x4f, 0x53, 0x53, 0x41, 0, 0, 0, 0, 2,
];

#[derive(Clone, Copy)]
enum ClientIngressFamily {
    Ipv4,
    Ipv6,
}
const WG_GENL_VERSION: u8 = 1;
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// Fixed failures mapped to non-sensitive helper diagnostic codes.
#[derive(Debug, Error)]
pub enum KernelError {
    /// Kernel socket or namespace I/O failed.
    #[error("kernel I/O operation failed")]
    Io(#[from] io::Error),
    /// The kernel rejected a request with an errno.
    #[error("kernel rejected network operation")]
    Errno(i32),
    /// The kernel returned a malformed or oversized response.
    #[error("malformed kernel netlink response")]
    Malformed,
    /// The caller supplied a value which cannot be represented safely.
    #[error("invalid bounded kernel operation")]
    Invalid,
    /// A requested kernel family or feature is not available.
    #[error("required kernel feature is unavailable")]
    Unsupported,
}

impl KernelError {
    /// Whether an error means an idempotent create/delete has already happened.
    pub const fn is_errno(&self, errno: i32) -> bool {
        matches!(self, Self::Errno(value) if *value == errno)
    }
}

/// Failure while creating a link in the parent namespace and moving it to a worker.
#[derive(Debug, Error)]
pub(crate) enum BirthLinkError {
    /// The exact derived name was already present before this transaction.
    #[error("derived WireGuard birth link already exists")]
    Conflict,
    /// A kernel operation failed and the parent link is confirmed absent.
    #[error("WireGuard birth-link kernel operation failed")]
    Kernel(#[source] KernelError),
    /// The parent cannot prove that a partially created link was removed or moved.
    #[error("WireGuard birth-link cleanup is incomplete")]
    CleanupIncomplete,
}

/// Affine same-runtime authority for one process-owned `WireGuard` birth link.
///
/// This deliberately non-`Clone` wrapper distinguishes live helper ownership from the public
/// marker metadata it contains. It grants no crash/restart recovery: durable cleanup still needs
/// the journal's separate affine authority.
pub(crate) struct LiveWireguardLeaseOwner {
    resource: DurableWireguardResource,
    birth: LiveBirthLinkState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveBirthLinkState {
    Uncreated,
    CreateSent(u32),
    CreateAcknowledged(u32),
    Provisional(u32),
    AliasSent(u32),
    Marked(u32),
    Moved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BirthCleanupTarget {
    ProveAbsent,
    Unmarked(u32),
    AliasMayBeSet(u32),
    Marked(u32),
}

const fn birth_cleanup_target(state: LiveBirthLinkState) -> BirthCleanupTarget {
    match state {
        LiveBirthLinkState::Uncreated | LiveBirthLinkState::Moved => {
            BirthCleanupTarget::ProveAbsent
        }
        LiveBirthLinkState::CreateSent(index)
        | LiveBirthLinkState::CreateAcknowledged(index)
        | LiveBirthLinkState::Provisional(index) => BirthCleanupTarget::Unmarked(index),
        LiveBirthLinkState::AliasSent(index) => BirthCleanupTarget::AliasMayBeSet(index),
        LiveBirthLinkState::Marked(index) => BirthCleanupTarget::Marked(index),
    }
}

const fn valid_birth_transition(current: LiveBirthLinkState, next: LiveBirthLinkState) -> bool {
    match current {
        LiveBirthLinkState::Uncreated => matches!(next, LiveBirthLinkState::CreateSent(_)),
        LiveBirthLinkState::CreateSent(current) => match next {
            LiveBirthLinkState::Uncreated => true,
            LiveBirthLinkState::CreateAcknowledged(next) => current == next,
            _ => false,
        },
        LiveBirthLinkState::CreateAcknowledged(current) => {
            matches!(next, LiveBirthLinkState::Provisional(next) if current == next)
        }
        LiveBirthLinkState::Provisional(current) => {
            matches!(next, LiveBirthLinkState::AliasSent(next) if current == next)
        }
        LiveBirthLinkState::AliasSent(current) => matches!(
            next,
            LiveBirthLinkState::Provisional(next) | LiveBirthLinkState::Marked(next)
                if current == next
        ),
        LiveBirthLinkState::Marked(_) => matches!(next, LiveBirthLinkState::Moved),
        LiveBirthLinkState::Moved => false,
    }
}

impl LiveWireguardLeaseOwner {
    /// Mint one live owner before any same-runtime birth-link mutation.
    pub(crate) const fn claim(resource: DurableWireguardResource) -> Self {
        Self {
            resource,
            birth: LiveBirthLinkState::Uncreated,
        }
    }

    /// Borrow the secret-free evidence needed by the authenticated child request.
    pub(crate) const fn resource(&self) -> &DurableWireguardResource {
        &self.resource
    }

    fn transition_birth(
        &mut self,
        expected: LiveBirthLinkState,
        next: LiveBirthLinkState,
    ) -> Result<(), KernelError> {
        if self.birth != expected || !valid_birth_transition(expected, next) {
            return Err(KernelError::Invalid);
        }
        self.birth = next;
        Ok(())
    }
}

impl std::fmt::Debug for LiveWireguardLeaseOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LiveWireguardLeaseOwner(<redacted>)")
    }
}

/// Same-transaction evidence for one confirmed, still-unmarked birth link.
///
/// This non-`Clone` value is minted only after a successful exclusive create acknowledgement and
/// exact readback of the new DOWN `WireGuard` link. It permits cleanup during the short marker-set
/// transaction; it is not durable restart authority.
#[must_use = "an acknowledged unmarked birth link must be marked, moved, or cleaned"]
struct ProvisionalWireguardBirthLink {
    index: u32,
}

/// Same-transaction evidence that the provisional link now has its exact durable marker.
#[must_use = "a marked birth link must be moved or cleaned"]
struct MarkedWireguardBirthLink {
    index: u32,
}

enum ObservedMutationAcknowledgement {
    Timely,
    Late(KernelError),
    Rejected(KernelError),
    Ambiguous(KernelError),
}

fn classify_mutation_acknowledgement(
    acknowledgement: Result<(), KernelError>,
    completed_before_progress_cutoff: bool,
) -> ObservedMutationAcknowledgement {
    match acknowledgement {
        Ok(()) if completed_before_progress_cutoff => ObservedMutationAcknowledgement::Timely,
        Ok(()) => ObservedMutationAcknowledgement::Late(KernelError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "birth-link progress cutoff elapsed",
        ))),
        Err(error @ KernelError::Errno(_)) => ObservedMutationAcknowledgement::Rejected(error),
        Err(error) => ObservedMutationAcknowledgement::Ambiguous(error),
    }
}

struct PendingMutationRequest {
    sequence: u32,
    request_type: u16,
    sent_before_progress_cutoff: bool,
}

/// Physical-namespace rtnetlink client used only by the root helper parent.
pub(crate) struct BirthNamespaceKernel {
    route: NetlinkClient,
}

/// Exact same-runtime ownership of the app-to-ingress veth pair.
pub(crate) struct LiveClientIngressVeth {
    parent_name: String,
    worker_name: String,
}

pub(crate) struct ClientIngressParentIpv4Routing {
    parent_ifindex: u32,
    loopback_ifindex: u32,
    initial_rules: Vec<Vec<u8>>,
}

impl ClientIngressParentIpv4Routing {
    pub(crate) const fn parent_ifindex(&self) -> u32 {
        self.parent_ifindex
    }

    pub(crate) const fn loopback_ifindex(&self) -> u32 {
        self.loopback_ifindex
    }
}

impl LiveClientIngressVeth {
    pub(crate) fn parent_name(&self) -> &str {
        &self.parent_name
    }
}

impl BirthNamespaceKernel {
    /// Open a route socket in the caller's current physical/underlay namespace.
    pub(crate) fn connect(deadline: HardDeadline) -> Result<Self, KernelError> {
        Ok(Self {
            route: NetlinkClient::connect(NETLINK_ROUTE, deadline)?,
        })
    }

    /// Create the fixed ingress veth with its peer born directly in the worker namespace.
    pub(crate) fn create_client_ingress_veth(
        &mut self,
        client_runtime_id: [u8; 16],
        target_namespace: RawFd,
        deadline: HardDeadline,
    ) -> Result<LiveClientIngressVeth, KernelError> {
        let (parent_name, worker_name) = client_ingress_interface_names(client_runtime_id)?;
        if target_namespace < 0 {
            return Err(KernelError::Invalid);
        }
        match self.route.link_index(&parent_name, deadline) {
            Err(error) if error.is_errno(libc::ENODEV) => {}
            Ok(_) => return Err(KernelError::Invalid),
            Err(error) => return Err(error),
        }
        let payload =
            encode_create_client_ingress_veth(&parent_name, &worker_name, target_namespace)?;
        self.route
            .request_ack(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &payload, deadline)?;
        let owner = LiveClientIngressVeth {
            parent_name,
            worker_name,
        };
        let configured = (|| {
            let details = self.route.link_details_full(&owner.parent_name, deadline)?;
            if details.name.as_deref() != Some(owner.parent_name.as_str())
                || details.kind.as_deref() != Some(VETH_LINK_KIND)
            {
                return Err(KernelError::Invalid);
            }
            self.route.add_raw_address(
                details.index,
                &CLIENT_INGRESS_PARENT_ADDRESS,
                30,
                deadline,
            )?;
            self.route.add_ipv6_address_without_dad(
                details.index,
                &CLIENT_INGRESS_PARENT_IPV6_ADDRESS,
                126,
                deadline,
            )?;
            self.route.set_link_state(details.index, true, deadline)
        })();
        if let Err(error) = configured {
            let _ = self.delete_client_ingress_veth(&owner, deadline);
            return Err(error);
        }
        Ok(owner)
    }

    /// Delete only the exact parent endpoint; deleting either veth endpoint retires the pair.
    pub(crate) fn delete_client_ingress_veth(
        &mut self,
        owner: &LiveClientIngressVeth,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let details = match self.route.link_details_full(&owner.parent_name, deadline) {
            Ok(details) => details,
            Err(error) if error.is_errno(libc::ENODEV) => return Ok(()),
            Err(error) => return Err(error),
        };
        if details.name.as_deref() != Some(owner.parent_name.as_str())
            || details.kind.as_deref() != Some(VETH_LINK_KIND)
        {
            return Err(KernelError::Invalid);
        }
        self.route
            .delete_owned_link(details.index, &owner.parent_name, deadline)?;
        self.route.prove_link_absent(&owner.parent_name, deadline)
    }

    pub(crate) fn install_client_ingress_parent_routing(
        &mut self,
        owner: &LiveClientIngressVeth,
        trusted_agent_uid: u32,
        deadline: HardDeadline,
    ) -> Result<ClientIngressParentIpv4Routing, KernelError> {
        let initial_rules = encode_client_ingress_initial_rules(trusted_agent_uid)?;
        let mut routing = self.install_client_ingress_parent_marked_routing(owner, deadline)?;
        for rule in initial_rules {
            if let Err(error) =
                self.route
                    .request_ack(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, &rule, deadline)
            {
                // Only positively installed predecessors belong to this owner. In particular,
                // an EEXIST rule must never be included in our cleanup prefix.
                let _ = self.remove_client_ingress_parent_routing(&routing, deadline);
                return Err(error);
            }
            routing.initial_rules.push(rule);
        }
        Ok(routing)
    }

    #[cfg(test)]
    pub(crate) fn install_client_ingress_root_smoke_routing(
        &mut self,
        owner: &LiveClientIngressVeth,
        deadline: HardDeadline,
    ) -> Result<ClientIngressParentIpv4Routing, KernelError> {
        // The disposable smoke maps only UID0, which is intentionally excluded from initial
        // application steering. It still proves the existing marked root-payload path.
        self.install_client_ingress_parent_marked_routing(owner, deadline)
    }

    fn install_client_ingress_parent_marked_routing(
        &mut self,
        owner: &LiveClientIngressVeth,
        deadline: HardDeadline,
    ) -> Result<ClientIngressParentIpv4Routing, KernelError> {
        let details = self.route.link_details_full(&owner.parent_name, deadline)?;
        if details.name.as_deref() != Some(owner.parent_name.as_str())
            || details.kind.as_deref() != Some(VETH_LINK_KIND)
        {
            return Err(KernelError::Invalid);
        }
        let loopback_ifindex = self.route.link_index("lo", deadline)?;
        let ipv4_route =
            encode_client_ingress_parent_route(details.index, ClientIngressFamily::Ipv4)?;
        self.route.request_ack(
            RTM_NEWROUTE,
            NLM_F_CREATE | NLM_F_EXCL,
            &ipv4_route,
            deadline,
        )?;
        let ipv6_route =
            encode_client_ingress_parent_route(details.index, ClientIngressFamily::Ipv6)?;
        if let Err(error) = self.route.request_ack(
            RTM_NEWROUTE,
            NLM_F_CREATE | NLM_F_EXCL,
            &ipv6_route,
            deadline,
        ) {
            let _ = self
                .route
                .request_ack(RTM_DELROUTE, 0, &ipv4_route, deadline);
            return Err(error);
        }
        let ipv4_rule = encode_client_ingress_parent_rule(ClientIngressFamily::Ipv4)?;
        if let Err(error) =
            self.route
                .request_ack(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, &ipv4_rule, deadline)
        {
            let _ = self
                .route
                .request_ack(RTM_DELROUTE, 0, &ipv6_route, deadline);
            let _ = self
                .route
                .request_ack(RTM_DELROUTE, 0, &ipv4_route, deadline);
            return Err(error);
        }
        let ipv6_rule = encode_client_ingress_parent_rule(ClientIngressFamily::Ipv6)?;
        if let Err(error) =
            self.route
                .request_ack(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, &ipv6_rule, deadline)
        {
            let _ = self.route.request_ack(RTM_DELRULE, 0, &ipv4_rule, deadline);
            let _ = self
                .route
                .request_ack(RTM_DELROUTE, 0, &ipv6_route, deadline);
            let _ = self
                .route
                .request_ack(RTM_DELROUTE, 0, &ipv4_route, deadline);
            return Err(error);
        }
        Ok(ClientIngressParentIpv4Routing {
            parent_ifindex: details.index,
            loopback_ifindex,
            initial_rules: Vec::with_capacity(4),
        })
    }

    pub(crate) fn remove_client_ingress_parent_routing(
        &mut self,
        routing: &ClientIngressParentIpv4Routing,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let mut initial_result = Ok(());
        for rule in routing.initial_rules.iter().rev() {
            let result = self.route.request_ack(RTM_DELRULE, 0, rule, deadline);
            initial_result = initial_result.and(result);
        }
        let ipv6_rule = encode_client_ingress_parent_rule(ClientIngressFamily::Ipv6)?;
        let ipv6_rule_result = self.route.request_ack(RTM_DELRULE, 0, &ipv6_rule, deadline);
        let ipv4_rule = encode_client_ingress_parent_rule(ClientIngressFamily::Ipv4)?;
        let ipv4_rule_result = self.route.request_ack(RTM_DELRULE, 0, &ipv4_rule, deadline);
        let ipv6_route =
            encode_client_ingress_parent_route(routing.parent_ifindex, ClientIngressFamily::Ipv6)?;
        let ipv6_route_result = self
            .route
            .request_ack(RTM_DELROUTE, 0, &ipv6_route, deadline);
        let ipv4_route =
            encode_client_ingress_parent_route(routing.parent_ifindex, ClientIngressFamily::Ipv4)?;
        let ipv4_route_result = self
            .route
            .request_ack(RTM_DELROUTE, 0, &ipv4_route, deadline);
        initial_result
            .and(ipv6_rule_result)
            .and(ipv4_rule_result)
            .and(ipv6_route_result)
            .and(ipv4_route_result)
    }

    /// Create a `WireGuard` device here and then move it by target namespace fd.
    pub(crate) fn create_and_move_wireguard(
        &mut self,
        ownership: &mut LiveWireguardLeaseOwner,
        target_namespace: RawFd,
        deadline: HardDeadline,
    ) -> Result<(), BirthLinkError> {
        if ownership.birth != LiveBirthLinkState::Uncreated {
            return Err(BirthLinkError::CleanupIncomplete);
        }
        let interface = ownership.resource().interface().to_owned();
        if validate_durable_wireguard_resource(ownership.resource()).is_err()
            || target_namespace < 0
        {
            return Err(BirthLinkError::Kernel(KernelError::Invalid));
        }
        let progress_deadline = deadline
            .before_tail(BIRTH_LINK_PROGRESS_TAIL)
            .map_err(KernelError::Io)
            .map_err(BirthLinkError::Kernel)?;
        let reconcile_deadline = deadline
            .before_tail(BIRTH_LINK_RECONCILE_TAIL)
            .map_err(KernelError::Io)
            .map_err(BirthLinkError::Kernel)?;
        let requested_index =
            requested_birth_ifindex(ownership.resource()).map_err(BirthLinkError::Kernel)?;
        match self.route.link_index(&interface, progress_deadline) {
            Ok(_) => return Err(BirthLinkError::Conflict),
            Err(error) if error.is_errno(libc::ENODEV) => {}
            Err(error) => return Err(BirthLinkError::Kernel(error)),
        }
        match self
            .route
            .link_details_by_index(requested_index, progress_deadline)
        {
            Ok(_) => return Err(BirthLinkError::Conflict),
            Err(error) if error.is_errno(libc::ENODEV) => {}
            Err(error) => return Err(BirthLinkError::Kernel(error)),
        }

        let provisional = self.begin_wireguard_birth(
            ownership,
            requested_index,
            progress_deadline,
            reconcile_deadline,
            deadline,
        )?;
        let marked = self.mark_wireguard_birth(
            ownership,
            &provisional,
            progress_deadline,
            reconcile_deadline,
            deadline,
        )?;
        self.move_marked_wireguard_birth(
            ownership,
            &marked,
            target_namespace,
            progress_deadline,
            deadline,
        )
    }

    fn begin_wireguard_birth(
        &mut self,
        ownership: &mut LiveWireguardLeaseOwner,
        requested_index: u32,
        progress_deadline: HardDeadline,
        reconcile_deadline: HardDeadline,
        cleanup_deadline: HardDeadline,
    ) -> Result<ProvisionalWireguardBirthLink, BirthLinkError> {
        let pending = self
            .route
            .send_create_wireguard_link(ownership.resource(), requested_index, progress_deadline)
            .map_err(BirthLinkError::Kernel)?;
        ownership
            .transition_birth(
                LiveBirthLinkState::Uncreated,
                LiveBirthLinkState::CreateSent(requested_index),
            )
            .map_err(|_| BirthLinkError::CleanupIncomplete)?;
        match self
            .route
            .observe_mutation_ack(&pending, progress_deadline, reconcile_deadline)
        {
            ObservedMutationAcknowledgement::Timely => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::CreateSent(requested_index),
                        LiveBirthLinkState::CreateAcknowledged(requested_index),
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
            }
            ObservedMutationAcknowledgement::Late(error) => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::CreateSent(requested_index),
                        LiveBirthLinkState::CreateAcknowledged(requested_index),
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                return Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline));
            }
            ObservedMutationAcknowledgement::Rejected(error) => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::CreateSent(requested_index),
                        LiveBirthLinkState::Uncreated,
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                return if error.is_errno(libc::EEXIST) || error.is_errno(libc::EBUSY) {
                    Err(BirthLinkError::Conflict)
                } else {
                    Err(BirthLinkError::Kernel(error))
                };
            }
            ObservedMutationAcknowledgement::Ambiguous(error) => {
                return Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline));
            }
        }

        match self.route.provisional_created_wireguard_link(
            ownership.resource(),
            requested_index,
            progress_deadline,
        ) {
            Ok(provisional) => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::CreateAcknowledged(provisional.index),
                        LiveBirthLinkState::Provisional(provisional.index),
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                Ok(provisional)
            }
            Err(error) => Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline)),
        }
    }

    fn mark_wireguard_birth(
        &mut self,
        ownership: &mut LiveWireguardLeaseOwner,
        provisional: &ProvisionalWireguardBirthLink,
        progress_deadline: HardDeadline,
        reconcile_deadline: HardDeadline,
        cleanup_deadline: HardDeadline,
    ) -> Result<MarkedWireguardBirthLink, BirthLinkError> {
        let pending = match self.route.send_set_link_alias(
            provisional.index,
            ownership.resource().ownership_alias(),
            progress_deadline,
        ) {
            Ok(pending) => pending,
            Err(error) => {
                return Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline));
            }
        };
        ownership
            .transition_birth(
                LiveBirthLinkState::Provisional(provisional.index),
                LiveBirthLinkState::AliasSent(provisional.index),
            )
            .map_err(|_| BirthLinkError::CleanupIncomplete)?;
        match self
            .route
            .observe_mutation_ack(&pending, progress_deadline, reconcile_deadline)
        {
            ObservedMutationAcknowledgement::Timely => {}
            ObservedMutationAcknowledgement::Rejected(error) => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::AliasSent(provisional.index),
                        LiveBirthLinkState::Provisional(provisional.index),
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                return Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline));
            }
            ObservedMutationAcknowledgement::Late(error)
            | ObservedMutationAcknowledgement::Ambiguous(error) => {
                return Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline));
            }
        }
        match self.route.marked_wireguard_birth_link(
            ownership.resource(),
            provisional,
            progress_deadline,
        ) {
            Ok(marked) => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::AliasSent(marked.index),
                        LiveBirthLinkState::Marked(marked.index),
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                Ok(marked)
            }
            Err(error) => Err(self.reconcile_birth_failure(ownership, error, cleanup_deadline)),
        }
    }

    fn move_marked_wireguard_birth(
        &mut self,
        ownership: &mut LiveWireguardLeaseOwner,
        marked: &MarkedWireguardBirthLink,
        target_namespace: RawFd,
        progress_deadline: HardDeadline,
        cleanup_deadline: HardDeadline,
    ) -> Result<(), BirthLinkError> {
        match self
            .route
            .move_link_to_namespace(marked.index, target_namespace, progress_deadline)
        {
            Ok(()) => {
                ownership
                    .transition_birth(
                        LiveBirthLinkState::Marked(marked.index),
                        LiveBirthLinkState::Moved,
                    )
                    .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                Ok(())
            }
            Err(move_error) => match self
                .route
                .link_details_by_index(marked.index, cleanup_deadline)
            {
                Err(error) if error.is_errno(libc::ENODEV) => {
                    ownership
                        .transition_birth(
                            LiveBirthLinkState::Marked(marked.index),
                            LiveBirthLinkState::Moved,
                        )
                        .map_err(|_| BirthLinkError::CleanupIncomplete)?;
                    Ok(())
                }
                Ok(details) => {
                    if prove_marked_wireguard_birth_link(ownership.resource(), marked, &details)
                        .is_ok()
                    {
                        Err(self.reconcile_birth_failure(ownership, move_error, cleanup_deadline))
                    } else {
                        Err(BirthLinkError::CleanupIncomplete)
                    }
                }
                Err(_) => Err(BirthLinkError::CleanupIncomplete),
            },
        }
    }

    fn reconcile_birth_failure(
        &mut self,
        ownership: &mut LiveWireguardLeaseOwner,
        error: KernelError,
        cleanup_deadline: HardDeadline,
    ) -> BirthLinkError {
        if self
            .delete_owned_wireguard(ownership, cleanup_deadline)
            .is_ok()
        {
            BirthLinkError::Kernel(error)
        } else {
            BirthLinkError::CleanupIncomplete
        }
    }

    /// Delete a same-runtime process-owned link only when exact name, marker and kind match.
    ///
    /// The live owner is not crash-recovery authority; durable restart cleanup remains a separate
    /// journal-authorized path.
    pub(crate) fn delete_owned_wireguard(
        &mut self,
        ownership: &mut LiveWireguardLeaseOwner,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let result = match birth_cleanup_target(ownership.birth) {
            BirthCleanupTarget::ProveAbsent => self
                .route
                .prove_link_absent(ownership.resource().interface(), deadline),
            BirthCleanupTarget::Unmarked(index) => self.route.cleanup_provisional_wireguard_link(
                ownership.resource(),
                &ProvisionalWireguardBirthLink { index },
                deadline,
            ),
            BirthCleanupTarget::AliasMayBeSet(index) => {
                self.route.cleanup_alias_sent_wireguard_link(
                    ownership.resource(),
                    &ProvisionalWireguardBirthLink { index },
                    deadline,
                )
            }
            BirthCleanupTarget::Marked(index) => self.route.cleanup_marked_wireguard_link(
                ownership.resource(),
                &MarkedWireguardBirthLink { index },
                deadline,
            ),
        };
        if result.is_ok() {
            ownership.birth = LiveBirthLinkState::Uncreated;
        }
        result
    }
}

fn prove_exact_owned_wireguard_link(
    resource: &DurableWireguardResource,
    details: &LinkDetails,
) -> Result<(), KernelError> {
    validate_durable_wireguard_resource(resource)?;
    if details.name.as_deref() != Some(resource.interface())
        || details.alias.as_deref() != Some(resource.ownership_alias())
        || details.kind.as_deref() != Some(WG_GENL_NAME)
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn prove_provisional_wireguard_birth_link(
    resource: &DurableWireguardResource,
    details: &LinkDetails,
) -> Result<(), KernelError> {
    validate_durable_wireguard_resource(resource)?;
    let up = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
    if details.name.as_deref() != Some(resource.interface())
        || details.alias.is_some()
        || details.kind.as_deref() != Some(WG_GENL_NAME)
        || details.flags & up != 0
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn prove_cleanup_eligible_provisional_wireguard_birth_link(
    resource: &DurableWireguardResource,
    provisional: &ProvisionalWireguardBirthLink,
    details: &LinkDetails,
) -> Result<(), KernelError> {
    validate_durable_wireguard_resource(resource)?;
    let up = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
    if details.index != provisional.index
        || details.name.as_deref() != Some(resource.interface())
        || details.alias.is_some()
        || details.kind.as_deref() != Some(WG_GENL_NAME)
        || details.flags & up != 0
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn prove_cleanup_eligible_alias_sent_wireguard_birth_link(
    resource: &DurableWireguardResource,
    provisional: &ProvisionalWireguardBirthLink,
    details: &LinkDetails,
) -> Result<(), KernelError> {
    validate_durable_wireguard_resource(resource)?;
    let up = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
    let marker_is_transactional =
        details.alias.is_none() || details.alias.as_deref() == Some(resource.ownership_alias());
    if details.index != provisional.index
        || details.name.as_deref() != Some(resource.interface())
        || !marker_is_transactional
        || details.kind.as_deref() != Some(WG_GENL_NAME)
        || details.flags & up != 0
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn prove_marked_wireguard_birth_link(
    resource: &DurableWireguardResource,
    marked: &MarkedWireguardBirthLink,
    details: &LinkDetails,
) -> Result<(), KernelError> {
    prove_exact_owned_wireguard_link(resource, details)?;
    let up = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
    if details.index != marked.index || details.flags & up != 0 {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn validate_durable_wireguard_resource(
    resource: &DurableWireguardResource,
) -> Result<(), KernelError> {
    if !valid_string_field(resource.interface(), MAX_IFNAME_BYTES)
        || !valid_string_field(resource.ownership_alias(), MAX_IFALIAS_BYTES)
        || !valid_string_field(WG_GENL_NAME, MAX_LINK_KIND_BYTES)
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn requested_birth_ifindex(resource: &DurableWireguardResource) -> Result<u32, KernelError> {
    validate_durable_wireguard_resource(resource)?;
    let digest = blake3::hash(resource.ownership_alias().as_bytes());
    let prefix = u32::from_be_bytes(
        digest.as_bytes()[..4]
            .try_into()
            .map_err(|_| KernelError::Invalid)?,
    );
    Ok(BIRTH_LINK_IFINDEX_PREFIX | (prefix & BIRTH_LINK_IFINDEX_MASK))
}

fn valid_string_field(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.is_ascii()
        && !value.as_bytes().contains(&0)
}

fn prove_fresh_wireguard_state(
    expected_name: &str,
    details: &LinkDetails,
    state: &WireguardDeviceState,
) -> Result<(), KernelError> {
    let up = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
    if details.flags & up != 0
        || state.ifindex != details.index
        || state.interface_name != expected_name
        || state.public_key != [0; 32]
        || state.listen_port != 0
        || state.firewall_mark != 0
        || !state.peers.is_empty()
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

/// Exact kernel evidence returned only after a v3 no-peer device is UP and read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedWireguardKernelProof {
    pub(crate) ifindex: u32,
    pub(crate) public_key: [u8; 32],
    pub(crate) listen_port: u16,
    pub(crate) local_overlay_address: IpAddr,
}

/// Exact peer state accepted by the v3 worker after signed public activation data is validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireguardV3PeerConfiguration {
    pub(crate) public_key: [u8; 32],
    pub(crate) endpoint: InternetSocketAddr,
    pub(crate) allowed_address: Ipv6Addr,
    pub(crate) allowed_prefix_length: u8,
    pub(crate) persistent_keepalive_seconds: u16,
}

/// Counters and handshake evidence from one exact correlated v3 GET.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireguardV3PeerProof {
    pub(crate) latest_handshake_unix: u64,
    pub(crate) latest_handshake_nanoseconds: u32,
    pub(crate) received_bytes: u64,
    pub(crate) transmitted_bytes: u64,
}

/// Namespace-local kernel client. Construct only after `CLONE_NEWNET` succeeds.
pub struct NamespaceKernel {
    route: NetlinkClient,
    wireguard: Option<GenericNetlinkClient>,
}

/// Exact namespace-local policy routing owned by one client-ingress worker.
pub(crate) struct ClientIngressIpv4Routing {
    loopback_index: u32,
    ingress_ifindex: u32,
}

fn restart_wireguard_roles(
    context_role: volparossa_routing::ContextRole,
) -> Result<&'static [WireguardRole], KernelError> {
    match context_role {
        volparossa_routing::ContextRole::Client => Ok(&[WireguardRole::Client]),
        volparossa_routing::ContextRole::Relay => {
            Ok(&[WireguardRole::RelayClient, WireguardRole::RelayExit])
        }
        volparossa_routing::ContextRole::Exit => Ok(&[WireguardRole::Exit]),
        volparossa_routing::ContextRole::Unspecified => Err(KernelError::Invalid),
    }
}

impl NamespaceKernel {
    /// Opens namespace-local route and `WireGuard` netlink sockets.
    pub fn connect(deadline: HardDeadline) -> Result<Self, KernelError> {
        let route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let wireguard = match GenericNetlinkClient::connect(WG_GENL_NAME, deadline) {
            Ok(wireguard) => Some(wireguard),
            Err(error) if error.is_errno(libc::ENOENT) || error.is_errno(libc::EOPNOTSUPP) => None,
            Err(error) => return Err(error),
        };
        deadline.ensure_remaining()?;
        Ok(Self { route, wireguard })
    }

    /// Activates only the loopback link in the newly isolated namespace.
    pub fn activate_loopback(&mut self, deadline: HardDeadline) -> Result<(), KernelError> {
        let index = self.route.link_index("lo", deadline)?;
        self.route.set_link_state(index, true, deadline)
    }

    /// Bring up and address only the worker endpoint derived from this client runtime.
    pub(crate) fn activate_client_ingress_link(
        &mut self,
        client_runtime_id: [u8; 16],
        deadline: HardDeadline,
    ) -> Result<u32, KernelError> {
        let (_, worker_name) = client_ingress_interface_names(client_runtime_id)?;
        let details = self.route.link_details_full(&worker_name, deadline)?;
        if details.name.as_deref() != Some(worker_name.as_str())
            || details.kind.as_deref() != Some(VETH_LINK_KIND)
        {
            return Err(KernelError::Invalid);
        }
        self.route
            .add_raw_address(details.index, &CLIENT_INGRESS_WORKER_ADDRESS, 30, deadline)?;
        self.route.add_ipv6_address_without_dad(
            details.index,
            &CLIENT_INGRESS_WORKER_IPV6_ADDRESS,
            126,
            deadline,
        )?;
        self.route.set_link_state(details.index, true, deadline)?;
        Ok(details.index)
    }

    /// Install the fixed dual-stack fwmark rules, local routes and return routes for TPROXY.
    pub(crate) fn install_client_ingress_routing(
        &mut self,
        ingress_ifindex: u32,
        deadline: HardDeadline,
    ) -> Result<ClientIngressIpv4Routing, KernelError> {
        if ingress_ifindex == 0 {
            return Err(KernelError::Invalid);
        }
        let loopback_index = self.route.link_index("lo", deadline)?;
        let routes = [
            encode_client_ingress_worker_return_route(ingress_ifindex, ClientIngressFamily::Ipv4)?,
            encode_client_ingress_worker_return_route(ingress_ifindex, ClientIngressFamily::Ipv6)?,
            encode_client_ingress_local_route(loopback_index, ClientIngressFamily::Ipv4)?,
            encode_client_ingress_local_route(loopback_index, ClientIngressFamily::Ipv6)?,
        ];
        for (installed_routes, route) in routes.iter().enumerate() {
            if let Err(error) =
                self.route
                    .request_ack(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, route, deadline)
            {
                for installed in routes[..installed_routes].iter().rev() {
                    let _ = self.route.request_ack(RTM_DELROUTE, 0, installed, deadline);
                }
                return Err(error);
            }
        }
        let rules = [
            encode_client_ingress_rule(ClientIngressFamily::Ipv4)?,
            encode_client_ingress_rule(ClientIngressFamily::Ipv6)?,
        ];
        for (installed_rules, rule) in rules.iter().enumerate() {
            if let Err(error) =
                self.route
                    .request_ack(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, rule, deadline)
            {
                for installed in rules[..installed_rules].iter().rev() {
                    let _ = self.route.request_ack(RTM_DELRULE, 0, installed, deadline);
                }
                for installed in routes.iter().rev() {
                    let _ = self.route.request_ack(RTM_DELROUTE, 0, installed, deadline);
                }
                return Err(error);
            }
        }
        Ok(ClientIngressIpv4Routing {
            loopback_index,
            ingress_ifindex,
        })
    }

    /// Remove the exact fwmark rule and local route while attempting both cleanup steps.
    #[allow(clippy::needless_pass_by_value)] // Consuming the token records affine teardown.
    pub(crate) fn remove_client_ingress_routing(
        &mut self,
        routing: ClientIngressIpv4Routing,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let operations = [
            (
                RTM_DELRULE,
                encode_client_ingress_rule(ClientIngressFamily::Ipv6)?,
            ),
            (
                RTM_DELRULE,
                encode_client_ingress_rule(ClientIngressFamily::Ipv4)?,
            ),
            (
                RTM_DELROUTE,
                encode_client_ingress_local_route(
                    routing.loopback_index,
                    ClientIngressFamily::Ipv6,
                )?,
            ),
            (
                RTM_DELROUTE,
                encode_client_ingress_local_route(
                    routing.loopback_index,
                    ClientIngressFamily::Ipv4,
                )?,
            ),
            (
                RTM_DELROUTE,
                encode_client_ingress_worker_return_route(
                    routing.ingress_ifindex,
                    ClientIngressFamily::Ipv6,
                )?,
            ),
            (
                RTM_DELROUTE,
                encode_client_ingress_worker_return_route(
                    routing.ingress_ifindex,
                    ClientIngressFamily::Ipv4,
                )?,
            ),
        ];
        let mut result = Ok(());
        for (operation, payload) in operations {
            let removed = self.route.request_ack(operation, 0, &payload, deadline);
            if result.is_ok() {
                result = removed;
            }
        }
        result
    }

    /// Prove the exact pre-dispatch link facts committed by one startup journal target.
    ///
    /// Custody is durably marked before dispatch can create a birth link or activate loopback.
    /// This read-only check re-derives every role-specific interface name internally, requires all
    /// of them absent, and requires the sole bootstrap loopback identity to remain down and
    /// unlabelled. It accepts no caller-provided interface name.
    pub(crate) fn prove_restart_pre_dispatch_links_absent(
        &mut self,
        plan: RestartNetworkPlan,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let roles = restart_wireguard_roles(plan.context_role())?;
        if plan.path_id() == 0 {
            return Err(KernelError::Invalid);
        }
        for role in roles {
            let specification = WireguardLeaseSpec::derive(
                plan.context_id(),
                plan.context_role(),
                u32::from(plan.path_id()),
                *role as i32,
            )
            .map_err(|_| KernelError::Invalid)?;
            self.route
                .prove_link_absent(specification.interface(), deadline)?;
        }
        let loopback = self.route.link_details_full("lo", deadline)?;
        let up = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
        if loopback.name.as_deref() != Some("lo")
            || loopback.alias.is_some()
            || loopback.flags & up != 0
        {
            return Err(KernelError::Invalid);
        }
        deadline.ensure_remaining()?;
        Ok(())
    }

    /// Read back one helper-derived `WireGuard` device through a bounded `GET_DEVICE` dump.
    ///
    /// The result proves only kernel key, port and peer configuration. It does not prove that a
    /// public IP is locally assigned or reachable.
    #[allow(dead_code)] // Phase-1 readback foundation; no v2 caller may use it.
    pub(crate) fn probe_wireguard_device(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<WireguardDeviceState, KernelError> {
        validate_durable_wireguard_resource(resource)?;
        let interface = resource.interface();
        let details = self
            .route
            .exact_owned_wireguard_link_details(resource, deadline)?;
        let wireguard = self.wireguard.as_mut().ok_or(KernelError::Unsupported)?;
        let state = wireguard_probe::probe_device(
            &mut wireguard.netlink,
            wireguard.family_id,
            interface,
            deadline,
        )?;
        if state.ifindex != details.index || state.interface_name != interface {
            return Err(KernelError::Malformed);
        }
        Ok(state)
    }

    /// Prove that every planned durable resource is an exact, freshly moved `WireGuard` link.
    ///
    /// The complete batch is inspected before callers perform any key, address, link-state, or
    /// listen-port mutation. Duplicate derived interfaces, an unavailable `WireGuard` family,
    /// an exact durable marker/kind mismatch, or any non-fresh device state fails closed. The
    /// marker is evidence derived from, not a substitute for, durable journal authority.
    pub(crate) fn preflight_exact_owned_wireguard_v3(
        &mut self,
        resources: &[DurableWireguardResource],
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        if resources.is_empty() {
            return Err(KernelError::Invalid);
        }
        if self.wireguard.is_none() {
            return Err(KernelError::Unsupported);
        }
        for (position, resource) in resources.iter().enumerate() {
            validate_durable_wireguard_resource(resource)?;
            let interface = resource.interface();
            if resources[..position]
                .iter()
                .any(|previous| previous.interface() == interface)
            {
                return Err(KernelError::Invalid);
            }
            let details = self
                .route
                .exact_owned_wireguard_link_details(resource, deadline)?;
            let wireguard = self.wireguard.as_mut().ok_or(KernelError::Unsupported)?;
            let state = wireguard_probe::probe_device(
                &mut wireguard.netlink,
                wireguard.family_id,
                interface,
                deadline,
            )?;
            prove_fresh_wireguard_state(interface, &details, &state)?;
        }
        deadline.ensure_remaining()?;
        Ok(())
    }

    /// Delete one namespace-local link only after exact durable name, alias, and kind proof.
    ///
    /// An already absent link is success. A link with the derived name but a different alias or
    /// kind is never deleted, and absence is proven again before success is returned. Production
    /// callers must additionally hold durable journal authority for this exact marker.
    pub(crate) fn delete_exact_owned_wireguard_v3(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        self.route
            .delete_named_exact_owned_wireguard_link(resource, deadline)
    }

    /// Prove that no link remains under one exact helper-derived interface name.
    pub(crate) fn prove_wireguard_absent_v3(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        validate_durable_wireguard_resource(resource)?;
        self.route.prove_link_absent(resource.interface(), deadline)
    }

    /// Configure one freshly moved v3 device with a worker-local key and no peers, bring it UP,
    /// and return only exact correlated kernel proof.
    ///
    /// The key container is zeroized by its worker owner. This API has no agent wire-message input
    /// and cannot encode a peer or caller-selected listen port.
    pub(crate) fn prepare_wireguard_v3(
        &mut self,
        resource: &DurableWireguardResource,
        private_key: &Zeroizing<[u8; 32]>,
        expected_public_key: [u8; 32],
        deadline: HardDeadline,
    ) -> Result<PreparedWireguardKernelProof, KernelError> {
        if private_key.iter().all(|byte| *byte == 0)
            || expected_public_key.iter().all(|byte| *byte == 0)
        {
            return Err(KernelError::Invalid);
        }
        validate_durable_wireguard_resource(resource)?;
        let interface = resource.interface();
        let index = self
            .route
            .exact_owned_wireguard_link_index(resource, deadline)?;
        let local = resource.local_address();
        self.route
            .add_raw_address(index, &local.octets(), 128, deadline)?;
        self.wireguard
            .as_mut()
            .ok_or(KernelError::Unsupported)?
            .prepare_key_no_peers_v3(resource, private_key, deadline)?;
        self.route.set_link_state(index, true, deadline)?;
        self.wireguard
            .as_mut()
            .ok_or(KernelError::Unsupported)?
            .set_ephemeral_listen_port_v3(resource, deadline)?;

        let proved = self
            .route
            .exact_owned_wireguard_link_details(resource, deadline)?;
        let up = proved.flags & u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)? != 0;
        if proved.index != index || !up {
            return Err(KernelError::Malformed);
        }
        let wireguard = self.wireguard.as_mut().ok_or(KernelError::Unsupported)?;
        let state = wireguard_probe::probe_device(
            &mut wireguard.netlink,
            wireguard.family_id,
            interface,
            deadline,
        )?;
        if state.ifindex != index
            || state.interface_name != interface
            || state.public_key != expected_public_key
            || state.listen_port == 0
            || state.firewall_mark != 0
            || !state.peers.is_empty()
        {
            return Err(KernelError::Malformed);
        }
        deadline.ensure_remaining()?;
        Ok(PreparedWireguardKernelProof {
            ifindex: index,
            public_key: state.public_key,
            listen_port: state.listen_port,
            local_overlay_address: IpAddr::V6(local),
        })
    }

    /// Replace the empty peer set with one exact, public-only v3 peer and prove the resulting GET.
    pub(crate) fn activate_wireguard_v3(
        &mut self,
        resource: &DurableWireguardResource,
        expected_device_public_key: [u8; 32],
        expected_listen_port: u16,
        peer: &WireguardV3PeerConfiguration,
        deadline: HardDeadline,
    ) -> Result<WireguardV3PeerProof, KernelError> {
        if expected_device_public_key.iter().all(|byte| *byte == 0)
            || expected_listen_port == 0
            || peer.allowed_address != resource.peer_address()
            || peer.allowed_prefix_length != 128
        {
            return Err(KernelError::Invalid);
        }
        validate_durable_wireguard_resource(resource)?;
        let index = self
            .route
            .exact_owned_wireguard_link_details(resource, deadline)?;
        let wireguard = self.wireguard.as_mut().ok_or(KernelError::Unsupported)?;
        wireguard.activate_device_v3(resource, peer, deadline)?;
        self.route
            .add_exact_main_ipv6_link_route(index.index, peer.allowed_address, deadline)?;
        let proof = self.probe_wireguard_peer_v3(
            resource,
            expected_device_public_key,
            expected_listen_port,
            peer,
            deadline,
        )?;
        Ok(deadline.complete(proof)?)
    }

    /// Prove one exact peer, endpoint, allowed prefix and device identity with a bounded GET.
    pub(crate) fn probe_wireguard_peer_v3(
        &mut self,
        resource: &DurableWireguardResource,
        expected_device_public_key: [u8; 32],
        expected_listen_port: u16,
        peer: &WireguardV3PeerConfiguration,
        deadline: HardDeadline,
    ) -> Result<WireguardV3PeerProof, KernelError> {
        if expected_device_public_key.iter().all(|byte| *byte == 0)
            || expected_listen_port == 0
            || peer.public_key.iter().all(|byte| *byte == 0)
            || peer.allowed_address != resource.peer_address()
            || peer.allowed_prefix_length != 128
            || peer.endpoint.ip().is_unspecified()
            || peer.endpoint.ip().is_multicast()
            || peer.endpoint.port() == 0
        {
            return Err(KernelError::Invalid);
        }
        validate_durable_wireguard_resource(resource)?;
        let interface = resource.interface();
        let details = self
            .route
            .exact_owned_wireguard_link_details(resource, deadline)?;
        let index = details.index;
        let flags = details.flags;
        let up = flags & u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)? != 0;
        if !up {
            return Err(KernelError::Malformed);
        }
        let wireguard = self.wireguard.as_mut().ok_or(KernelError::Unsupported)?;
        let state = wireguard_probe::probe_device(
            &mut wireguard.netlink,
            wireguard.family_id,
            interface,
            deadline,
        )?;
        if state.ifindex != index
            || state.interface_name != interface
            || state.public_key != expected_device_public_key
            || state.listen_port != expected_listen_port
            || state.firewall_mark != wireguard_underlay_mark(resource)
        {
            return Err(KernelError::Malformed);
        }
        let proved_peer = state.single_peer()?;
        let expected_allowed = wireguard_probe::WireguardAllowedIp {
            address: IpAddr::V6(peer.allowed_address),
            prefix_length: peer.allowed_prefix_length,
        };
        if proved_peer.public_key != peer.public_key
            || proved_peer.endpoint != peer.endpoint
            || proved_peer.persistent_keepalive_seconds != peer.persistent_keepalive_seconds
            || proved_peer.allowed_ips.as_slice() != [expected_allowed]
            || proved_peer.protocol_version != Some(1)
        {
            return Err(KernelError::Malformed);
        }
        self.route
            .prove_exact_main_ipv6_link_route(index, peer.allowed_address, deadline)?;
        deadline.ensure_remaining()?;
        Ok(WireguardV3PeerProof {
            latest_handshake_unix: proved_peer.last_handshake_seconds,
            latest_handshake_nanoseconds: proved_peer.last_handshake_nanoseconds,
            received_bytes: proved_peer.received_bytes,
            transmitted_bytes: proved_peer.transmitted_bytes,
        })
    }

    /// Resolves the namespace-local index of one already validated helper-derived link.
    pub(crate) fn wireguard_if_index(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<u32, KernelError> {
        self.route
            .exact_owned_wireguard_link_index(resource, deadline)
    }
}

struct NetlinkReply {
    message: Zeroizing<Vec<u8>>,
    sender: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinkDetails {
    index: u32,
    name: Option<String>,
    alias: Option<String>,
    kind: Option<String>,
    flags: u32,
}

struct NetlinkClient {
    socket: Socket,
    local_port_id: u32,
    sequence: u32,
}

fn bound_unicast_port_id(address: SocketAddr) -> Result<u32, KernelError> {
    let port_id = address.port_number();
    if port_id == 0 || address.multicast_groups() != 0 {
        return Err(KernelError::Malformed);
    }
    Ok(port_id)
}

impl NetlinkClient {
    fn connect(protocol: isize, deadline: HardDeadline) -> Result<Self, KernelError> {
        deadline.ensure_remaining()?;
        let mut socket = Socket::new(protocol)?;
        deadline.ensure_remaining()?;
        socket.set_non_blocking(true)?;
        if protocol == NETLINK_GENERIC {
            deadline.ensure_remaining()?;
            match setsockopt(&socket, NetlinkCapAck, &true) {
                Ok(()) | Err(nix::errno::Errno::ENOPROTOOPT) => {}
                Err(error) => {
                    return Err(io::Error::from_raw_os_error(error as i32).into());
                }
            }
        }
        deadline.ensure_remaining()?;
        let local_port_id = bound_unicast_port_id(socket.bind_auto()?)?;
        deadline.ensure_remaining()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_remaining()?;
        Ok(Self {
            socket,
            local_port_id,
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> u32 {
        let current = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        current
    }

    fn request_ack(
        &mut self,
        message_type: u16,
        flags: u16,
        payload: &[u8],
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let sequence = self.next_sequence();
        let message = Zeroizing::new(build_netlink_message(
            message_type,
            flags | NLM_F_REQUEST | NLM_F_ACK,
            sequence,
            payload,
        )?);
        self.send(&message, deadline)?;
        let response = self.receive(deadline)?;
        let parsed = parse_ack(&response, sequence, message_type, self.local_port_id);
        deadline.ensure_remaining()?;
        parsed
    }

    fn request_reply(
        &mut self,
        message_type: u16,
        payload: &[u8],
        deadline: HardDeadline,
    ) -> Result<(NetlinkReply, u32), KernelError> {
        let sequence = self.next_sequence();
        let message = Zeroizing::new(build_netlink_message(
            message_type,
            NLM_F_REQUEST,
            sequence,
            payload,
        )?);
        self.send(&message, deadline)?;
        let response = self.receive(deadline)?;
        Ok((response, sequence))
    }

    fn send(&self, message: &[u8], deadline: HardDeadline) -> Result<(), KernelError> {
        loop {
            deadline.ensure_remaining()?;
            match self.socket.send(message, 0) {
                Ok(written) if written == message.len() => {
                    deadline.complete(())?;
                    return Ok(());
                }
                Ok(_) => {
                    return Err(KernelError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short netlink write",
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_for_fd(&self.socket, PollFlags::POLLOUT, deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn send_observed_request(
        &self,
        message: &[u8],
        progress_deadline: HardDeadline,
    ) -> Result<bool, KernelError> {
        loop {
            progress_deadline.ensure_remaining()?;
            match self.socket.send(message, 0) {
                Ok(written) if written == message.len() => {
                    return Ok(progress_deadline.ensure_remaining().is_ok());
                }
                Ok(_) => {
                    return Err(KernelError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short netlink datagram write",
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_for_fd(&self.socket, PollFlags::POLLOUT, progress_deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn receive(&self, deadline: HardDeadline) -> Result<NetlinkReply, KernelError> {
        let mut bytes = Zeroizing::new(vec![0_u8; MAX_NETLINK_MESSAGE]);
        loop {
            wait_for_fd(&self.socket, PollFlags::POLLIN, deadline)?;
            deadline.ensure_remaining()?;
            let (received, sender) = match self.socket.recv_from(&mut &mut bytes[..], 0) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            deadline.ensure_remaining()?;
            if !(NLMSG_HEADER_LEN..=MAX_NETLINK_MESSAGE).contains(&received) {
                return Err(KernelError::Malformed);
            }
            bytes.truncate(received);
            return Ok(NetlinkReply {
                message: bytes,
                sender,
            });
        }
    }

    fn send_create_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        requested_index: u32,
        progress_deadline: HardDeadline,
    ) -> Result<PendingMutationRequest, KernelError> {
        let (message_type, flags, payload) =
            encode_create_wireguard_link(resource, requested_index)?;
        self.send_mutation_request(message_type, flags, &payload, progress_deadline)
    }

    fn send_mutation_request(
        &mut self,
        message_type: u16,
        flags: u16,
        payload: &[u8],
        progress_deadline: HardDeadline,
    ) -> Result<PendingMutationRequest, KernelError> {
        let sequence = self.next_sequence();
        let message = Zeroizing::new(build_netlink_message(
            message_type,
            flags | NLM_F_REQUEST | NLM_F_ACK,
            sequence,
            payload,
        )?);
        let sent_before_progress_cutoff =
            self.send_observed_request(&message, progress_deadline)?;
        Ok(PendingMutationRequest {
            sequence,
            request_type: message_type,
            sent_before_progress_cutoff,
        })
    }

    fn observe_mutation_ack(
        &self,
        pending: &PendingMutationRequest,
        progress_deadline: HardDeadline,
        reconcile_deadline: HardDeadline,
    ) -> ObservedMutationAcknowledgement {
        let response = match self.receive(reconcile_deadline) {
            Ok(response) => response,
            Err(error) => return ObservedMutationAcknowledgement::Ambiguous(error),
        };
        let acknowledgement = parse_ack(
            &response,
            pending.sequence,
            pending.request_type,
            self.local_port_id,
        );
        classify_mutation_acknowledgement(
            acknowledgement,
            pending.sent_before_progress_cutoff && progress_deadline.ensure_remaining().is_ok(),
        )
    }

    fn provisional_created_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        requested_index: u32,
        deadline: HardDeadline,
    ) -> Result<ProvisionalWireguardBirthLink, KernelError> {
        let details = self.link_details_by_index(requested_index, deadline)?;
        prove_provisional_wireguard_birth_link(resource, &details)?;
        Ok(ProvisionalWireguardBirthLink {
            index: details.index,
        })
    }

    fn send_set_link_alias(
        &mut self,
        index: u32,
        alias: &str,
        progress_deadline: HardDeadline,
    ) -> Result<PendingMutationRequest, KernelError> {
        let (message_type, flags, payload) = encode_set_link_alias(index, alias)?;
        self.send_mutation_request(message_type, flags, &payload, progress_deadline)
    }

    fn marked_wireguard_birth_link(
        &mut self,
        resource: &DurableWireguardResource,
        provisional: &ProvisionalWireguardBirthLink,
        deadline: HardDeadline,
    ) -> Result<MarkedWireguardBirthLink, KernelError> {
        let details = self.link_details_by_index(provisional.index, deadline)?;
        let marked = MarkedWireguardBirthLink {
            index: provisional.index,
        };
        prove_marked_wireguard_birth_link(resource, &marked, &details)?;
        Ok(marked)
    }

    fn cleanup_provisional_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        provisional: &ProvisionalWireguardBirthLink,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let details = match self.link_details_by_index(provisional.index, deadline) {
            Ok(details) => details,
            Err(error) if error.is_errno(libc::ENODEV) => {
                return self.prove_link_absent(resource.interface(), deadline);
            }
            Err(error) => return Err(error),
        };
        prove_cleanup_eligible_provisional_wireguard_birth_link(resource, provisional, &details)?;
        self.delete_owned_link(details.index, resource.interface(), deadline)?;
        self.prove_deleted_birth_link_absent(provisional.index, resource.interface(), deadline)
    }

    fn cleanup_alias_sent_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        provisional: &ProvisionalWireguardBirthLink,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let details = match self.link_details_by_index(provisional.index, deadline) {
            Ok(details) => details,
            Err(error) if error.is_errno(libc::ENODEV) => {
                return self.prove_link_absent(resource.interface(), deadline);
            }
            Err(error) => return Err(error),
        };
        prove_cleanup_eligible_alias_sent_wireguard_birth_link(resource, provisional, &details)?;
        self.delete_owned_link(details.index, resource.interface(), deadline)?;
        self.prove_deleted_birth_link_absent(provisional.index, resource.interface(), deadline)
    }

    fn cleanup_marked_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        marked: &MarkedWireguardBirthLink,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let details = match self.link_details_by_index(marked.index, deadline) {
            Ok(details) => details,
            Err(error) if error.is_errno(libc::ENODEV) => {
                return self.prove_link_absent(resource.interface(), deadline);
            }
            Err(error) => return Err(error),
        };
        prove_marked_wireguard_birth_link(resource, marked, &details)?;
        self.delete_owned_link(details.index, resource.interface(), deadline)?;
        self.prove_deleted_birth_link_absent(marked.index, resource.interface(), deadline)
    }

    fn move_link_to_namespace(
        &mut self,
        index: u32,
        target_namespace: RawFd,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let (message_type, flags, payload) =
            encode_move_link_to_namespace(index, target_namespace)?;
        self.request_ack(message_type, flags, &payload, deadline)
    }

    fn delete_owned_link(
        &mut self,
        index: u32,
        name: &str,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let (message_type, flags, payload) = encode_delete_link(index)?;
        match self.request_ack(message_type, flags, &payload, deadline) {
            Ok(()) => Ok(()),
            Err(error) if error.is_errno(libc::ENODEV) || error.is_errno(libc::ENOENT) => Ok(()),
            Err(delete_error) => match self.link_index(name, deadline) {
                Err(error) if error.is_errno(libc::ENODEV) => Ok(()),
                Ok(_) | Err(_) => Err(delete_error),
            },
        }
    }

    fn delete_named_exact_owned_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let name = resource.interface();
        let index = match self.exact_owned_wireguard_link_index(resource, deadline) {
            Ok(index) => index,
            Err(error) if error.is_errno(libc::ENODEV) => return Ok(()),
            Err(error) => return Err(error),
        };
        self.delete_owned_link(index, name, deadline)?;
        self.prove_link_absent(name, deadline)
    }

    fn exact_owned_wireguard_link_index(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<u32, KernelError> {
        self.exact_owned_wireguard_link_details(resource, deadline)
            .map(|details| details.index)
    }

    fn exact_owned_wireguard_link_details(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<LinkDetails, KernelError> {
        validate_durable_wireguard_resource(resource)?;
        let details = self.link_details_full(resource.interface(), deadline)?;
        prove_exact_owned_wireguard_link(resource, &details)?;
        Ok(details)
    }

    fn prove_link_absent(&mut self, name: &str, deadline: HardDeadline) -> Result<(), KernelError> {
        match self.link_details_full(name, deadline) {
            Err(error) if error.is_errno(libc::ENODEV) => {
                deadline.ensure_remaining()?;
                Ok(())
            }
            Ok(_) => Err(KernelError::Invalid),
            Err(error) => Err(error),
        }
    }

    fn prove_link_index_absent(
        &mut self,
        index: u32,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        match self.link_details_by_index(index, deadline) {
            Err(error) if error.is_errno(libc::ENODEV) => {
                deadline.ensure_remaining()?;
                Ok(())
            }
            Ok(_) => Err(KernelError::Invalid),
            Err(error) => Err(error),
        }
    }

    fn prove_deleted_birth_link_absent(
        &mut self,
        index: u32,
        name: &str,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        self.prove_link_index_absent(index, deadline)?;
        self.prove_link_absent(name, deadline)
    }

    fn link_index(&mut self, name: &str, deadline: HardDeadline) -> Result<u32, KernelError> {
        self.link_details(name, deadline).map(|(index, _)| index)
    }

    fn link_details(
        &mut self,
        name: &str,
        deadline: HardDeadline,
    ) -> Result<(u32, Option<String>), KernelError> {
        let details = self.link_details_full(name, deadline)?;
        Ok((details.index, details.alias))
    }

    fn link_details_by_index(
        &mut self,
        index: u32,
        deadline: HardDeadline,
    ) -> Result<LinkDetails, KernelError> {
        if index == 0 || index > i32::MAX as u32 {
            return Err(KernelError::Invalid);
        }
        let payload = interface_info(index, 0, 0)?;
        let (response, sequence) = self.request_reply(RTM_GETLINK, &payload, deadline)?;
        validate_kernel_sender(&response.sender)?;
        let response_frames = frames(&response.message)?;
        if response_frames.len() != 1 {
            return Err(KernelError::Malformed);
        }
        let frame = response_frames[0];
        if read_u16(frame, 4) == Some(NLMSG_ERROR) {
            parse_ack(&response, sequence, RTM_GETLINK, self.local_port_id)?;
            return Err(KernelError::Malformed);
        }
        validate_kernel_header(frame, sequence, RTM_NEWLINK, self.local_port_id)?;
        let details = parse_link_details_frame(frame)?;
        if details.index != index {
            return Err(KernelError::Malformed);
        }
        deadline.ensure_remaining()?;
        Ok(details)
    }

    fn link_details_full(
        &mut self,
        name: &str,
        deadline: HardDeadline,
    ) -> Result<LinkDetails, KernelError> {
        let mut payload = interface_info(0, 0, 0)?;
        push_string_attribute(&mut payload, IFLA_IFNAME, name)?;
        let (response, sequence) = self.request_reply(RTM_GETLINK, &payload, deadline)?;
        validate_kernel_sender(&response.sender)?;
        let response_frames = frames(&response.message)?;
        if response_frames.len() != 1 {
            return Err(KernelError::Malformed);
        }
        let frame = response_frames[0];
        if read_u16(frame, 4) == Some(NLMSG_ERROR) {
            parse_ack(&response, sequence, RTM_GETLINK, self.local_port_id)?;
            return Err(KernelError::Malformed);
        }
        validate_kernel_header(frame, sequence, RTM_NEWLINK, self.local_port_id)?;
        let details = parse_link_details_frame(frame)?;
        if details.name.as_deref() != Some(name) {
            return Err(KernelError::Malformed);
        }
        deadline.ensure_remaining()?;
        Ok(details)
    }

    fn set_link_state(
        &mut self,
        index: u32,
        up: bool,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let flag = u32::try_from(libc::IFF_UP).map_err(|_| KernelError::Invalid)?;
        let flags = if up { flag } else { 0 };
        let payload = interface_info(index, flags, flag)?;
        self.request_ack(RTM_NEWLINK, 0, &payload, deadline)
    }

    fn add_raw_address(
        &mut self,
        index: u32,
        address: &[u8],
        prefix_length: u8,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let family = match (address.len(), prefix_length) {
            (4, 0..=32) => u8::try_from(libc::AF_INET).map_err(|_| KernelError::Invalid)?,
            (16, 0..=128) => u8::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?,
            _ => return Err(KernelError::Invalid),
        };
        self.add_raw_address_for_family(index, family, address, prefix_length, 0, deadline)
    }

    fn add_ipv6_address_without_dad(
        &mut self,
        index: u32,
        address: &[u8; 16],
        prefix_length: u8,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let family = u8::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?;
        let flags = u8::try_from(libc::IFA_F_NODAD).map_err(|_| KernelError::Invalid)?;
        self.add_raw_address_for_family(index, family, address, prefix_length, flags, deadline)
    }

    fn add_raw_address_for_family(
        &mut self,
        index: u32,
        family: u8,
        address: &[u8],
        prefix_length: u8,
        flags: u8,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        if index == 0 {
            return Err(KernelError::Invalid);
        }
        let mut payload = Vec::with_capacity(64);
        payload.push(family);
        payload.push(prefix_length);
        payload.push(flags);
        payload.push(0);
        payload.extend_from_slice(&index.to_ne_bytes());
        push_attribute(&mut payload, IFA_ADDRESS, address)?;
        push_attribute(&mut payload, IFA_LOCAL, address)?;
        self.request_ack(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &payload, deadline)
    }

    fn add_exact_main_ipv6_link_route(
        &mut self,
        index: u32,
        destination: Ipv6Addr,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let payload = encode_exact_main_ipv6_link_route(index, destination)?;
        self.request_ack(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &payload, deadline)
    }

    fn prove_exact_main_ipv6_link_route(
        &mut self,
        index: u32,
        destination: Ipv6Addr,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let payload = encode_exact_main_ipv6_link_route_query(index, destination)?;
        let (response, sequence) = self.request_reply(RTM_GETROUTE, &payload, deadline)?;
        parse_exact_main_ipv6_link_route_reply(
            &response,
            sequence,
            self.local_port_id,
            index,
            destination,
        )?;
        Ok(deadline.complete(())?)
    }
}

fn parse_exact_main_ipv6_link_route_reply(
    reply: &NetlinkReply,
    expected_sequence: u32,
    local_port_id: u32,
    index: u32,
    destination: Ipv6Addr,
) -> Result<(), KernelError> {
    validate_kernel_sender(&reply.sender)?;
    let response_frames = frames(&reply.message)?;
    if response_frames.len() != 1 {
        return Err(KernelError::Malformed);
    }
    let frame = response_frames[0];
    if read_u16(frame, 4) == Some(NLMSG_ERROR) {
        parse_ack(reply, expected_sequence, RTM_GETROUTE, local_port_id)?;
        return Err(KernelError::Malformed);
    }
    validate_kernel_header(frame, expected_sequence, RTM_NEWROUTE, local_port_id)?;
    parse_exact_main_ipv6_link_route(frame, index, destination)
}

fn encode_exact_main_ipv6_link_route(
    index: u32,
    destination: Ipv6Addr,
) -> Result<Vec<u8>, KernelError> {
    if index == 0 || destination.is_unspecified() || destination.is_multicast() {
        return Err(KernelError::Invalid);
    }
    let mut payload = Vec::with_capacity(48);
    payload.push(u8::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?);
    payload.push(128);
    payload.push(0);
    payload.push(0);
    payload.push(RT_TABLE_MAIN);
    payload.push(RTPROT_STATIC);
    payload.push(RT_SCOPE_LINK);
    payload.push(RTN_UNICAST);
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    push_attribute(&mut payload, RTA_DST, &destination.octets())?;
    push_attribute(&mut payload, RTA_OIF, &index.to_ne_bytes())?;
    push_attribute(
        &mut payload,
        RTA_PRIORITY,
        &IPV6_USER_ROUTE_PRIORITY.to_ne_bytes(),
    )?;
    Ok(payload)
}

fn client_ingress_kernel_family(family: ClientIngressFamily) -> Result<u8, KernelError> {
    u8::try_from(match family {
        ClientIngressFamily::Ipv4 => libc::AF_INET,
        ClientIngressFamily::Ipv6 => libc::AF_INET6,
    })
    .map_err(|_| KernelError::Invalid)
}

const fn client_ingress_mark(family: ClientIngressFamily) -> u32 {
    match family {
        ClientIngressFamily::Ipv4 => CLIENT_INGRESS_IPV4_MARK,
        ClientIngressFamily::Ipv6 => CLIENT_INGRESS_IPV6_MARK,
    }
}

const fn client_ingress_parent_mark(family: ClientIngressFamily) -> u32 {
    match family {
        ClientIngressFamily::Ipv4 => CLIENT_INGRESS_PARENT_IPV4_MARK,
        ClientIngressFamily::Ipv6 => CLIENT_INGRESS_PARENT_IPV6_MARK,
    }
}

fn encode_client_ingress_local_route(
    loopback_index: u32,
    family: ClientIngressFamily,
) -> Result<Vec<u8>, KernelError> {
    if loopback_index == 0 {
        return Err(KernelError::Invalid);
    }
    let mut payload = Vec::with_capacity(40);
    payload.push(client_ingress_kernel_family(family)?);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.push(CLIENT_INGRESS_ROUTE_TABLE);
    payload.push(RTPROT_STATIC);
    payload.push(RT_SCOPE_HOST);
    payload.push(RTN_LOCAL);
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    push_attribute(
        &mut payload,
        RTA_TABLE,
        &u32::from(CLIENT_INGRESS_ROUTE_TABLE).to_ne_bytes(),
    )?;
    push_attribute(&mut payload, RTA_OIF, &loopback_index.to_ne_bytes())?;
    Ok(payload)
}

fn encode_client_ingress_rule(family: ClientIngressFamily) -> Result<Vec<u8>, KernelError> {
    let mut payload = Vec::with_capacity(48);
    payload.push(client_ingress_kernel_family(family)?);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.push(CLIENT_INGRESS_ROUTE_TABLE);
    payload.extend_from_slice(&[0, 0]);
    payload.push(FR_ACT_TO_TBL);
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    if payload.len() != FIB_RULE_HDR_LEN {
        return Err(KernelError::Invalid);
    }
    push_attribute(
        &mut payload,
        FRA_PRIORITY,
        &CLIENT_INGRESS_RULE_PRIORITY.to_ne_bytes(),
    )?;
    push_attribute(
        &mut payload,
        FRA_FWMARK,
        &client_ingress_mark(family).to_ne_bytes(),
    )?;
    push_attribute(&mut payload, FRA_FWMASK, &u32::MAX.to_ne_bytes())?;
    push_attribute(
        &mut payload,
        FRA_TABLE,
        &u32::from(CLIENT_INGRESS_ROUTE_TABLE).to_ne_bytes(),
    )?;
    Ok(payload)
}

fn encode_client_ingress_worker_return_route(
    ingress_ifindex: u32,
    family: ClientIngressFamily,
) -> Result<Vec<u8>, KernelError> {
    if ingress_ifindex == 0 {
        return Err(KernelError::Invalid);
    }
    let mut payload = Vec::with_capacity(40);
    payload.push(client_ingress_kernel_family(family)?);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.push(RT_TABLE_MAIN);
    payload.push(RTPROT_STATIC);
    payload.push(RT_SCOPE_UNIVERSE);
    payload.push(RTN_UNICAST);
    payload.extend_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
    push_attribute(&mut payload, RTA_OIF, &ingress_ifindex.to_ne_bytes())?;
    let gateway: &[u8] = match family {
        ClientIngressFamily::Ipv4 => &CLIENT_INGRESS_PARENT_ADDRESS,
        ClientIngressFamily::Ipv6 => &CLIENT_INGRESS_PARENT_IPV6_ADDRESS,
    };
    push_attribute(&mut payload, RTA_GATEWAY, gateway)?;
    Ok(payload)
}

fn encode_client_ingress_parent_route(
    parent_ifindex: u32,
    family: ClientIngressFamily,
) -> Result<Vec<u8>, KernelError> {
    if parent_ifindex == 0 {
        return Err(KernelError::Invalid);
    }
    let mut payload = Vec::with_capacity(48);
    payload.push(client_ingress_kernel_family(family)?);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.push(CLIENT_INGRESS_PARENT_ROUTE_TABLE);
    payload.push(RTPROT_STATIC);
    payload.push(RT_SCOPE_UNIVERSE);
    payload.push(RTN_UNICAST);
    payload.extend_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
    push_attribute(
        &mut payload,
        RTA_TABLE,
        &u32::from(CLIENT_INGRESS_PARENT_ROUTE_TABLE).to_ne_bytes(),
    )?;
    push_attribute(&mut payload, RTA_OIF, &parent_ifindex.to_ne_bytes())?;
    let gateway: &[u8] = match family {
        ClientIngressFamily::Ipv4 => &CLIENT_INGRESS_WORKER_ADDRESS,
        ClientIngressFamily::Ipv6 => &CLIENT_INGRESS_WORKER_IPV6_ADDRESS,
    };
    push_attribute(&mut payload, RTA_GATEWAY, gateway)?;
    Ok(payload)
}

fn encode_client_ingress_parent_rule(family: ClientIngressFamily) -> Result<Vec<u8>, KernelError> {
    let mut payload = Vec::with_capacity(48);
    payload.push(client_ingress_kernel_family(family)?);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.push(CLIENT_INGRESS_PARENT_ROUTE_TABLE);
    payload.extend_from_slice(&[0, 0]);
    payload.push(FR_ACT_TO_TBL);
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    if payload.len() != FIB_RULE_HDR_LEN {
        return Err(KernelError::Invalid);
    }
    push_attribute(
        &mut payload,
        FRA_PRIORITY,
        &CLIENT_INGRESS_PARENT_RULE_PRIORITY.to_ne_bytes(),
    )?;
    push_attribute(
        &mut payload,
        FRA_FWMARK,
        &client_ingress_parent_mark(family).to_ne_bytes(),
    )?;
    push_attribute(&mut payload, FRA_FWMASK, &u32::MAX.to_ne_bytes())?;
    push_attribute(
        &mut payload,
        FRA_TABLE,
        &u32::from(CLIENT_INGRESS_PARENT_ROUTE_TABLE).to_ne_bytes(),
    )?;
    Ok(payload)
}

fn encode_client_ingress_initial_rules(
    trusted_agent_uid: u32,
) -> Result<Vec<Vec<u8>>, KernelError> {
    if trusted_agent_uid == 0 || trusted_agent_uid == u32::MAX {
        return Err(KernelError::Invalid);
    }
    let mut rules = Vec::with_capacity(4);
    // Root/helper route observations stay physical. The permanent agent UID owns discovery
    // and Exit payload sockets. INVALID_UID is not a valid kernel uid-range endpoint.
    for (offset, start, end) in [
        (0, 1, trusted_agent_uid - 1),
        (1, trusted_agent_uid + 1, u32::MAX - 1),
    ] {
        if start > end {
            continue;
        }
        for family in [ClientIngressFamily::Ipv4, ClientIngressFamily::Ipv6] {
            let mut payload = Vec::with_capacity(80);
            payload.push(client_ingress_kernel_family(family)?);
            payload.extend_from_slice(&[0, 0, 0]);
            payload.push(CLIENT_INGRESS_PARENT_ROUTE_TABLE);
            payload.extend_from_slice(&[0, 0]);
            payload.push(FR_ACT_TO_TBL);
            payload.extend_from_slice(&0_u32.to_ne_bytes());
            push_attribute(
                &mut payload,
                FRA_PRIORITY,
                &(CLIENT_INGRESS_INITIAL_RULE_PRIORITY + offset).to_ne_bytes(),
            )?;
            // Only locally generated, initially unmarked application traffic may use this
            // route. Forwarded traffic and every WireGuard bypass mark retain their lookup.
            push_attribute(&mut payload, FRA_IIFNAME, b"lo\0")?;
            push_attribute(&mut payload, FRA_FWMARK, &0_u32.to_ne_bytes())?;
            push_attribute(&mut payload, FRA_FWMASK, &u32::MAX.to_ne_bytes())?;
            let mut range = [0_u8; 8];
            range[..4].copy_from_slice(&start.to_ne_bytes());
            range[4..].copy_from_slice(&end.to_ne_bytes());
            push_attribute(&mut payload, FRA_UID_RANGE, &range)?;
            push_attribute(
                &mut payload,
                FRA_TABLE,
                &u32::from(CLIENT_INGRESS_PARENT_ROUTE_TABLE).to_ne_bytes(),
            )?;
            rules.push(payload);
        }
    }
    Ok(rules)
}

fn encode_exact_main_ipv6_link_route_query(
    index: u32,
    destination: Ipv6Addr,
) -> Result<Vec<u8>, KernelError> {
    if index == 0 || destination.is_unspecified() || destination.is_multicast() {
        return Err(KernelError::Invalid);
    }
    let mut payload = Vec::with_capacity(48);
    payload.push(u8::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?);
    payload.push(128);
    payload.extend_from_slice(&[0; 6]);
    payload.extend_from_slice(&RTM_F_FIB_MATCH.to_ne_bytes());
    push_attribute(&mut payload, RTA_DST, &destination.octets())?;
    push_attribute(&mut payload, RTA_OIF, &index.to_ne_bytes())?;
    Ok(payload)
}

fn parse_exact_main_ipv6_link_route(
    frame: &[u8],
    expected_index: u32,
    expected_destination: Ipv6Addr,
) -> Result<(), KernelError> {
    let payload = frame
        .get(NLMSG_HEADER_LEN..)
        .filter(|payload| payload.len() >= RTMSG_LEN)
        .ok_or(KernelError::Malformed)?;
    let expected_family = u8::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?;
    if expected_index == 0
        || expected_destination.is_unspecified()
        || expected_destination.is_multicast()
        || payload[0] != expected_family
        || payload[1] != 128
        || payload[2] != 0
        || payload[3] != 0
        || payload[4] != RT_TABLE_MAIN
        || payload[5] != RTPROT_STATIC
        || payload[6] != RT_SCOPE_UNIVERSE
        || payload[7] != RTN_UNICAST
        || read_u32(payload, 8) != Some(0)
    {
        return Err(KernelError::Malformed);
    }

    let mut destination = None;
    let mut output_index = None;
    let mut table = None;
    let mut priority = None;
    let mut cacheinfo_seen = false;
    let mut preference = None;
    for (raw_kind, value) in attributes(&payload[RTMSG_LEN..])? {
        if raw_kind != raw_kind & NLA_TYPE_MASK {
            return Err(KernelError::Malformed);
        }
        match raw_kind {
            RTA_DST => {
                if destination.is_some() || value.len() != 16 {
                    return Err(KernelError::Malformed);
                }
                destination = Some(Ipv6Addr::from(
                    <[u8; 16]>::try_from(value).map_err(|_| KernelError::Malformed)?,
                ));
            }
            RTA_OIF => {
                if output_index.is_some() || value.len() != 4 {
                    return Err(KernelError::Malformed);
                }
                output_index = read_u32(value, 0);
            }
            RTA_TABLE => {
                if table.is_some() || value.len() != 4 {
                    return Err(KernelError::Malformed);
                }
                table = read_u32(value, 0);
            }
            RTA_PRIORITY => {
                if priority.is_some() || value.len() != 4 {
                    return Err(KernelError::Malformed);
                }
                priority = read_u32(value, 0);
            }
            RTA_CACHEINFO => {
                if cacheinfo_seen
                    || value.len() != RTA_CACHEINFO_LEN
                    || value.iter().any(|byte| *byte != 0)
                {
                    return Err(KernelError::Malformed);
                }
                cacheinfo_seen = true;
            }
            RTA_PREF => {
                if preference.replace(value).is_some() || value != [IPV6_ROUTER_PREF_MEDIUM] {
                    return Err(KernelError::Malformed);
                }
            }
            RTA_GATEWAY | RTA_PREFSRC | RTA_MULTIPATH => return Err(KernelError::Invalid),
            _ => return Err(KernelError::Malformed),
        }
    }
    if destination != Some(expected_destination)
        || output_index != Some(expected_index)
        || table != Some(u32::from(RT_TABLE_MAIN))
        || priority != Some(IPV6_USER_ROUTE_PRIORITY)
        || !cacheinfo_seen
        || preference != Some([IPV6_ROUTER_PREF_MEDIUM].as_slice())
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn encode_create_wireguard_link(
    resource: &DurableWireguardResource,
    requested_index: u32,
) -> Result<(u16, u16, Vec<u8>), KernelError> {
    validate_durable_wireguard_resource(resource)?;
    if requested_index == 0 || requested_index > i32::MAX as u32 {
        return Err(KernelError::Invalid);
    }
    let mut link_info = Vec::with_capacity(32);
    push_bounded_string_attribute(
        &mut link_info,
        IFLA_INFO_KIND,
        WG_GENL_NAME,
        MAX_LINK_KIND_BYTES,
    )?;
    let mut link_attributes = Vec::with_capacity(64);
    push_bounded_string_attribute(
        &mut link_attributes,
        IFLA_IFNAME,
        resource.interface(),
        MAX_IFNAME_BYTES,
    )?;
    push_attribute(
        &mut link_attributes,
        IFLA_LINKINFO | NLA_F_NESTED,
        &link_info,
    )?;
    let mut payload = interface_info(requested_index, 0, 0)?;
    payload.extend_from_slice(&link_attributes);
    Ok((RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, payload))
}

pub(crate) fn client_ingress_interface_names(
    client_runtime_id: [u8; 16],
) -> Result<(String, String), KernelError> {
    if client_runtime_id.iter().all(|byte| *byte == 0) {
        return Err(KernelError::Invalid);
    }
    let mut suffix = String::with_capacity(8);
    for byte in &client_runtime_id[..4] {
        suffix.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        suffix.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    let parent = format!("vpih{suffix}");
    let worker = format!("vpiw{suffix}");
    if !valid_string_field(&parent, MAX_IFNAME_BYTES)
        || !valid_string_field(&worker, MAX_IFNAME_BYTES)
        || parent == worker
    {
        return Err(KernelError::Invalid);
    }
    Ok((parent, worker))
}

fn encode_create_client_ingress_veth(
    parent_name: &str,
    worker_name: &str,
    target_namespace: RawFd,
) -> Result<Vec<u8>, KernelError> {
    if target_namespace < 0
        || !valid_string_field(parent_name, MAX_IFNAME_BYTES)
        || !valid_string_field(worker_name, MAX_IFNAME_BYTES)
        || parent_name == worker_name
    {
        return Err(KernelError::Invalid);
    }
    let mut peer = interface_info(0, 0, 0)?;
    push_bounded_string_attribute(&mut peer, IFLA_IFNAME, worker_name, MAX_IFNAME_BYTES)?;
    push_attribute(&mut peer, IFLA_MTU, &CLIENT_INGRESS_MTU.to_ne_bytes())?;
    push_attribute(&mut peer, IFLA_NET_NS_FD, &target_namespace.to_ne_bytes())?;
    let mut data = Vec::with_capacity(peer.len() + 8);
    push_attribute(&mut data, VETH_INFO_PEER | NLA_F_NESTED, &peer)?;
    let mut link_info = Vec::with_capacity(data.len() + 32);
    push_bounded_string_attribute(
        &mut link_info,
        IFLA_INFO_KIND,
        VETH_LINK_KIND,
        MAX_LINK_KIND_BYTES,
    )?;
    push_attribute(&mut link_info, IFLA_INFO_DATA | NLA_F_NESTED, &data)?;
    let mut payload = interface_info(0, 0, 0)?;
    push_bounded_string_attribute(&mut payload, IFLA_IFNAME, parent_name, MAX_IFNAME_BYTES)?;
    push_attribute(&mut payload, IFLA_MTU, &CLIENT_INGRESS_MTU.to_ne_bytes())?;
    push_attribute(&mut payload, IFLA_LINKINFO | NLA_F_NESTED, &link_info)?;
    Ok(payload)
}

fn encode_set_link_alias(index: u32, alias: &str) -> Result<(u16, u16, Vec<u8>), KernelError> {
    if index == 0 || index > i32::MAX as u32 || !valid_string_field(alias, MAX_IFALIAS_BYTES) {
        return Err(KernelError::Invalid);
    }
    let mut payload = interface_info(index, 0, 0)?;
    // IFLA_IFALIAS is NLA_BINARY on SET so that an empty value can remove it. Match iproute2 and
    // send the bounded alias bytes without a trailing NUL; GET replies use nla_put_string instead.
    push_attribute(&mut payload, IFLA_IFALIAS, alias.as_bytes())?;
    Ok((RTM_SETLINK, 0, payload))
}

fn encode_move_link_to_namespace(
    index: u32,
    target_namespace: RawFd,
) -> Result<(u16, u16, Vec<u8>), KernelError> {
    if index == 0 || index > i32::MAX as u32 || target_namespace < 0 {
        return Err(KernelError::Invalid);
    }
    let mut payload = interface_info(index, 0, 0)?;
    push_attribute(
        &mut payload,
        IFLA_NET_NS_FD,
        &target_namespace.to_ne_bytes(),
    )?;
    push_attribute(&mut payload, IFLA_NEW_IFINDEX, &index.to_ne_bytes())?;
    Ok((RTM_NEWLINK, 0, payload))
}

fn encode_delete_link(index: u32) -> Result<(u16, u16, Vec<u8>), KernelError> {
    if index == 0 || index > i32::MAX as u32 {
        return Err(KernelError::Invalid);
    }
    Ok((RTM_DELLINK, 0, interface_info(index, 0, 0)?))
}

struct GenericNetlinkClient {
    netlink: NetlinkClient,
    family_id: u16,
}

impl GenericNetlinkClient {
    fn connect(family_name: &str, deadline: HardDeadline) -> Result<Self, KernelError> {
        let mut netlink = NetlinkClient::connect(NETLINK_GENERIC, deadline)?;
        let family_id = resolve_generic_family(&mut netlink, family_name, deadline)?;
        Ok(Self { netlink, family_id })
    }

    fn prepare_key_no_peers_v3(
        &mut self,
        resource: &DurableWireguardResource,
        private_key: &Zeroizing<[u8; 32]>,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let payload = encode_prepare_key_no_peers_v3(resource, private_key)?;
        self.netlink
            .request_ack(self.family_id, 0, &payload, deadline)
    }

    fn set_ephemeral_listen_port_v3(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let payload = encode_set_ephemeral_listen_port_v3(resource)?;
        self.netlink
            .request_ack(self.family_id, 0, &payload, deadline)
    }

    fn activate_device_v3(
        &mut self,
        resource: &DurableWireguardResource,
        peer: &WireguardV3PeerConfiguration,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let payload = encode_activate_device_v3(resource, peer)?;
        self.netlink
            .request_ack(self.family_id, 0, &payload, deadline)
    }
}

fn encode_activate_device_v3(
    resource: &DurableWireguardResource,
    peer: &WireguardV3PeerConfiguration,
) -> Result<Zeroizing<Vec<u8>>, KernelError> {
    validate_durable_wireguard_resource(resource)?;
    if peer.public_key.iter().all(|byte| *byte == 0)
        || peer.allowed_address != resource.peer_address()
        || peer.allowed_prefix_length != 128
        || peer.endpoint.ip().is_unspecified()
        || peer.endpoint.ip().is_multicast()
        || peer.endpoint.port() == 0
    {
        return Err(KernelError::Invalid);
    }
    let mut peer_attributes = Zeroizing::new(Vec::with_capacity(256));
    push_attribute(&mut peer_attributes, WGPEER_A_PUBLIC_KEY, &peer.public_key)?;
    push_attribute(
        &mut peer_attributes,
        WGPEER_A_FLAGS,
        &WGPEER_F_REPLACE_ALLOWEDIPS.to_ne_bytes(),
    )?;
    push_attribute(
        &mut peer_attributes,
        WGPEER_A_ENDPOINT,
        &encode_socket_endpoint(peer.endpoint)?,
    )?;
    push_attribute(
        &mut peer_attributes,
        WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
        &peer.persistent_keepalive_seconds.to_ne_bytes(),
    )?;
    let mut allowed = Zeroizing::new(Vec::with_capacity(64));
    let mut allowed_entry = Zeroizing::new(Vec::with_capacity(48));
    let family = u16::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?;
    push_attribute(
        &mut allowed_entry,
        WGALLOWEDIP_A_FAMILY,
        &family.to_ne_bytes(),
    )?;
    push_attribute(
        &mut allowed_entry,
        WGALLOWEDIP_A_IPADDR,
        &peer.allowed_address.octets(),
    )?;
    push_attribute(
        &mut allowed_entry,
        WGALLOWEDIP_A_CIDR_MASK,
        &[peer.allowed_prefix_length],
    )?;
    push_attribute(&mut allowed, 1 | NLA_F_NESTED, &allowed_entry)?;
    push_attribute(
        &mut peer_attributes,
        WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
        &allowed,
    )?;
    let mut peers = Zeroizing::new(Vec::with_capacity(peer_attributes.len() + 8));
    push_attribute(&mut peers, 1 | NLA_F_NESTED, &peer_attributes)?;
    let mut device = Zeroizing::new(Vec::with_capacity(peers.len() + 64));
    push_string_attribute(&mut device, WGDEVICE_A_IFNAME, resource.interface())?;
    push_attribute(
        &mut device,
        WGDEVICE_A_FWMARK,
        &wireguard_underlay_mark(resource).to_ne_bytes(),
    )?;
    push_attribute(
        &mut device,
        WGDEVICE_A_FLAGS,
        &WGDEVICE_F_REPLACE_PEERS.to_ne_bytes(),
    )?;
    push_attribute(&mut device, WGDEVICE_A_PEERS | NLA_F_NESTED, &peers)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(device.len() + GENL_HEADER_LEN));
    payload.push(WG_CMD_SET_DEVICE);
    payload.push(WG_GENL_VERSION);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&device);
    Ok(payload)
}

/// All `WireGuard` outer packets originate in the kernel and therefore have no trusted agent
/// socket UID. The existing ingress mark bypasses parent output steering without selecting the
/// parent-to-ingress policy table. Relay/Exit packets need the same exemption when this node also
/// consumes the network; otherwise its own Client ingress recursively captures contribution.
fn wireguard_underlay_mark(resource: &DurableWireguardResource) -> u32 {
    match WireguardRole::try_from(resource.key().1) {
        Ok(WireguardRole::Client) => CLIENT_INGRESS_IPV4_MARK,
        Ok(WireguardRole::RelayClient | WireguardRole::RelayExit | WireguardRole::Exit) => {
            CONTRIBUTION_WIREGUARD_MARK
        }
        Ok(WireguardRole::Unspecified) | Err(_) => 0,
    }
}

fn encode_prepare_key_no_peers_v3(
    resource: &DurableWireguardResource,
    private_key: &Zeroizing<[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>, KernelError> {
    validate_durable_wireguard_resource(resource)?;
    if private_key.iter().all(|byte| *byte == 0) {
        return Err(KernelError::Invalid);
    }
    let mut device = Zeroizing::new(Vec::with_capacity(128));
    push_string_attribute(&mut device, WGDEVICE_A_IFNAME, resource.interface())?;
    push_attribute(&mut device, WGDEVICE_A_PRIVATE_KEY, private_key.as_slice())?;
    push_attribute(
        &mut device,
        WGDEVICE_A_FLAGS,
        &WGDEVICE_F_REPLACE_PEERS.to_ne_bytes(),
    )?;
    let mut payload = Zeroizing::new(Vec::with_capacity(device.len() + GENL_HEADER_LEN));
    payload.push(WG_CMD_SET_DEVICE);
    payload.push(WG_GENL_VERSION);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&device);
    Ok(payload)
}
fn encode_set_ephemeral_listen_port_v3(
    resource: &DurableWireguardResource,
) -> Result<Zeroizing<Vec<u8>>, KernelError> {
    validate_durable_wireguard_resource(resource)?;
    let mut device = Zeroizing::new(Vec::with_capacity(64));
    push_string_attribute(&mut device, WGDEVICE_A_IFNAME, resource.interface())?;
    push_attribute(&mut device, WGDEVICE_A_LISTEN_PORT, &0_u16.to_ne_bytes())?;
    let mut payload = Zeroizing::new(Vec::with_capacity(device.len() + GENL_HEADER_LEN));
    payload.push(WG_CMD_SET_DEVICE);
    payload.push(WG_GENL_VERSION);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&device);
    Ok(payload)
}

fn resolve_generic_family(
    netlink: &mut NetlinkClient,
    family_name: &str,
    deadline: HardDeadline,
) -> Result<u16, KernelError> {
    if family_name.is_empty() || family_name.len() > 64 || family_name.as_bytes().contains(&0) {
        return Err(KernelError::Invalid);
    }
    let mut family_attributes = Vec::with_capacity(80);
    push_string_attribute(&mut family_attributes, CTRL_ATTR_FAMILY_NAME, family_name)?;
    let mut payload = Vec::with_capacity(family_attributes.len() + GENL_HEADER_LEN);
    payload.push(CTRL_CMD_GETFAMILY);
    payload.push(CTRL_VERSION);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&family_attributes);
    let (response, sequence) = netlink.request_reply(GENL_ID_CTRL, &payload, deadline)?;
    let family_id = parse_family_id(&response, sequence, netlink.local_port_id)?;
    deadline.ensure_remaining()?;
    Ok(family_id)
}

fn interface_info(index: u32, flags: u32, change: u32) -> Result<Vec<u8>, KernelError> {
    let mut payload = Vec::with_capacity(16);
    payload.push(u8::try_from(libc::AF_UNSPEC).map_err(|_| KernelError::Invalid)?);
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&index.to_ne_bytes());
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload.extend_from_slice(&change.to_ne_bytes());
    Ok(payload)
}

fn encode_socket_endpoint(endpoint: InternetSocketAddr) -> Result<Vec<u8>, KernelError> {
    match endpoint {
        InternetSocketAddr::V4(endpoint) => {
            let family = u16::try_from(libc::AF_INET).map_err(|_| KernelError::Invalid)?;
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&family.to_ne_bytes());
            bytes.extend_from_slice(&endpoint.port().to_be_bytes());
            bytes.extend_from_slice(&endpoint.ip().octets());
            bytes.extend_from_slice(&[0; 8]);
            Ok(bytes)
        }
        InternetSocketAddr::V6(endpoint)
            if endpoint.flowinfo() == 0 && endpoint.scope_id() == 0 =>
        {
            let family = u16::try_from(libc::AF_INET6).map_err(|_| KernelError::Invalid)?;
            let mut bytes = Vec::with_capacity(28);
            bytes.extend_from_slice(&family.to_ne_bytes());
            bytes.extend_from_slice(&endpoint.port().to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_ne_bytes());
            bytes.extend_from_slice(&endpoint.ip().octets());
            bytes.extend_from_slice(&0_u32.to_ne_bytes());
            Ok(bytes)
        }
        InternetSocketAddr::V6(_) => Err(KernelError::Invalid),
    }
}

fn build_netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, KernelError> {
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(KernelError::Invalid)?;
    if length > MAX_NETLINK_MESSAGE {
        return Err(KernelError::Invalid);
    }
    let length = u32::try_from(length).map_err(|_| KernelError::Invalid)?;
    let mut message = Vec::with_capacity(length as usize);
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn parse_string_attribute(value: &[u8], maximum_bytes: usize) -> Result<String, KernelError> {
    let bytes = value.strip_suffix(&[0]).ok_or(KernelError::Malformed)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes || bytes.contains(&0) || !bytes.is_ascii() {
        return Err(KernelError::Malformed);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| KernelError::Malformed)
}

fn parse_link_details_frame(frame: &[u8]) -> Result<LinkDetails, KernelError> {
    if frame.len() < NLMSG_HEADER_LEN + 16 {
        return Err(KernelError::Malformed);
    }
    let signed_index = i32::from_ne_bytes(
        frame[20..24]
            .try_into()
            .map_err(|_| KernelError::Malformed)?,
    );
    let index = u32::try_from(signed_index).map_err(|_| KernelError::Malformed)?;
    if index == 0 {
        return Err(KernelError::Malformed);
    }
    let flags = u32::from_ne_bytes(
        frame[24..28]
            .try_into()
            .map_err(|_| KernelError::Malformed)?,
    );
    let mut name = None;
    let mut alias = None;
    let mut kind = None;
    let mut link_info_seen = false;
    for (raw_kind, value) in attributes(&frame[NLMSG_HEADER_LEN + 16..])? {
        match raw_kind & NLA_TYPE_MASK {
            IFLA_IFNAME => {
                if raw_kind != IFLA_IFNAME || name.is_some() {
                    return Err(KernelError::Malformed);
                }
                name = Some(parse_string_attribute(value, MAX_IFNAME_BYTES)?);
            }
            IFLA_IFALIAS => {
                if raw_kind != IFLA_IFALIAS || alias.is_some() {
                    return Err(KernelError::Malformed);
                }
                alias = Some(parse_string_attribute(value, MAX_IFALIAS_BYTES)?);
            }
            IFLA_LINKINFO => {
                if (raw_kind != IFLA_LINKINFO && raw_kind != (IFLA_LINKINFO | NLA_F_NESTED))
                    || link_info_seen
                {
                    return Err(KernelError::Malformed);
                }
                link_info_seen = true;
                for (nested_kind, nested_value) in attributes(value)? {
                    if nested_kind & NLA_TYPE_MASK == IFLA_INFO_KIND {
                        if nested_kind != IFLA_INFO_KIND || kind.is_some() {
                            return Err(KernelError::Malformed);
                        }
                        kind = Some(parse_string_attribute(nested_value, MAX_LINK_KIND_BYTES)?);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(LinkDetails {
        index,
        name,
        alias,
        kind,
        flags,
    })
}

fn push_string_attribute(buffer: &mut Vec<u8>, kind: u16, value: &str) -> Result<(), KernelError> {
    push_bounded_string_attribute(buffer, kind, value, 64)
}

fn push_bounded_string_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), KernelError> {
    if !valid_string_field(value, maximum_bytes) {
        return Err(KernelError::Invalid);
    }
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    push_attribute(buffer, kind, &bytes)
}

fn push_attribute(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<(), KernelError> {
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(KernelError::Invalid)?;
    let length = u16::try_from(length).map_err(|_| KernelError::Invalid)?;
    buffer.extend_from_slice(&length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len()), 0);
    if buffer.len() > MAX_NETLINK_MESSAGE {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn frames(mut bytes: &[u8]) -> Result<Vec<&[u8]>, KernelError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < NLMSG_HEADER_LEN {
            return Err(KernelError::Malformed);
        }
        let length = usize::try_from(read_u32(bytes, 0).ok_or(KernelError::Malformed)?)
            .map_err(|_| KernelError::Malformed)?;
        if length < NLMSG_HEADER_LEN || length > bytes.len() {
            return Err(KernelError::Malformed);
        }
        result.push(&bytes[..length]);
        let aligned = align4(length);
        if aligned > bytes.len() {
            return Err(KernelError::Malformed);
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, KernelError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(KernelError::Malformed);
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        if length < ATTRIBUTE_HEADER_LEN || length > bytes.len() {
            return Err(KernelError::Malformed);
        }
        result.push((kind, &bytes[ATTRIBUTE_HEADER_LEN..length]));
        let aligned = align4(length);
        if aligned > bytes.len() {
            return Err(KernelError::Malformed);
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn parse_family_id(
    reply: &NetlinkReply,
    expected_sequence: u32,
    local_port_id: u32,
) -> Result<u16, KernelError> {
    validate_kernel_sender(&reply.sender)?;
    let response_frames = frames(&reply.message)?;
    if response_frames.len() != 1 {
        return Err(KernelError::Malformed);
    }
    let frame = response_frames[0];
    if read_u16(frame, 4) == Some(NLMSG_ERROR) {
        return match parse_ack(reply, expected_sequence, GENL_ID_CTRL, local_port_id) {
            Ok(()) => Err(KernelError::Unsupported),
            Err(error) if error.is_errno(libc::ENOENT) => Err(KernelError::Unsupported),
            Err(error) => Err(error),
        };
    }
    validate_kernel_header(frame, expected_sequence, GENL_ID_CTRL, local_port_id)?;
    if frame.len() < NLMSG_HEADER_LEN + GENL_HEADER_LEN
        || frame[NLMSG_HEADER_LEN] != CTRL_CMD_NEWFAMILY
        || frame[NLMSG_HEADER_LEN + 1] != CTRL_VERSION
    {
        return Err(KernelError::Malformed);
    }
    let mut family_id = None;
    for (kind, value) in attributes(&frame[NLMSG_HEADER_LEN + GENL_HEADER_LEN..])? {
        if kind & NLA_TYPE_MASK == CTRL_ATTR_FAMILY_ID {
            if value.len() != 2 || family_id.is_some() {
                return Err(KernelError::Malformed);
            }
            let value = u16::from_ne_bytes([value[0], value[1]]);
            if value == 0 {
                return Err(KernelError::Malformed);
            }
            family_id = Some(value);
        }
    }
    family_id.ok_or(KernelError::Unsupported)
}

fn parse_ack(
    reply: &NetlinkReply,
    expected_sequence: u32,
    expected_request_type: u16,
    local_port_id: u32,
) -> Result<(), KernelError> {
    validate_kernel_sender(&reply.sender)?;
    let response_frames = frames(&reply.message)?;
    if response_frames.len() != 1 {
        return Err(KernelError::Malformed);
    }
    let frame = response_frames[0];
    validate_kernel_header(frame, expected_sequence, NLMSG_ERROR, local_port_id)?;
    let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
    if frame.len() < embedded_offset + NLMSG_HEADER_LEN
        || read_u32(frame, embedded_offset)
            .is_none_or(|length| length < u32::try_from(NLMSG_HEADER_LEN).unwrap_or(u32::MAX))
        || read_u16(frame, embedded_offset + 4) != Some(expected_request_type)
        || read_u32(frame, embedded_offset + 8) != Some(expected_sequence)
        || read_u32(frame, embedded_offset + 12) != Some(0)
    {
        return Err(KernelError::Malformed);
    }
    let errno = read_i32(frame, NLMSG_HEADER_LEN).ok_or(KernelError::Malformed)?;
    if errno == 0 {
        return Ok(());
    }
    Err(KernelError::Errno(errno.saturating_abs()))
}

fn validate_kernel_sender(sender: &SocketAddr) -> Result<(), KernelError> {
    if *sender != SocketAddr::new(0, 0) {
        return Err(KernelError::Malformed);
    }
    Ok(())
}

fn validate_kernel_header(
    frame: &[u8],
    expected_sequence: u32,
    expected_type: u16,
    local_port_id: u32,
) -> Result<(), KernelError> {
    if local_port_id == 0
        || read_u16(frame, 4) != Some(expected_type)
        || read_u32(frame, 8) != Some(expected_sequence)
        || read_u32(frame, 12) != Some(local_port_id)
    {
        return Err(KernelError::Malformed);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(test)]
mod tests {
    use volparossa_routing::{ContextRole, WireguardRole};

    use super::*;
    use crate::ownership_journal::durable_wireguard_resource_for_test;

    const TEST_SEQUENCE: u32 = 7;
    const TEST_REQUEST_TYPE: u16 = 0x42;
    const TEST_FAMILY_ID: u16 = 0x43;
    const TEST_PORT_ID: u32 = 4_242;

    fn attribute<'a>(encoded: &'a [(u16, &'a [u8])], kind: u16) -> &'a [u8] {
        encoded
            .iter()
            .find_map(|(candidate, value)| ((*candidate & NLA_TYPE_MASK) == kind).then_some(*value))
            .expect("required attribute")
    }

    fn durable_resource(route_context_seed: u8, ownership_seed: u8) -> DurableWireguardResource {
        durable_wireguard_resource_for_test(
            [route_context_seed; 16],
            ContextRole::Client,
            1,
            WireguardRole::Client,
            ownership_seed,
        )
        .expect("durable WireGuard resource fixture")
    }

    #[test]
    fn client_ingress_initial_rules_cover_only_unmarked_local_unprivileged_applications() {
        let agent_uid = 987;
        let rules = encode_client_ingress_initial_rules(agent_uid).expect("initial rules");
        assert_eq!(rules.len(), 4);
        for family in [ClientIngressFamily::Ipv4, ClientIngressFamily::Ipv6] {
            let family = client_ingress_kernel_family(family).expect("kernel family");
            let family_rules = rules
                .iter()
                .filter(|rule| rule[0] == family)
                .collect::<Vec<_>>();
            assert_eq!(family_rules.len(), 2);
            for (offset, rule) in family_rules.iter().enumerate() {
                assert_eq!(rule[4], CLIENT_INGRESS_PARENT_ROUTE_TABLE);
                assert_eq!(rule[7], FR_ACT_TO_TBL);
                assert_eq!(&rule[8..12], &0_u32.to_ne_bytes());
                let attributes = attributes(&rule[FIB_RULE_HDR_LEN..]).expect("rule attributes");
                assert_eq!(attributes.len(), 6);
                assert_eq!(attribute(&attributes, FRA_IIFNAME), b"lo\0");
                assert_eq!(attribute(&attributes, FRA_FWMARK), 0_u32.to_ne_bytes());
                assert_eq!(attribute(&attributes, FRA_FWMASK), u32::MAX.to_ne_bytes());
                assert_eq!(
                    attribute(&attributes, FRA_PRIORITY),
                    (CLIENT_INGRESS_INITIAL_RULE_PRIORITY + u32::try_from(offset).unwrap())
                        .to_ne_bytes()
                );
                let priority =
                    u32::from_ne_bytes(attribute(&attributes, FRA_PRIORITY).try_into().unwrap());
                assert!(priority > 0 && priority < CLIENT_INGRESS_PARENT_RULE_PRIORITY);
                assert!(priority < 32_766);
                assert_eq!(
                    attribute(&attributes, FRA_TABLE),
                    u32::from(CLIENT_INGRESS_PARENT_ROUTE_TABLE).to_ne_bytes()
                );
                let range = attribute(&attributes, FRA_UID_RANGE);
                assert_eq!(range.len(), 8);
                let start = u32::from_ne_bytes(range[..4].try_into().unwrap());
                let end = u32::from_ne_bytes(range[4..].try_into().unwrap());
                assert_eq!(
                    (start, end),
                    if offset == 0 {
                        (1, agent_uid - 1)
                    } else {
                        (agent_uid + 1, u32::MAX - 1)
                    }
                );
                assert!(start > 0 && end < u32::MAX);
                assert!(!(start..=end).contains(&agent_uid));
            }
        }
    }

    #[test]
    fn client_ingress_initial_rules_reject_invalid_uids_and_skip_empty_ranges() {
        assert!(encode_client_ingress_initial_rules(0).is_err());
        assert!(encode_client_ingress_initial_rules(u32::MAX).is_err());
        assert_eq!(encode_client_ingress_initial_rules(1).unwrap().len(), 2);
        assert_eq!(
            encode_client_ingress_initial_rules(u32::MAX - 1)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn client_ingress_ipv6_routes_bind_exact_family_gateways_and_marks() {
        let local = encode_client_ingress_local_route(7, ClientIngressFamily::Ipv6)
            .expect("IPv6 local route");
        assert_eq!(local[0], u8::try_from(libc::AF_INET6).expect("AF_INET6"));
        assert_eq!(local[4], CLIENT_INGRESS_ROUTE_TABLE);
        assert_eq!(local[7], RTN_LOCAL);
        assert!(
            attributes(&local[RTMSG_LEN..])
                .expect("local route attributes")
                .iter()
                .any(|(kind, value)| *kind == RTA_OIF && *value == 7_u32.to_ne_bytes())
        );

        let worker_return = encode_client_ingress_worker_return_route(9, ClientIngressFamily::Ipv6)
            .expect("IPv6 worker return route");
        assert!(
            attributes(&worker_return[RTMSG_LEN..])
                .expect("worker return attributes")
                .iter()
                .any(|(kind, value)| {
                    *kind == RTA_GATEWAY && *value == CLIENT_INGRESS_PARENT_IPV6_ADDRESS
                })
        );

        let parent = encode_client_ingress_parent_route(11, ClientIngressFamily::Ipv6)
            .expect("IPv6 parent route");
        assert!(
            attributes(&parent[RTMSG_LEN..])
                .expect("parent route attributes")
                .iter()
                .any(|(kind, value)| {
                    *kind == RTA_GATEWAY && *value == CLIENT_INGRESS_WORKER_IPV6_ADDRESS
                })
        );

        let worker_rule =
            encode_client_ingress_rule(ClientIngressFamily::Ipv6).expect("IPv6 TPROXY rule");
        assert_eq!(
            worker_rule[0],
            u8::try_from(libc::AF_INET6).expect("AF_INET6")
        );
        assert!(
            attributes(&worker_rule[FIB_RULE_HDR_LEN..])
                .expect("worker rule attributes")
                .iter()
                .any(|(kind, value)| {
                    *kind == FRA_FWMARK && *value == CLIENT_INGRESS_IPV6_MARK.to_ne_bytes()
                })
        );

        let parent_rule =
            encode_client_ingress_parent_rule(ClientIngressFamily::Ipv6).expect("IPv6 parent rule");
        assert!(
            attributes(&parent_rule[FIB_RULE_HDR_LEN..])
                .expect("parent rule attributes")
                .iter()
                .any(|(kind, value)| {
                    *kind == FRA_FWMARK && *value == CLIENT_INGRESS_PARENT_IPV6_MARK.to_ne_bytes()
                })
        );
    }

    #[test]
    fn client_ingress_veth_caps_both_endpoints_at_ipv6_minimum_mtu() {
        let payload = encode_create_client_ingress_veth("vpih01020304", "vpiw01020304", 17)
            .expect("client ingress veth");
        let outer = attributes(&payload[16..]).expect("outer link attributes");
        assert_eq!(
            attribute(&outer, IFLA_MTU),
            CLIENT_INGRESS_MTU.to_ne_bytes()
        );

        let link_info =
            attributes(attribute(&outer, IFLA_LINKINFO)).expect("nested link-info attributes");
        let veth_data =
            attributes(attribute(&link_info, IFLA_INFO_DATA)).expect("nested veth attributes");
        let peer = attribute(&veth_data, VETH_INFO_PEER);
        let peer_attributes = attributes(&peer[16..]).expect("peer link attributes");
        assert_eq!(
            attribute(&peer_attributes, IFLA_MTU),
            CLIENT_INGRESS_MTU.to_ne_bytes()
        );
        assert_eq!(CLIENT_INGRESS_MTU, 1_280);
    }

    fn acknowledgement(errno: i32) -> NetlinkReply {
        let mut message = vec![0_u8; NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN + NLMSG_HEADER_LEN];
        let length = u32::try_from(message.len()).expect("small acknowledgement");
        message[0..4].copy_from_slice(&length.to_ne_bytes());
        message[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        message[8..12].copy_from_slice(&TEST_SEQUENCE.to_ne_bytes());
        message[12..16].copy_from_slice(&TEST_PORT_ID.to_ne_bytes());
        message[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN]
            .copy_from_slice(&errno.to_ne_bytes());
        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        let request_length =
            u32::try_from(NLMSG_HEADER_LEN + GENL_HEADER_LEN).expect("small request");
        message[embedded_offset..embedded_offset + 4]
            .copy_from_slice(&request_length.to_ne_bytes());
        message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&TEST_REQUEST_TYPE.to_ne_bytes());
        message[embedded_offset + 6..embedded_offset + 8]
            .copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        message[embedded_offset + 8..embedded_offset + 12]
            .copy_from_slice(&TEST_SEQUENCE.to_ne_bytes());
        NetlinkReply {
            message: Zeroizing::new(message),
            sender: SocketAddr::new(0, 0),
        }
    }

    fn family_reply() -> NetlinkReply {
        let mut family_attributes = Vec::new();
        push_attribute(
            &mut family_attributes,
            CTRL_ATTR_FAMILY_ID,
            &TEST_FAMILY_ID.to_ne_bytes(),
        )
        .expect("family ID");
        let mut payload = vec![CTRL_CMD_NEWFAMILY, CTRL_VERSION, 0, 0];
        payload.extend_from_slice(&family_attributes);
        let mut message = build_netlink_message(GENL_ID_CTRL, 0, TEST_SEQUENCE, &payload)
            .expect("family response");
        message[12..16].copy_from_slice(&TEST_PORT_ID.to_ne_bytes());
        NetlinkReply {
            message: Zeroizing::new(message),
            sender: SocketAddr::new(0, 0),
        }
    }

    fn link_details_frame(name: &str, alias: &str, kind: &str, flags: u32) -> Vec<u8> {
        let mut link_info = Vec::new();
        push_bounded_string_attribute(&mut link_info, IFLA_INFO_KIND, kind, MAX_LINK_KIND_BYTES)
            .expect("kind");
        let mut payload = interface_info(17, flags, 0).expect("interface info");
        push_bounded_string_attribute(&mut payload, IFLA_IFNAME, name, MAX_IFNAME_BYTES)
            .expect("name");
        push_bounded_string_attribute(&mut payload, IFLA_IFALIAS, alias, MAX_IFALIAS_BYTES)
            .expect("alias");
        push_attribute(&mut payload, IFLA_LINKINFO | NLA_F_NESTED, &link_info).expect("link info");
        let mut message =
            build_netlink_message(RTM_NEWLINK, 0, TEST_SEQUENCE, &payload).expect("link response");
        message[12..16].copy_from_slice(&TEST_PORT_ID.to_ne_bytes());
        message
    }

    fn exact_route_frame(index: u32, destination: Ipv6Addr) -> Vec<u8> {
        let mut payload =
            encode_exact_main_ipv6_link_route(index, destination).expect("exact route");
        payload[6] = RT_SCOPE_UNIVERSE;
        push_attribute(
            &mut payload,
            RTA_TABLE,
            &u32::from(RT_TABLE_MAIN).to_ne_bytes(),
        )
        .expect("explicit main table");
        push_attribute(&mut payload, RTA_CACHEINFO, &[0; RTA_CACHEINFO_LEN])
            .expect("empty route cache information");
        push_attribute(&mut payload, RTA_PREF, &[IPV6_ROUTER_PREF_MEDIUM])
            .expect("medium preference");
        build_netlink_message(RTM_NEWROUTE, 0, TEST_SEQUENCE, &payload).expect("route response")
    }

    fn exact_route_reply(index: u32, destination: Ipv6Addr) -> NetlinkReply {
        let mut message = exact_route_frame(index, destination);
        message[12..16].copy_from_slice(&TEST_PORT_ID.to_ne_bytes());
        NetlinkReply {
            message: Zeroizing::new(message),
            sender: SocketAddr::new(0, 0),
        }
    }

    fn route_acknowledgement(errno: i32) -> NetlinkReply {
        let mut reply = acknowledgement(errno);
        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        reply.message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        reply
    }

    fn route_frame_from_payload(payload: &[u8]) -> Vec<u8> {
        build_netlink_message(RTM_NEWROUTE, 0, TEST_SEQUENCE, payload).expect("route response")
    }

    #[test]
    fn netlink_messages_are_bounded_and_length_consistent() {
        let payload = interface_info(0, 0, 0).expect("interface info");
        let message =
            build_netlink_message(RTM_GETLINK, NLM_F_REQUEST, 9, &payload).expect("message");
        assert_eq!(read_u32(&message, 0), u32::try_from(message.len()).ok());
        assert_eq!(read_u32(&message, 8), Some(9));
    }

    #[test]
    fn attributes_reject_truncation() {
        let mut encoded = Vec::new();
        push_string_attribute(&mut encoded, IFLA_IFNAME, "vp-test").expect("attribute");
        assert_eq!(attributes(&encoded).expect("parse").len(), 1);
        encoded[0] = 0xff;
        assert!(attributes(&encoded).is_err());
    }

    #[test]
    fn v3_prepare_encoders_split_key_from_ephemeral_port() {
        let resource = durable_resource(7, 11);
        let interface = resource.interface();
        let key = Zeroizing::new([0x5a; 32]);
        let key_payload = encode_prepare_key_no_peers_v3(&resource, &key).expect("key encoding");
        assert_eq!(
            key_payload[..GENL_HEADER_LEN],
            [WG_CMD_SET_DEVICE, WG_GENL_VERSION, 0, 0]
        );
        let key_device =
            attributes(&key_payload[GENL_HEADER_LEN..]).expect("key device attributes");
        assert!(key_device.iter().any(|(kind, value)| {
            *kind == WGDEVICE_A_IFNAME && value.strip_suffix(&[0]) == Some(interface.as_bytes())
        }));
        assert!(
            key_device.iter().any(|(kind, value)| {
                *kind == WGDEVICE_A_PRIVATE_KEY && *value == key.as_slice()
            })
        );
        assert!(key_device.iter().any(|(kind, value)| {
            *kind == WGDEVICE_A_FLAGS && *value == WGDEVICE_F_REPLACE_PEERS.to_ne_bytes()
        }));
        assert!(key_device.iter().all(|(kind, _)| {
            let kind = kind & NLA_TYPE_MASK;
            kind != WGDEVICE_A_LISTEN_PORT && kind != WGDEVICE_A_PEERS
        }));

        let port_payload = encode_set_ephemeral_listen_port_v3(&resource).expect("port encoding");
        let port_device =
            attributes(&port_payload[GENL_HEADER_LEN..]).expect("port device attributes");
        assert!(port_device.iter().any(|(kind, value)| {
            *kind == WGDEVICE_A_IFNAME && value.strip_suffix(&[0]) == Some(interface.as_bytes())
        }));
        assert!(port_device.iter().any(|(kind, value)| {
            *kind == WGDEVICE_A_LISTEN_PORT && *value == 0_u16.to_ne_bytes()
        }));
        assert!(port_device.iter().all(|(kind, _)| {
            let kind = kind & NLA_TYPE_MASK;
            kind != WGDEVICE_A_PRIVATE_KEY && kind != WGDEVICE_A_FLAGS && kind != WGDEVICE_A_PEERS
        }));

        assert!(encode_prepare_key_no_peers_v3(&resource, &Zeroizing::new([0; 32])).is_err());
    }

    #[test]
    fn v3_activation_marks_every_role_to_bypass_combined_node_client_ingress() {
        for (context_role, role) in [
            (ContextRole::Client, WireguardRole::Client),
            (ContextRole::Relay, WireguardRole::RelayClient),
            (ContextRole::Relay, WireguardRole::RelayExit),
            (ContextRole::Exit, WireguardRole::Exit),
        ] {
            let resource = durable_wireguard_resource_for_test([7; 16], context_role, 1, role, 11)
                .expect("exact role resource");
            let peer = WireguardV3PeerConfiguration {
                public_key: [0x33; 32],
                endpoint: "198.51.100.4:51820".parse().expect("endpoint"),
                allowed_address: resource.peer_address(),
                allowed_prefix_length: 128,
                persistent_keepalive_seconds: 5,
            };
            let payload = encode_activate_device_v3(&resource, &peer).expect("activation encoding");
            let device = attributes(&payload[GENL_HEADER_LEN..]).expect("device attributes");
            let expected_mark = if role == WireguardRole::Client {
                CLIENT_INGRESS_IPV4_MARK
            } else {
                CONTRIBUTION_WIREGUARD_MARK
            };
            assert!(
                device.iter().any(|(kind, value)| {
                    *kind == WGDEVICE_A_FWMARK && *value == expected_mark.to_ne_bytes()
                }),
                "kernel WireGuard outer packets must bypass Client ingress in role {role:?}"
            );
        }
    }

    #[test]
    fn v3_activation_encoder_contains_one_exact_public_peer_and_no_secret() {
        let resource = durable_resource(7, 11);
        let peer = WireguardV3PeerConfiguration {
            public_key: [0x33; 32],
            endpoint: "198.51.100.4:51820".parse().expect("endpoint"),
            allowed_address: resource.peer_address(),
            allowed_prefix_length: 128,
            persistent_keepalive_seconds: 5,
        };
        let payload = encode_activate_device_v3(&resource, &peer).expect("activation encoding");
        let device = attributes(&payload[GENL_HEADER_LEN..]).expect("device attributes");
        assert!(
            device
                .iter()
                .all(|(kind, _)| kind & NLA_TYPE_MASK != WGDEVICE_A_PRIVATE_KEY)
        );
        assert!(
            device
                .iter()
                .all(|(kind, _)| kind & NLA_TYPE_MASK != WGDEVICE_A_LISTEN_PORT)
        );
        assert!(device.iter().any(|(kind, value)| {
            *kind == WGDEVICE_A_FWMARK && *value == CLIENT_INGRESS_IPV4_MARK.to_ne_bytes()
        }));
        let peers = device
            .iter()
            .find_map(|(kind, value)| (*kind == WGDEVICE_A_PEERS | NLA_F_NESTED).then_some(*value))
            .expect("peer set");
        let peer_entries = attributes(peers).expect("peer entries");
        assert_eq!(peer_entries.len(), 1);
        assert_eq!(peer_entries[0].0, 1 | NLA_F_NESTED);
        let peer_attributes = attributes(peer_entries[0].1).expect("peer attributes");
        assert!(
            peer_attributes
                .iter()
                .any(|(kind, value)| { *kind == WGPEER_A_PUBLIC_KEY && *value == peer.public_key })
        );
        assert!(peer_attributes.iter().any(|(kind, value)| {
            *kind == WGPEER_A_ENDPOINT
                && *value == encode_socket_endpoint(peer.endpoint).expect("endpoint encoding")
        }));
        let allowed = peer_attributes
            .iter()
            .find_map(|(kind, value)| {
                (*kind == WGPEER_A_ALLOWEDIPS | NLA_F_NESTED).then_some(*value)
            })
            .expect("allowed set");
        let allowed_entries = attributes(allowed).expect("allowed entries");
        assert_eq!(allowed_entries.len(), 1);
        let allowed_attributes = attributes(allowed_entries[0].1).expect("allowed attributes");
        assert!(allowed_attributes.iter().any(|(kind, value)| {
            *kind == WGALLOWEDIP_A_IPADDR && *value == peer.allowed_address.octets()
        }));
        assert!(allowed_attributes.iter().any(|(kind, value)| {
            *kind == WGALLOWEDIP_A_CIDR_MASK && *value == [peer.allowed_prefix_length]
        }));

        let mut invalid = peer;
        invalid.public_key = [0; 32];
        assert!(encode_activate_device_v3(&resource, &invalid).is_err());

        let mut substituted = invalid;
        substituted.public_key = [0x33; 32];
        substituted.allowed_address = resource.local_address();
        assert!(encode_activate_device_v3(&resource, &substituted).is_err());
    }

    #[test]
    fn exact_main_ipv6_link_route_encodings_are_topology_bound() {
        let resource = durable_resource(7, 11);
        let destination = resource.peer_address();
        let create = encode_exact_main_ipv6_link_route(17, destination).expect("create route");
        assert_eq!(create.len(), RTMSG_LEN + 20 + 8 + 8);
        assert_eq!(create[0], u8::try_from(libc::AF_INET6).expect("family"));
        assert_eq!(create[1..8], [128, 0, 0, 254, 4, 253, 1]);
        assert_eq!(read_u32(&create, 8), Some(0));
        assert_eq!(
            attributes(&create[RTMSG_LEN..]).expect("route attributes"),
            vec![
                (RTA_DST, destination.octets().as_slice()),
                (RTA_OIF, 17_u32.to_ne_bytes().as_slice()),
                (
                    RTA_PRIORITY,
                    IPV6_USER_ROUTE_PRIORITY.to_ne_bytes().as_slice()
                ),
            ]
        );

        let query = encode_exact_main_ipv6_link_route_query(17, destination).expect("query route");
        assert_eq!(query.len(), RTMSG_LEN + 20 + 8);
        assert_eq!(query[0], u8::try_from(libc::AF_INET6).expect("family"));
        assert_eq!(query[1..8], [128, 0, 0, 0, 0, 0, 0]);
        assert_eq!(read_u32(&query, 8), Some(RTM_F_FIB_MATCH));
        assert_eq!(
            attributes(&query[RTMSG_LEN..]).expect("query attributes"),
            attributes(&create[RTMSG_LEN..])
                .expect("create attributes")
                .into_iter()
                .filter(|(kind, _)| *kind != RTA_PRIORITY)
                .collect::<Vec<_>>()
        );

        assert!(encode_exact_main_ipv6_link_route(0, destination).is_err());
        assert!(encode_exact_main_ipv6_link_route(17, Ipv6Addr::UNSPECIFIED).is_err());
        assert!(
            encode_exact_main_ipv6_link_route(17, "ff02::1".parse().expect("multicast")).is_err()
        );
        assert!(encode_exact_main_ipv6_link_route_query(0, destination).is_err());
        assert!(encode_exact_main_ipv6_link_route_query(17, Ipv6Addr::UNSPECIFIED).is_err());
        assert!(
            encode_exact_main_ipv6_link_route_query(17, "ff02::1".parse().expect("multicast"))
                .is_err()
        );
    }

    #[test]
    fn exact_main_ipv6_link_route_success_is_bound_to_kernel_header_and_socket() {
        let destination = durable_resource(7, 11).peer_address();
        let parse = |reply: &NetlinkReply, local_port_id| {
            parse_exact_main_ipv6_link_route_reply(
                reply,
                TEST_SEQUENCE,
                local_port_id,
                17,
                destination,
            )
        };
        assert!(parse(&exact_route_reply(17, destination), TEST_PORT_ID).is_ok());

        for (offset, wrong_value) in [
            (8, TEST_SEQUENCE + 1),
            (12, 0),
            (12, 1),
            (12, TEST_PORT_ID + 1),
        ] {
            let mut wrong = exact_route_reply(17, destination);
            wrong.message[offset..offset + 4].copy_from_slice(&wrong_value.to_ne_bytes());
            assert!(matches!(
                parse(&wrong, TEST_PORT_ID),
                Err(KernelError::Malformed)
            ));
        }
        assert!(matches!(
            parse(&exact_route_reply(17, destination), 0),
            Err(KernelError::Malformed)
        ));

        let mut wrong = exact_route_reply(17, destination);
        wrong.message[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        assert!(matches!(
            parse(&wrong, TEST_PORT_ID),
            Err(KernelError::Malformed)
        ));

        for sender in [SocketAddr::new(1, 0), SocketAddr::new(0, 1)] {
            let mut wrong = exact_route_reply(17, destination);
            wrong.sender = sender;
            assert!(matches!(
                parse(&wrong, TEST_PORT_ID),
                Err(KernelError::Malformed)
            ));
        }

        let mut wrong = exact_route_reply(17, destination);
        let second = wrong.message.clone();
        wrong.message.extend_from_slice(&second);
        assert!(matches!(
            parse(&wrong, TEST_PORT_ID),
            Err(KernelError::Malformed)
        ));
    }

    #[test]
    fn exact_main_ipv6_link_route_ack_is_bound_to_request_header_and_socket() {
        let destination = durable_resource(7, 11).peer_address();
        let parse = |reply: &NetlinkReply, local_port_id| {
            parse_exact_main_ipv6_link_route_reply(
                reply,
                TEST_SEQUENCE,
                local_port_id,
                17,
                destination,
            )
        };
        assert!(matches!(
            parse(&route_acknowledgement(-libc::ENOENT), TEST_PORT_ID),
            Err(KernelError::Errno(libc::ENOENT))
        ));
        assert!(matches!(
            parse(&route_acknowledgement(0), TEST_PORT_ID),
            Err(KernelError::Malformed)
        ));

        for (offset, wrong_value) in [
            (8, TEST_SEQUENCE + 1),
            (12, 0),
            (12, 1),
            (12, TEST_PORT_ID + 1),
        ] {
            let mut wrong = route_acknowledgement(-libc::ENOENT);
            wrong.message[offset..offset + 4].copy_from_slice(&wrong_value.to_ne_bytes());
            assert!(matches!(
                parse(&wrong, TEST_PORT_ID),
                Err(KernelError::Malformed)
            ));
        }
        assert!(matches!(
            parse(&route_acknowledgement(-libc::ENOENT), 0),
            Err(KernelError::Malformed)
        ));

        let mut wrong = route_acknowledgement(-libc::ENOENT);
        wrong.message[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        assert!(matches!(
            parse(&wrong, TEST_PORT_ID),
            Err(KernelError::Malformed)
        ));

        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        wrong = route_acknowledgement(-libc::ENOENT);
        wrong.message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        assert!(matches!(
            parse(&wrong, TEST_PORT_ID),
            Err(KernelError::Malformed)
        ));

        wrong = route_acknowledgement(-libc::ENOENT);
        wrong.message[embedded_offset + 8..embedded_offset + 12]
            .copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(matches!(
            parse(&wrong, TEST_PORT_ID),
            Err(KernelError::Malformed)
        ));

        for sender in [SocketAddr::new(1, 0), SocketAddr::new(0, 1)] {
            wrong = route_acknowledgement(-libc::ENOENT);
            wrong.sender = sender;
            assert!(matches!(
                parse(&wrong, TEST_PORT_ID),
                Err(KernelError::Malformed)
            ));
        }
    }

    #[test]
    fn exact_main_ipv6_link_route_readback_rejects_every_identity_substitution() {
        let destination = durable_resource(7, 11).peer_address();
        let exact = exact_route_frame(17, destination);
        assert!(parse_exact_main_ipv6_link_route(&exact, 17, destination).is_ok());

        for offset in [16, 17, 18, 19, 20, 21, 22, 23] {
            let mut changed = exact.clone();
            changed[offset] ^= 1;
            assert!(
                parse_exact_main_ipv6_link_route(&changed, 17, destination).is_err(),
                "route header byte {offset} was not bound"
            );
        }
        let mut changed = exact.clone();
        changed[24..28].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_exact_main_ipv6_link_route(&changed, 17, destination).is_err());
        assert!(parse_exact_main_ipv6_link_route(&exact, 18, destination).is_err());
        assert!(
            parse_exact_main_ipv6_link_route(&exact, 17, "fd00::9".parse().expect("other route"),)
                .is_err()
        );

        for forbidden in [RTA_GATEWAY, RTA_PREFSRC, RTA_MULTIPATH] {
            let mut payload = exact[NLMSG_HEADER_LEN..].to_vec();
            push_attribute(&mut payload, forbidden, &[0; 16]).expect("forbidden attribute");
            let frame = build_netlink_message(RTM_NEWROUTE, 0, TEST_SEQUENCE, &payload)
                .expect("forbidden route response");
            assert!(parse_exact_main_ipv6_link_route(&frame, 17, destination).is_err());
        }

        let mut wrong_table = exact[NLMSG_HEADER_LEN..].to_vec();
        let table = wrong_table
            .windows(4)
            .rposition(|window| window == u32::from(RT_TABLE_MAIN).to_ne_bytes())
            .expect("table value");
        wrong_table[table..table + 4].copy_from_slice(&253_u32.to_ne_bytes());
        let wrong_table = build_netlink_message(RTM_NEWROUTE, 0, TEST_SEQUENCE, &wrong_table)
            .expect("wrong table response");
        assert!(parse_exact_main_ipv6_link_route(&wrong_table, 17, destination).is_err());
    }

    #[test]
    fn exact_main_ipv6_link_route_readback_requires_every_canonical_attribute() {
        let destination = durable_resource(7, 11).peer_address();
        let exact = exact_route_frame(17, destination);
        let payload = &exact[NLMSG_HEADER_LEN..];
        let route_attributes = attributes(&payload[RTMSG_LEN..]).expect("canonical attributes");
        let required = [
            RTA_DST,
            RTA_OIF,
            RTA_PRIORITY,
            RTA_TABLE,
            RTA_CACHEINFO,
            RTA_PREF,
        ];

        for missing in required {
            let mut changed = payload[..RTMSG_LEN].to_vec();
            for (kind, value) in &route_attributes {
                if *kind != missing {
                    push_attribute(&mut changed, *kind, value).expect("retained attribute");
                }
            }
            assert!(
                parse_exact_main_ipv6_link_route(
                    &route_frame_from_payload(&changed),
                    17,
                    destination,
                )
                .is_err(),
                "missing route attribute {missing} was accepted"
            );
        }

        for duplicate in required {
            let value = route_attributes
                .iter()
                .find_map(|(kind, value)| (*kind == duplicate).then_some(*value))
                .expect("required attribute");
            let mut changed = payload.to_vec();
            push_attribute(&mut changed, duplicate, value).expect("duplicate attribute");
            assert!(
                parse_exact_main_ipv6_link_route(
                    &route_frame_from_payload(&changed),
                    17,
                    destination,
                )
                .is_err(),
                "duplicate route attribute {duplicate} was accepted"
            );
        }

        for (kind, value) in [
            (RTA_PRIORITY, 1025_u32.to_ne_bytes().to_vec()),
            (RTA_CACHEINFO, {
                let mut value = vec![0; RTA_CACHEINFO_LEN];
                value[0] = 1;
                value
            }),
            (RTA_PREF, vec![1]),
        ] {
            let mut changed = payload[..RTMSG_LEN].to_vec();
            for (candidate, original) in &route_attributes {
                push_attribute(
                    &mut changed,
                    *candidate,
                    if *candidate == kind { &value } else { original },
                )
                .expect("substituted attribute");
            }
            assert!(
                parse_exact_main_ipv6_link_route(
                    &route_frame_from_payload(&changed),
                    17,
                    destination,
                )
                .is_err()
            );
        }

        let mut changed = payload.to_vec();
        push_attribute(&mut changed, 0x3fff, &[0]).expect("unknown attribute");
        assert!(
            parse_exact_main_ipv6_link_route(&route_frame_from_payload(&changed), 17, destination,)
                .is_err()
        );
    }

    #[test]
    fn wireguard_birth_encoders_are_exact_and_namespace_fd_scoped() {
        let resource = durable_resource(7, 11);
        let name = resource.interface();
        let alias = resource.ownership_alias();
        let requested_index = requested_birth_ifindex(&resource).expect("requested ifindex");
        assert!((BIRTH_LINK_IFINDEX_PREFIX..=i32::MAX as u32).contains(&requested_index));
        assert_eq!(requested_index, requested_birth_ifindex(&resource).unwrap());
        assert_ne!(
            requested_index,
            requested_birth_ifindex(&durable_resource(8, 12)).unwrap()
        );
        let (message_type, flags, payload) =
            encode_create_wireguard_link(&resource, requested_index).expect("create encoding");
        assert_eq!(message_type, RTM_NEWLINK);
        assert_eq!(flags, NLM_F_CREATE | NLM_F_EXCL);
        assert_eq!(read_u32(&payload, 4), Some(requested_index));
        assert!(encode_create_wireguard_link(&resource, 0).is_err());
        assert!(encode_create_wireguard_link(&resource, i32::MAX as u32 + 1).is_err());
        let top = attributes(&payload[16..]).expect("top-level attributes");
        assert!(top.iter().any(|(kind, value)| {
            *kind == IFLA_IFNAME && value.strip_suffix(&[0]) == Some(name.as_bytes())
        }));
        assert!(top.iter().all(|(kind, _)| *kind != IFLA_IFALIAS));
        let link_info = top
            .iter()
            .find_map(|(kind, value)| (*kind == (IFLA_LINKINFO | NLA_F_NESTED)).then_some(*value))
            .expect("link info");
        assert!(
            attributes(link_info)
                .expect("nested attributes")
                .iter()
                .any(|(kind, value)| { *kind == IFLA_INFO_KIND && *value == b"wireguard\0" })
        );

        let (message_type, flags, payload) =
            encode_set_link_alias(17, alias).expect("alias encoding");
        assert_eq!(message_type, RTM_SETLINK);
        assert_eq!(flags, 0);
        assert_eq!(read_u32(&payload, 4), Some(17));
        let alias_attributes = attributes(&payload[16..]).expect("alias attributes");
        assert_eq!(alias_attributes, [(IFLA_IFALIAS, alias.as_bytes())]);
        assert!(encode_set_link_alias(0, alias).is_err());
        assert!(encode_set_link_alias(i32::MAX as u32 + 1, alias).is_err());
        assert!(encode_set_link_alias(17, "").is_err());
        assert!(encode_set_link_alias(17, "marker\0suffix").is_err());
        assert!(encode_set_link_alias(17, &"a".repeat(MAX_IFALIAS_BYTES + 1)).is_err());

        let (message_type, flags, payload) =
            encode_move_link_to_namespace(17, 23).expect("move encoding");
        assert_eq!(message_type, RTM_NEWLINK);
        assert_eq!(flags, 0);
        assert_eq!(read_u32(&payload, 4), Some(17));
        assert!(
            attributes(&payload[16..])
                .expect("move attributes")
                .iter()
                .any(|(kind, value)| { *kind == IFLA_NET_NS_FD && *value == 23_i32.to_ne_bytes() })
        );
        assert!(
            attributes(&payload[16..])
                .expect("move attributes")
                .iter()
                .any(|(kind, value)| {
                    *kind == IFLA_NEW_IFINDEX && *value == 17_u32.to_ne_bytes()
                })
        );
        let (message_type, _, _) = encode_delete_link(17).expect("delete encoding");
        assert_eq!(message_type, RTM_DELLINK);
        assert!(encode_move_link_to_namespace(0, 23).is_err());
        assert!(encode_move_link_to_namespace(i32::MAX as u32 + 1, 23).is_err());
        assert!(encode_move_link_to_namespace(17, -1).is_err());
        assert!(encode_delete_link(i32::MAX as u32 + 1).is_err());
    }

    #[test]
    fn birth_deadlines_reserve_reconciliation_then_cleanup_in_one_outer_budget() {
        let outer = HardDeadline::after(Duration::from_secs(2)).expect("outer deadline");
        let progress = outer
            .before_tail(BIRTH_LINK_PROGRESS_TAIL)
            .expect("progress cutoff");
        let reconcile = outer
            .before_tail(BIRTH_LINK_RECONCILE_TAIL)
            .expect("reconcile cutoff");
        assert!(progress.expires_at() < reconcile.expires_at());
        assert!(reconcile.expires_at() < outer.expires_at());
        assert_eq!(
            outer.expires_at().duration_since(progress.expires_at()),
            Duration::from_millis(500)
        );
        assert_eq!(
            outer.expires_at().duration_since(reconcile.expires_at()),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn link_identity_proof_requires_exact_durable_name_alias_and_wireguard_kind() {
        let resource = durable_resource(7, 11);
        let name = resource.interface();
        let alias = resource.ownership_alias();
        let details = parse_link_details_frame(&link_details_frame(name, alias, WG_GENL_NAME, 0))
            .expect("exact details");
        assert!(prove_exact_owned_wireguard_link(&resource, &details).is_ok());

        let wrong_kind = parse_link_details_frame(&link_details_frame(name, alias, "dummy", 0))
            .expect("details");
        assert!(prove_exact_owned_wireguard_link(&resource, &wrong_kind).is_err());

        let legacy_alias = format!("volparossa:wireguard:v3:{name}");
        let legacy =
            parse_link_details_frame(&link_details_frame(name, &legacy_alias, WG_GENL_NAME, 0))
                .expect("legacy details");
        assert!(prove_exact_owned_wireguard_link(&resource, &legacy).is_err());

        let wrong_alias = format!("{alias}0");
        let wrong_alias_details =
            parse_link_details_frame(&link_details_frame(name, &wrong_alias, WG_GENL_NAME, 0))
                .expect("wrong-alias details");
        assert!(prove_exact_owned_wireguard_link(&resource, &wrong_alias_details).is_err());

        let other_name = durable_resource(8, 11);
        assert_ne!(other_name.interface(), name);
        let wrong_name = parse_link_details_frame(&link_details_frame(
            other_name.interface(),
            alias,
            WG_GENL_NAME,
            0,
        ))
        .expect("wrong-name details");
        assert!(prove_exact_owned_wireguard_link(&resource, &wrong_name).is_err());

        let mut duplicate_alias = link_details_frame(name, alias, WG_GENL_NAME, 0);
        let length =
            usize::try_from(read_u32(&duplicate_alias, 0).expect("length")).expect("length fits");
        push_bounded_string_attribute(&mut duplicate_alias, IFLA_IFALIAS, alias, MAX_IFALIAS_BYTES)
            .expect("duplicate");
        let new_length = u32::try_from(duplicate_alias.len()).expect("bounded");
        duplicate_alias[0..4].copy_from_slice(&new_length.to_ne_bytes());
        assert!(duplicate_alias.len() > length);
        assert!(parse_link_details_frame(&duplicate_alias).is_err());
    }

    #[test]
    fn provisional_birth_identity_is_unmarked_down_exact_name_and_wireguard_kind() {
        let resource = durable_resource(7, 11);
        let exact = LinkDetails {
            index: 17,
            name: Some(resource.interface().to_owned()),
            alias: None,
            kind: Some(WG_GENL_NAME.to_owned()),
            flags: 0,
        };
        assert!(prove_provisional_wireguard_birth_link(&resource, &exact).is_ok());
        let provisional = ProvisionalWireguardBirthLink { index: 17 };
        assert!(
            prove_cleanup_eligible_provisional_wireguard_birth_link(
                &resource,
                &provisional,
                &exact
            )
            .is_ok()
        );
        assert!(
            prove_cleanup_eligible_alias_sent_wireguard_birth_link(&resource, &provisional, &exact)
                .is_ok()
        );

        let mut marked = exact.clone();
        marked.alias = Some(resource.ownership_alias().to_owned());
        assert!(prove_provisional_wireguard_birth_link(&resource, &marked).is_err());
        assert!(
            prove_cleanup_eligible_provisional_wireguard_birth_link(
                &resource,
                &provisional,
                &marked
            )
            .is_err()
        );
        assert!(
            prove_cleanup_eligible_alias_sent_wireguard_birth_link(
                &resource,
                &provisional,
                &marked
            )
            .is_ok()
        );
        let marked_owner = MarkedWireguardBirthLink { index: 17 };
        assert!(prove_marked_wireguard_birth_link(&resource, &marked_owner, &marked).is_ok());
        let wrong_marked_owner = MarkedWireguardBirthLink { index: 18 };
        assert!(
            prove_marked_wireguard_birth_link(&resource, &wrong_marked_owner, &marked).is_err()
        );

        for changed in [
            LinkDetails {
                index: 18,
                ..exact.clone()
            },
            LinkDetails {
                name: Some("vp-other".to_owned()),
                ..exact.clone()
            },
            LinkDetails {
                alias: Some("not-our-marker".to_owned()),
                ..exact.clone()
            },
            LinkDetails {
                kind: Some("dummy".to_owned()),
                ..exact.clone()
            },
            LinkDetails {
                flags: u32::try_from(libc::IFF_UP).expect("UP flag"),
                ..exact.clone()
            },
        ] {
            assert!(
                prove_cleanup_eligible_provisional_wireguard_birth_link(
                    &resource,
                    &provisional,
                    &changed
                )
                .is_err()
            );
            assert!(
                prove_cleanup_eligible_alias_sent_wireguard_birth_link(
                    &resource,
                    &provisional,
                    &changed
                )
                .is_err()
            );
        }
    }

    #[test]
    fn birth_cleanup_targets_preserve_each_identity_strength() {
        let index = 17;
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::Uncreated),
            BirthCleanupTarget::ProveAbsent
        );
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::CreateSent(index)),
            BirthCleanupTarget::Unmarked(index)
        );
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::CreateAcknowledged(index)),
            BirthCleanupTarget::Unmarked(index)
        );
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::Provisional(index)),
            BirthCleanupTarget::Unmarked(index)
        );
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::AliasSent(index)),
            BirthCleanupTarget::AliasMayBeSet(index)
        );
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::Marked(index)),
            BirthCleanupTarget::Marked(index)
        );
        assert_eq!(
            birth_cleanup_target(LiveBirthLinkState::Moved),
            BirthCleanupTarget::ProveAbsent
        );
    }

    #[test]
    fn birth_owner_transitions_retain_one_exact_requested_index() {
        let resource = durable_resource(7, 11);
        let mut owner = LiveWireguardLeaseOwner::claim(resource);
        let index = requested_birth_ifindex(owner.resource()).expect("requested index");
        assert!(!valid_birth_transition(
            LiveBirthLinkState::Uncreated,
            LiveBirthLinkState::Moved
        ));
        assert!(!valid_birth_transition(
            LiveBirthLinkState::CreateSent(index),
            LiveBirthLinkState::CreateAcknowledged(index + 1)
        ));
        assert!(valid_birth_transition(
            LiveBirthLinkState::CreateSent(index),
            LiveBirthLinkState::Uncreated
        ));
        assert!(valid_birth_transition(
            LiveBirthLinkState::AliasSent(index),
            LiveBirthLinkState::Provisional(index)
        ));
        for (expected, next) in [
            (
                LiveBirthLinkState::Uncreated,
                LiveBirthLinkState::CreateSent(index),
            ),
            (
                LiveBirthLinkState::CreateSent(index),
                LiveBirthLinkState::CreateAcknowledged(index),
            ),
            (
                LiveBirthLinkState::CreateAcknowledged(index),
                LiveBirthLinkState::Provisional(index),
            ),
            (
                LiveBirthLinkState::Provisional(index),
                LiveBirthLinkState::AliasSent(index),
            ),
            (
                LiveBirthLinkState::AliasSent(index),
                LiveBirthLinkState::Marked(index),
            ),
            (LiveBirthLinkState::Marked(index), LiveBirthLinkState::Moved),
        ] {
            owner
                .transition_birth(expected, next)
                .expect("valid affine transition");
            assert_eq!(owner.birth, next);
        }
        assert!(
            owner
                .transition_birth(
                    LiveBirthLinkState::Marked(index),
                    LiveBirthLinkState::Uncreated
                )
                .is_err()
        );
        assert_eq!(owner.birth, LiveBirthLinkState::Moved);
    }

    #[test]
    fn late_positive_create_ack_retains_exact_unmarked_cleanup_authority() {
        let mut late_owner = LiveWireguardLeaseOwner::claim(durable_resource(9, 13));
        let late_index = requested_birth_ifindex(late_owner.resource()).expect("late index");
        late_owner
            .transition_birth(
                LiveBirthLinkState::Uncreated,
                LiveBirthLinkState::CreateSent(late_index),
            )
            .expect("full send retains exact index");
        let observation = classify_mutation_acknowledgement(Ok(()), false);
        assert!(matches!(
            observation,
            ObservedMutationAcknowledgement::Late(_)
        ));
        late_owner
            .transition_birth(
                LiveBirthLinkState::CreateSent(late_index),
                LiveBirthLinkState::CreateAcknowledged(late_index),
            )
            .expect("late positive ACK retains authority");
        assert_eq!(
            late_owner.birth,
            LiveBirthLinkState::CreateAcknowledged(late_index)
        );
        assert_eq!(
            birth_cleanup_target(late_owner.birth),
            BirthCleanupTarget::Unmarked(late_index)
        );
    }

    #[test]
    fn same_name_with_a_different_durable_marker_fails_the_delete_identity_gate() {
        let current = durable_resource(7, 11);
        let stale = durable_resource(7, 12);
        assert_eq!(stale.interface(), current.interface());
        assert_ne!(stale.ownership_alias(), current.ownership_alias());

        let stale_details = parse_link_details_frame(&link_details_frame(
            current.interface(),
            stale.ownership_alias(),
            WG_GENL_NAME,
            0,
        ))
        .expect("stale same-name details");

        // This is the same pure identity gate used before an RTM_DELLINK index is selected.
        assert!(prove_exact_owned_wireguard_link(&current, &stale_details).is_err());
    }

    #[test]
    fn link_identity_fields_enforce_kernel_specific_ascii_and_nul_bounds() {
        let name_maximum = "n".repeat(MAX_IFNAME_BYTES);
        let alias_maximum = "a".repeat(MAX_IFALIAS_BYTES);
        let kind_maximum = "k".repeat(MAX_LINK_KIND_BYTES);
        let mut encoded = Vec::new();
        assert!(
            push_bounded_string_attribute(
                &mut encoded,
                IFLA_IFNAME,
                &name_maximum,
                MAX_IFNAME_BYTES,
            )
            .is_ok()
        );
        assert!(
            push_bounded_string_attribute(
                &mut encoded,
                IFLA_IFALIAS,
                &alias_maximum,
                MAX_IFALIAS_BYTES,
            )
            .is_ok()
        );
        assert!(
            push_bounded_string_attribute(
                &mut encoded,
                IFLA_INFO_KIND,
                &kind_maximum,
                MAX_LINK_KIND_BYTES,
            )
            .is_ok()
        );

        assert!(!valid_string_field(
            &"n".repeat(MAX_IFNAME_BYTES + 1),
            MAX_IFNAME_BYTES
        ));
        assert!(!valid_string_field(
            &"a".repeat(MAX_IFALIAS_BYTES + 1),
            MAX_IFALIAS_BYTES
        ));
        assert!(!valid_string_field(
            &"k".repeat(MAX_LINK_KIND_BYTES + 1),
            MAX_LINK_KIND_BYTES
        ));
        assert!(!valid_string_field("alias\0suffix", MAX_IFALIAS_BYTES));
        assert!(!valid_string_field("alias-é", MAX_IFALIAS_BYTES));

        let mut maximum_alias_attribute = alias_maximum.into_bytes();
        maximum_alias_attribute.push(0);
        assert!(parse_string_attribute(&maximum_alias_attribute, MAX_IFALIAS_BYTES).is_ok());
        let mut oversized_alias_attribute = vec![b'a'; MAX_IFALIAS_BYTES + 1];
        oversized_alias_attribute.push(0);
        assert!(parse_string_attribute(&oversized_alias_attribute, MAX_IFALIAS_BYTES).is_err());
        assert!(parse_string_attribute(b"alias\0suffix\0", MAX_IFALIAS_BYTES).is_err());
    }

    #[test]
    fn fresh_wireguard_proof_rejects_every_mutated_state_class() {
        let resource = durable_resource(7, 11);
        let name = resource.interface();
        let details = LinkDetails {
            index: 17,
            name: Some(name.to_owned()),
            alias: Some(resource.ownership_alias().to_owned()),
            kind: Some(WG_GENL_NAME.to_owned()),
            flags: 0,
        };
        let state = WireguardDeviceState {
            ifindex: 17,
            interface_name: name.to_owned(),
            public_key: [0; 32],
            listen_port: 0,
            firewall_mark: 0,
            peers: Vec::new(),
        };
        assert!(prove_fresh_wireguard_state(name, &details, &state).is_ok());

        let mut changed_details = details.clone();
        changed_details.flags = u32::try_from(libc::IFF_UP).expect("UP flag");
        assert!(prove_fresh_wireguard_state(name, &changed_details, &state).is_err());

        let mut changed = state.clone();
        changed.public_key = [1; 32];
        assert!(prove_fresh_wireguard_state(name, &details, &changed).is_err());
        changed = state.clone();
        changed.listen_port = 51_820;
        assert!(prove_fresh_wireguard_state(name, &details, &changed).is_err());
        changed = state.clone();
        changed.firewall_mark = 7;
        assert!(prove_fresh_wireguard_state(name, &details, &changed).is_err());
        changed = state.clone();
        changed.ifindex = 18;
        assert!(prove_fresh_wireguard_state(name, &details, &changed).is_err());
        changed = state.clone();
        changed.peers.push(wireguard_probe::WireguardPeerState {
            public_key: [2; 32],
            endpoint: "198.51.100.7:51820".parse().expect("endpoint"),
            persistent_keepalive_seconds: 0,
            last_handshake_seconds: 0,
            last_handshake_nanoseconds: 0,
            received_bytes: 0,
            transmitted_bytes: 0,
            allowed_ips: Vec::new(),
            protocol_version: None,
        });
        assert!(prove_fresh_wireguard_state(name, &details, &changed).is_err());
    }

    #[test]
    fn bound_address_requires_one_nonzero_unicast_port_id() {
        assert_eq!(
            bound_unicast_port_id(SocketAddr::new(TEST_PORT_ID, 0)).expect("unicast port"),
            TEST_PORT_ID
        );
        for address in [
            SocketAddr::new(0, 0),
            SocketAddr::new(TEST_PORT_ID, 1),
            SocketAddr::new(0, 1),
        ] {
            assert!(matches!(
                bound_unicast_port_id(address),
                Err(KernelError::Malformed)
            ));
        }
    }

    #[test]
    fn acknowledgement_is_bound_to_kernel_sequence_type_and_original_request() {
        assert!(
            parse_ack(
                &acknowledgement(0),
                TEST_SEQUENCE,
                TEST_REQUEST_TYPE,
                TEST_PORT_ID
            )
            .is_ok()
        );
        assert!(matches!(
            parse_ack(
                &acknowledgement(-libc::EPERM),
                TEST_SEQUENCE,
                TEST_REQUEST_TYPE,
                TEST_PORT_ID
            ),
            Err(KernelError::Errno(libc::EPERM))
        ));

        let mut wrong = acknowledgement(0);
        wrong.message[8..12].copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());

        for wrong_port_id in [0, 1, TEST_PORT_ID + 1] {
            wrong = acknowledgement(0);
            wrong.message[12..16].copy_from_slice(&wrong_port_id.to_ne_bytes());
            assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());
        }
        assert!(parse_ack(&acknowledgement(0), TEST_SEQUENCE, TEST_REQUEST_TYPE, 0).is_err());

        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&(TEST_REQUEST_TYPE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());

        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 8..embedded_offset + 12]
            .copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());

        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 12..embedded_offset + 16]
            .copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());

        wrong = acknowledgement(0);
        wrong.sender = SocketAddr::new(99, 0);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());

        wrong = acknowledgement(0);
        wrong.sender = SocketAddr::new(0, 1);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());

        wrong = acknowledgement(0);
        let second = wrong.message.clone();
        wrong.message.extend_from_slice(&second);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE, TEST_PORT_ID).is_err());
    }

    #[test]
    fn mutation_acknowledgement_matrix_distinguishes_late_rejected_and_ambiguous() {
        assert!(matches!(
            classify_mutation_acknowledgement(Ok(()), true),
            ObservedMutationAcknowledgement::Timely
        ));
        assert!(matches!(
            classify_mutation_acknowledgement(Ok(()), false),
            ObservedMutationAcknowledgement::Late(KernelError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(matches!(
            classify_mutation_acknowledgement(Err(KernelError::Errno(libc::EBUSY)), false),
            ObservedMutationAcknowledgement::Rejected(KernelError::Errno(libc::EBUSY))
        ));
        assert!(matches!(
            classify_mutation_acknowledgement(Err(KernelError::Malformed), true),
            ObservedMutationAcknowledgement::Ambiguous(KernelError::Malformed)
        ));
    }

    #[test]
    fn restart_pre_dispatch_role_shape_is_exact_and_never_broader_than_one_path() {
        assert_eq!(
            restart_wireguard_roles(ContextRole::Client).expect("client roles"),
            &[WireguardRole::Client]
        );
        assert_eq!(
            restart_wireguard_roles(ContextRole::Relay).expect("relay roles"),
            &[WireguardRole::RelayClient, WireguardRole::RelayExit,]
        );
        assert_eq!(
            restart_wireguard_roles(ContextRole::Exit).expect("exit roles"),
            &[WireguardRole::Exit]
        );
        assert!(restart_wireguard_roles(ContextRole::Unspecified).is_err());

        let source = include_str!("kernel.rs");
        let start = source
            .find("pub(crate) fn prove_restart_pre_dispatch_links_absent")
            .expect("restart absence proof");
        let end = source[start..]
            .find("/// Read back one helper-derived")
            .map(|offset| start + offset)
            .expect("restart absence proof end");
        let proof = &source[start..end];
        assert!(proof.contains("WireguardLeaseSpec::derive("));
        assert!(proof.contains("prove_link_absent"));
        assert!(proof.contains("link_details_full(\"lo\""));
        assert!(proof.contains("loopback.flags & up != 0"));
        for forbidden in [
            "delete",
            "remove",
            "set_link_up",
            "set_link_down",
            "Command::",
        ] {
            assert!(
                !proof.contains(forbidden),
                "unexpected mutation: {forbidden}"
            );
        }
    }

    #[test]
    fn family_lookup_is_bound_to_kernel_ctrl_header_and_single_frame() {
        assert_eq!(
            parse_family_id(&family_reply(), TEST_SEQUENCE, TEST_PORT_ID).expect("family ID"),
            TEST_FAMILY_ID
        );

        let mut wrong = family_reply();
        wrong.message[8..12].copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());

        for wrong_port_id in [0, 1, TEST_PORT_ID + 1] {
            wrong = family_reply();
            wrong.message[12..16].copy_from_slice(&wrong_port_id.to_ne_bytes());
            assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());
        }
        assert!(parse_family_id(&family_reply(), TEST_SEQUENCE, 0).is_err());

        wrong = family_reply();
        wrong.message[4..6].copy_from_slice(&TEST_FAMILY_ID.to_ne_bytes());
        assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());

        wrong = family_reply();
        wrong.message[NLMSG_HEADER_LEN] = CTRL_CMD_GETFAMILY;
        assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());

        wrong = family_reply();
        wrong.message[NLMSG_HEADER_LEN + 1] = CTRL_VERSION + 1;
        assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());

        wrong = family_reply();
        wrong.sender = SocketAddr::new(1, 0);
        assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());

        wrong = family_reply();
        let second = wrong.message.clone();
        wrong.message.extend_from_slice(&second);
        assert!(parse_family_id(&wrong, TEST_SEQUENCE, TEST_PORT_ID).is_err());
    }
}
