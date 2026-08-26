//! Bounded Linux rtnetlink and `WireGuard` generic-netlink operations.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr as InternetSocketAddr},
    os::fd::RawFd,
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
use zeroize::Zeroizing;

use crate::{
    deadline::{HardDeadline, wait_for_fd},
    ownership_journal::DurableWireguardResource,
};

#[allow(dead_code)] // GET_DEVICE is wired into the v3 lease state machine in phase 2.
mod wireguard_probe;

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
const RTM_NEWADDR: u16 = 20;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_IFALIAS: u16 = 20;
const IFLA_INFO_KIND: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_VERSION: u8 = 2;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const MAX_IFNAME_BYTES: usize = 15;
const MAX_IFALIAS_BYTES: usize = 255;
const MAX_LINK_KIND_BYTES: usize = 16;

const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u8 = 1;
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
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

/// Physical-namespace rtnetlink client used only by the root helper parent.
pub(crate) struct BirthNamespaceKernel {
    route: NetlinkClient,
}

impl BirthNamespaceKernel {
    /// Open a route socket in the caller's current physical/underlay namespace.
    pub(crate) fn connect(deadline: HardDeadline) -> Result<Self, KernelError> {
        Ok(Self {
            route: NetlinkClient::connect(NETLINK_ROUTE, deadline)?,
        })
    }

    /// Create a `WireGuard` device here and then move it by target namespace fd.
    pub(crate) fn create_and_move_wireguard(
        &mut self,
        resource: &DurableWireguardResource,
        target_namespace: RawFd,
        deadline: HardDeadline,
    ) -> Result<(), BirthLinkError> {
        let interface = resource.interface();
        if validate_durable_wireguard_resource(resource).is_err() || target_namespace < 0 {
            return Err(BirthLinkError::Kernel(KernelError::Invalid));
        }
        match self.route.link_index(interface, deadline) {
            Ok(_) => return Err(BirthLinkError::Conflict),
            Err(error) if error.is_errno(libc::ENODEV) => {}
            Err(error) => return Err(BirthLinkError::Kernel(error)),
        }

        let index = match self.route.create_wireguard_link(resource, deadline) {
            Ok(()) => self
                .route
                .exact_owned_wireguard_link_index(resource, deadline)
                .map_err(|_| BirthLinkError::CleanupIncomplete)?,
            Err(error) if error.is_errno(libc::EEXIST) => {
                return Err(BirthLinkError::Conflict);
            }
            Err(create_error) => match self
                .route
                .exact_owned_wireguard_link_index(resource, deadline)
            {
                Ok(index) => index,
                Err(error) if error.is_errno(libc::ENODEV) => {
                    return Err(BirthLinkError::Kernel(create_error));
                }
                Err(_) => return Err(BirthLinkError::CleanupIncomplete),
            },
        };

        match self
            .route
            .move_link_to_namespace(index, target_namespace, deadline)
        {
            Ok(()) => Ok(()),
            Err(move_error) => match self.route.link_index(interface, deadline) {
                Err(error) if error.is_errno(libc::ENODEV) => Ok(()),
                Ok(_) => {
                    if self
                        .route
                        .delete_named_exact_owned_wireguard_link(resource, deadline)
                        .is_ok()
                    {
                        Err(BirthLinkError::Kernel(move_error))
                    } else {
                        Err(BirthLinkError::CleanupIncomplete)
                    }
                }
                Err(_) => Err(BirthLinkError::CleanupIncomplete),
            },
        }
    }

    /// Delete a crash-stranded `WireGuard` link only when its exact durable marker and kind match.
    /// Production callers must separately hold durable journal authority.
    pub(crate) fn delete_owned_wireguard(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        self.route
            .delete_named_exact_owned_wireguard_link(resource, deadline)
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
        if expected_device_public_key.iter().all(|byte| *byte == 0) || expected_listen_port == 0 {
            return Err(KernelError::Invalid);
        }
        validate_durable_wireguard_resource(resource)?;
        self.route
            .exact_owned_wireguard_link_details(resource, deadline)?;
        let wireguard = self.wireguard.as_mut().ok_or(KernelError::Unsupported)?;
        wireguard.activate_device_v3(resource, peer, deadline)?;
        self.probe_wireguard_peer_v3(
            resource,
            expected_device_public_key,
            expected_listen_port,
            peer,
            deadline,
        )
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
            || peer.allowed_prefix_length > 128
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
            || state.firewall_mark != 0
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
            || proved_peer.protocol_version.is_some()
        {
            return Err(KernelError::Malformed);
        }
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
    sequence: u32,
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
        socket.bind_auto()?;
        deadline.ensure_remaining()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_remaining()?;
        Ok(Self {
            socket,
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
        let parsed = parse_ack(&response, sequence, message_type);
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

    fn create_wireguard_link(
        &mut self,
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let (message_type, flags, payload) = encode_create_wireguard_link(resource)?;
        self.request_ack(message_type, flags, &payload, deadline)
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
            parse_ack(&response, sequence, RTM_GETLINK)?;
            return Err(KernelError::Malformed);
        }
        validate_kernel_header(frame, sequence, RTM_NEWLINK)?;
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
        self.add_raw_address_for_family(index, family, address, prefix_length, deadline)
    }

    fn add_raw_address_for_family(
        &mut self,
        index: u32,
        family: u8,
        address: &[u8],
        prefix_length: u8,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        if index == 0 {
            return Err(KernelError::Invalid);
        }
        let mut payload = Vec::with_capacity(64);
        payload.push(family);
        payload.push(prefix_length);
        payload.push(0);
        payload.push(0);
        payload.extend_from_slice(&index.to_ne_bytes());
        push_attribute(&mut payload, IFA_ADDRESS, address)?;
        push_attribute(&mut payload, IFA_LOCAL, address)?;
        self.request_ack(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &payload, deadline)
    }
}

fn encode_create_wireguard_link(
    resource: &DurableWireguardResource,
) -> Result<(u16, u16, Vec<u8>), KernelError> {
    validate_durable_wireguard_resource(resource)?;
    let mut link_info = Vec::with_capacity(32);
    push_bounded_string_attribute(
        &mut link_info,
        IFLA_INFO_KIND,
        WG_GENL_NAME,
        MAX_LINK_KIND_BYTES,
    )?;
    let mut link_attributes = Vec::with_capacity(128);
    push_bounded_string_attribute(
        &mut link_attributes,
        IFLA_IFNAME,
        resource.interface(),
        MAX_IFNAME_BYTES,
    )?;
    push_bounded_string_attribute(
        &mut link_attributes,
        IFLA_IFALIAS,
        resource.ownership_alias(),
        MAX_IFALIAS_BYTES,
    )?;
    push_attribute(
        &mut link_attributes,
        IFLA_LINKINFO | NLA_F_NESTED,
        &link_info,
    )?;
    let mut payload = interface_info(0, 0, 0)?;
    payload.extend_from_slice(&link_attributes);
    Ok((RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, payload))
}

fn encode_move_link_to_namespace(
    index: u32,
    target_namespace: RawFd,
) -> Result<(u16, u16, Vec<u8>), KernelError> {
    if index == 0 || target_namespace < 0 {
        return Err(KernelError::Invalid);
    }
    let mut payload = interface_info(index, 0, 0)?;
    push_attribute(
        &mut payload,
        IFLA_NET_NS_FD,
        &target_namespace.to_ne_bytes(),
    )?;
    Ok((RTM_NEWLINK, 0, payload))
}

fn encode_delete_link(index: u32) -> Result<(u16, u16, Vec<u8>), KernelError> {
    if index == 0 {
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
        || peer.allowed_prefix_length > 128
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
    let family_id = parse_family_id(&response, sequence)?;
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

fn parse_family_id(reply: &NetlinkReply, expected_sequence: u32) -> Result<u16, KernelError> {
    validate_kernel_sender(&reply.sender)?;
    let response_frames = frames(&reply.message)?;
    if response_frames.len() != 1 {
        return Err(KernelError::Malformed);
    }
    let frame = response_frames[0];
    if read_u16(frame, 4) == Some(NLMSG_ERROR) {
        return match parse_ack(reply, expected_sequence, GENL_ID_CTRL) {
            Ok(()) => Err(KernelError::Unsupported),
            Err(error) if error.is_errno(libc::ENOENT) => Err(KernelError::Unsupported),
            Err(error) => Err(error),
        };
    }
    validate_kernel_header(frame, expected_sequence, GENL_ID_CTRL)?;
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
) -> Result<(), KernelError> {
    validate_kernel_sender(&reply.sender)?;
    let response_frames = frames(&reply.message)?;
    if response_frames.len() != 1 {
        return Err(KernelError::Malformed);
    }
    let frame = response_frames[0];
    validate_kernel_header(frame, expected_sequence, NLMSG_ERROR)?;
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
) -> Result<(), KernelError> {
    if read_u16(frame, 4) != Some(expected_type)
        || read_u32(frame, 8) != Some(expected_sequence)
        || read_u32(frame, 12) != Some(0)
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

    fn acknowledgement(errno: i32) -> NetlinkReply {
        let mut message = vec![0_u8; NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN + NLMSG_HEADER_LEN];
        let length = u32::try_from(message.len()).expect("small acknowledgement");
        message[0..4].copy_from_slice(&length.to_ne_bytes());
        message[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        message[8..12].copy_from_slice(&TEST_SEQUENCE.to_ne_bytes());
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
        NetlinkReply {
            message: Zeroizing::new(
                build_netlink_message(GENL_ID_CTRL, 0, TEST_SEQUENCE, &payload)
                    .expect("family response"),
            ),
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
        build_netlink_message(RTM_NEWLINK, 0, TEST_SEQUENCE, &payload).expect("link response")
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
    fn v3_activation_encoder_contains_one_exact_public_peer_and_no_secret() {
        let resource = durable_resource(7, 11);
        let peer = WireguardV3PeerConfiguration {
            public_key: [0x33; 32],
            endpoint: "198.51.100.4:51820".parse().expect("endpoint"),
            allowed_address: "fd00::2".parse().expect("allowed IP"),
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
    }

    #[test]
    fn wireguard_birth_encoders_are_exact_and_namespace_fd_scoped() {
        let resource = durable_resource(7, 11);
        let name = resource.interface();
        let alias = resource.ownership_alias();
        let (message_type, flags, payload) =
            encode_create_wireguard_link(&resource).expect("create encoding");
        assert_eq!(message_type, RTM_NEWLINK);
        assert_eq!(flags, NLM_F_CREATE | NLM_F_EXCL);
        let top = attributes(&payload[16..]).expect("top-level attributes");
        assert!(top.iter().any(|(kind, value)| {
            *kind == IFLA_IFNAME && value.strip_suffix(&[0]) == Some(name.as_bytes())
        }));
        assert!(top.iter().any(|(kind, value)| {
            *kind == IFLA_IFALIAS && value.strip_suffix(&[0]) == Some(alias.as_bytes())
        }));
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
        let (message_type, _, _) = encode_delete_link(17).expect("delete encoding");
        assert_eq!(message_type, RTM_DELLINK);
        assert!(encode_move_link_to_namespace(0, 23).is_err());
        assert!(encode_move_link_to_namespace(17, -1).is_err());
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
    fn acknowledgement_is_bound_to_kernel_sequence_type_and_original_request() {
        assert!(parse_ack(&acknowledgement(0), TEST_SEQUENCE, TEST_REQUEST_TYPE).is_ok());
        assert!(matches!(
            parse_ack(
                &acknowledgement(-libc::EPERM),
                TEST_SEQUENCE,
                TEST_REQUEST_TYPE
            ),
            Err(KernelError::Errno(libc::EPERM))
        ));

        let mut wrong = acknowledgement(0);
        wrong.message[8..12].copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        wrong = acknowledgement(0);
        wrong.message[12..16].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&(TEST_REQUEST_TYPE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 8..embedded_offset + 12]
            .copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 12..embedded_offset + 16]
            .copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        wrong = acknowledgement(0);
        wrong.sender = SocketAddr::new(99, 0);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        wrong = acknowledgement(0);
        wrong.sender = SocketAddr::new(0, 1);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());

        wrong = acknowledgement(0);
        let second = wrong.message.clone();
        wrong.message.extend_from_slice(&second);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_REQUEST_TYPE).is_err());
    }

    #[test]
    fn family_lookup_is_bound_to_kernel_ctrl_header_and_single_frame() {
        assert_eq!(
            parse_family_id(&family_reply(), TEST_SEQUENCE).expect("family ID"),
            TEST_FAMILY_ID
        );

        let mut wrong = family_reply();
        wrong.message[8..12].copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.message[4..6].copy_from_slice(&TEST_FAMILY_ID.to_ne_bytes());
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.message[NLMSG_HEADER_LEN] = CTRL_CMD_GETFAMILY;
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.message[NLMSG_HEADER_LEN + 1] = CTRL_VERSION + 1;
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.sender = SocketAddr::new(1, 0);
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        let second = wrong.message.clone();
        wrong.message.extend_from_slice(&second);
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());
    }
}
