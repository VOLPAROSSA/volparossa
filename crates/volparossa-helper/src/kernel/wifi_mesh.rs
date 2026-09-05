//! Explicit, open-L2 802.11s adjacency owned by one helper runtime.
//!
//! nl80211 creates/joins the mesh; `WireGuard` and libp2p provide the unchanged overlay encryption.
//! Mesh forwarding, root/portal announcements and automatic IP configuration are disabled. This
//! does not claim SAE, radio capacity, Internet access, or isolation of existing LAN host services.

use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

use super::{
    HardDeadline, IFLA_IFALIAS, KernelError, LinkDetails, NETLINK_ROUTE, NetlinkClient,
    RTM_NEWLINK, interface_info, push_attribute, push_string_attribute,
};
use netlink::{
    CENTER_FREQ1, CHANNEL_WIDTH, DEL_INTERFACE, GET_INTERFACE, GET_MESH_CONFIG, GET_STATION,
    GET_WIPHY, IFINDEX, IFNAME, IFTYPE, JOIN_MESH, LEAVE_MESH, MESH_CONFIG, MESH_ID, MESH_POINT,
    NEW_INTERFACE, NEW_STATION, NEW_WIPHY, SOCKET_OWNER, SPLIT_WIPHY_DUMP, WIPHY, WIPHY_FREQ,
    Wireless,
};
use observation::{Interface, Radio};

mod addressing;
mod netlink;
mod observation;
#[cfg(test)]
mod tests;

/// Explicit operator-selected local radio geometry, never an instruction to retune a parent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WifiMeshConfig {
    pub parent_interface: String,
    pub mesh_id: Vec<u8>,
    pub frequency_mhz: u32,
    pub local_address: Vec<u8>,
    pub prefix_len: u8,
    pub maximum_peers: u16,
    pub runtime_id: [u8; 16],
}

/// Current station counters are observations, not available-bandwidth estimates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeshPeer {
    pub mac: [u8; 6],
    pub established: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// A joined mesh is valid with zero peers while asynchronous peering is in progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeshSnapshot {
    pub ifindex: u32,
    pub wiphy: u32,
    pub frequency_mhz: u32,
    pub joined: bool,
    pub peers: Vec<MeshPeer>,
}

/// Keep the socket-owned cleanup authority even if creation acknowledgement was lost.
#[derive(Debug)]
pub(crate) struct InstallFailure {
    pub source: KernelError,
    pub cleanup: Option<Box<MeshOwner>>,
}

/// The generic netlink socket owns the new interface (`NL80211_ATTR_SOCKET_OWNER`). Its close
/// auto-deletes that exact interface, including when no successful create reply was observed.
pub(crate) struct MeshOwner {
    config: WifiMeshConfig,
    name: String,
    alias: String,
    namespace: File,
    parent: LinkDetails,
    wiphy: u32,
    ifindex: u32,
    link_verified: bool,
    wireless: Option<Wireless>,
    joined: bool,
    removed: bool,
}

impl std::fmt::Debug for MeshOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshOwner")
            .field("interface", &self.name)
            .field("ifindex", &self.ifindex)
            .field("wiphy", &self.wiphy)
            .field("joined", &self.joined)
            .field("removed", &self.removed)
            .finish_non_exhaustive()
    }
}

/// Validate without mutating anything, then create only a new socket-owned interface.
pub(crate) fn install(
    config: WifiMeshConfig,
    deadline: HardDeadline,
) -> Result<MeshOwner, InstallFailure> {
    let mut owner = preflight(config, deadline).map_err(|source| InstallFailure {
        source,
        cleanup: None,
    })?;
    if let Err(source) = owner.create(deadline) {
        return Err(InstallFailure {
            source,
            cleanup: Some(Box::new(owner)),
        });
    }
    Ok(owner)
}

fn preflight(config: WifiMeshConfig, deadline: HardDeadline) -> Result<MeshOwner, KernelError> {
    validate_config(&config)?;
    deadline.ensure_remaining()?;
    let namespace = File::open("/proc/thread-self/ns/net")?;
    let name = interface_name(&config.runtime_id);
    let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
    route.prove_link_absent(&name, deadline)?;
    let parent = route.link_details_full(&config.parent_interface, deadline)?;
    let mut wireless = Wireless::connect(deadline)?;
    let parent_wireless = query_interface(&mut wireless, parent.index, deadline)?;
    if parent_wireless.name.as_deref() != Some(config.parent_interface.as_str()) {
        return Err(KernelError::Invalid);
    }
    let wiphy = parent_wireless.wiphy;
    verify_unblocked(wiphy, deadline)?;
    let mut attrs = Vec::new();
    push_attribute(&mut attrs, WIPHY, &wiphy.to_ne_bytes())?;
    push_attribute(&mut attrs, SPLIT_WIPHY_DUMP, &[])?;
    let radio = Radio::parse(
        &wireless.dump(GET_WIPHY, NEW_WIPHY, &attrs, deadline)?,
        wiphy,
        config.frequency_mhz,
    )?;
    verify_coexistence(
        &mut wireless,
        &mut route,
        &radio,
        wiphy,
        config.frequency_mhz,
        deadline,
    )?;
    addressing::prove_subnet_available(&mut route, &config, deadline)?;
    let alias = format!("volparossa-mesh:{}", runtime_hex(&config.runtime_id));
    Ok(MeshOwner {
        config,
        name,
        alias,
        namespace,
        parent,
        wiphy,
        ifindex: 0,
        link_verified: false,
        wireless: Some(wireless),
        joined: false,
        removed: false,
    })
}

impl MeshOwner {
    pub(crate) fn config(&self) -> &WifiMeshConfig {
        &self.config
    }
    pub(crate) fn interface_name(&self) -> &str {
        &self.name
    }
    pub(crate) fn ifindex(&self) -> u32 {
        self.ifindex
    }
    pub(crate) fn wiphy(&self) -> u32 {
        self.wiphy
    }

    fn create(&mut self, deadline: HardDeadline) -> Result<(), KernelError> {
        self.verify_namespace()?;
        let attrs = create_attributes(self.wiphy, &self.name)?;
        let response = self.wireless.as_mut().ok_or(KernelError::Invalid)?.query(
            NEW_INTERFACE,
            NEW_INTERFACE,
            &attrs,
            deadline,
        )?;
        let interface = Interface::parse(&response)?;
        if interface.wiphy != self.wiphy
            || interface.kind != MESH_POINT
            || interface.name.as_deref() != Some(self.name.as_str())
        {
            return Err(KernelError::Invalid);
        }
        self.ifindex = interface
            .index
            .filter(|index| *index > 0)
            .ok_or(KernelError::Malformed)?;
        let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let link = route.link_details_by_index(self.ifindex, deadline)?;
        if link.name.as_deref() != Some(self.name.as_str()) || link.flags & libc::IFF_UP as u32 != 0
        {
            return Err(KernelError::Invalid);
        }
        let mut payload = interface_info(self.ifindex, 0, 0)?;
        push_string_attribute(&mut payload, IFLA_IFALIAS, &self.alias)?;
        route.request_ack(RTM_NEWLINK, 0, &payload, deadline)?;
        self.verify_link(&mut route, deadline)?;
        self.link_verified = true;
        self.disable_automatic_configuration(&mut route, deadline)?;
        // Recheck shared-channel and address admission immediately before bringing the new link up.
        self.verify_parent(&mut route, deadline)?;
        verify_unblocked(self.wiphy, deadline)?;
        self.verify_current_radio(&mut route, deadline)?;
        addressing::prove_subnet_available(&mut route, &self.config, deadline)?;
        route.add_raw_address(
            self.ifindex,
            &self.config.local_address,
            self.config.prefix_len,
            deadline,
        )?;
        route.set_link_state(self.ifindex, true, deadline)?;
        let attrs = join_attributes(self.ifindex, &self.config)?;
        self.wireless
            .as_mut()
            .ok_or(KernelError::Invalid)?
            .ack(JOIN_MESH, &attrs, deadline)?;
        self.joined = true;
        self.inspect(deadline)?;
        Ok(())
    }

    /// Read only exact-owned link and kernel station state; no scans, joins, or channel changes.
    pub(crate) fn inspect(&mut self, deadline: HardDeadline) -> Result<MeshSnapshot, KernelError> {
        self.verify_namespace()?;
        if self.removed || !self.joined || self.ifindex == 0 {
            return Err(KernelError::Invalid);
        }
        let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let link = self.verify_link(&mut route, deadline)?;
        self.verify_parent(&mut route, deadline)?;
        if link.flags & libc::IFF_UP as u32 == 0 {
            return Err(KernelError::Invalid);
        }
        let wireless = self.wireless.as_mut().ok_or(KernelError::Invalid)?;
        let interface = query_interface(wireless, self.ifindex, deadline)?;
        if interface.wiphy != self.wiphy
            || interface.kind != MESH_POINT
            || interface.frequency != Some(self.config.frequency_mhz)
            || interface.name.as_deref() != Some(self.name.as_str())
        {
            return Err(KernelError::Invalid);
        }
        let attrs = index_attributes(self.ifindex)?;
        observation::verify_mesh_configuration(
            &wireless.query(GET_MESH_CONFIG, GET_MESH_CONFIG, &attrs, deadline)?,
            &self.config,
        )?;
        let peers = observation::peers(
            &wireless.dump(GET_STATION, NEW_STATION, &attrs, deadline)?,
            self.ifindex,
            self.config.maximum_peers,
        )?;
        addressing::verify_address(&mut route, self.ifindex, &self.config, deadline)?;
        Ok(MeshSnapshot {
            ifindex: self.ifindex,
            wiphy: self.wiphy,
            frequency_mhz: self.config.frequency_mhz,
            joined: true,
            peers,
        })
    }

    /// Retire only this owner, retaining failed cleanup authority for a later retry.
    pub(crate) fn remove(&mut self, deadline: HardDeadline) -> Result<bool, KernelError> {
        self.verify_namespace()?;
        if self.removed {
            return Ok(false);
        }
        let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline)?;
        let existed = match route.link_details_full(&self.name, deadline) {
            Ok(link) => {
                // A missing create reply has no index authority: socket close is the only allowed
                // operation in that case, never name-based deletion of an unproven object.
                if self.ifindex != 0 && link.index != self.ifindex {
                    return Err(KernelError::Invalid);
                }
                true
            }
            Err(error) if error.is_errno(libc::ENODEV) => false,
            Err(error) => return Err(error),
        };
        if existed && self.ifindex != 0 && self.joined {
            self.verify_link(&mut route, deadline)?;
            if let Some(wireless) = self.wireless.as_mut() {
                match wireless.ack(LEAVE_MESH, &index_attributes(self.ifindex)?, deadline) {
                    Ok(()) => self.joined = false,
                    Err(error)
                        if error.is_errno(libc::ENOTCONN) || error.is_errno(libc::ENODEV) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if existed && self.ifindex != 0 && self.link_verified {
            // Exact socket-bound interface identity was returned by the creating kernel socket.
            self.verify_link(&mut route, deadline)?;
            if let Some(wireless) = self.wireless.as_mut() {
                match wireless.ack(DEL_INTERFACE, &index_attributes(self.ifindex)?, deadline) {
                    Ok(()) => {}
                    Err(error) if error.is_errno(libc::ENODEV) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.wireless.take(); // Also cleans an ambiguous successful NEW_INTERFACE response.
        loop {
            match route.link_details_full(&self.name, deadline) {
                Err(error) if error.is_errno(libc::ENODEV) => break,
                Err(error) => return Err(error),
                Ok(link) if self.ifindex != 0 && link.index != self.ifindex => {
                    return Err(KernelError::Invalid);
                }
                Ok(_) => {
                    deadline.ensure_remaining()?;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
        self.joined = false;
        self.removed = true;
        Ok(existed)
    }

    fn verify_namespace(&self) -> Result<(), KernelError> {
        let current = std::fs::metadata("/proc/thread-self/ns/net")?;
        let pinned = self.namespace.metadata()?;
        if current.dev() != pinned.dev() || current.ino() != pinned.ino() {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    fn verify_link(
        &self,
        route: &mut NetlinkClient,
        deadline: HardDeadline,
    ) -> Result<LinkDetails, KernelError> {
        self.verify_namespace()?;
        let link = route.link_details_by_index(self.ifindex, deadline)?;
        if link.name.as_deref() != Some(self.name.as_str())
            || link.alias.as_deref() != Some(self.alias.as_str())
        {
            return Err(KernelError::Invalid);
        }
        Ok(link)
    }

    fn verify_parent(
        &mut self,
        route: &mut NetlinkClient,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let parent = route.link_details_by_index(self.parent.index, deadline)?;
        if parent.name != self.parent.name
            || parent.alias != self.parent.alias
            || parent.kind != self.parent.kind
        {
            return Err(KernelError::Invalid);
        }
        let wireless = self.wireless.as_mut().ok_or(KernelError::Invalid)?;
        if query_interface(wireless, parent.index, deadline)?.wiphy != self.wiphy {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    fn verify_current_radio(
        &mut self,
        route: &mut NetlinkClient,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let wireless = self.wireless.as_mut().ok_or(KernelError::Invalid)?;
        let mut attrs = Vec::new();
        push_attribute(&mut attrs, WIPHY, &self.wiphy.to_ne_bytes())?;
        push_attribute(&mut attrs, SPLIT_WIPHY_DUMP, &[])?;
        let radio = Radio::parse(
            &wireless.dump(GET_WIPHY, NEW_WIPHY, &attrs, deadline)?,
            self.wiphy,
            self.config.frequency_mhz,
        )?;
        verify_coexistence(
            wireless,
            route,
            &radio,
            self.wiphy,
            self.config.frequency_mhz,
            deadline,
        )
    }

    fn disable_automatic_configuration(
        &self,
        route: &mut NetlinkClient,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        for (family, knob) in [
            ("ipv4", "accept_redirects"),
            ("ipv6", "accept_ra"),
            ("ipv6", "autoconf"),
            ("ipv6", "accept_redirects"),
        ] {
            self.verify_link(route, deadline)?;
            // Both directory and knob are fixed by this provider; the name was helper-generated
            // and verified against the socket-owned kernel index immediately before every write.
            let path = format!("/proc/sys/net/{family}/conf/{}/{knob}", self.name);
            deadline.ensure_remaining()?;
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)?
                .write_all(b"0\n")?;
            let mut value = String::new();
            File::open(path)?.take(16).read_to_string(&mut value)?;
            if value.trim() != "0" {
                return Err(KernelError::Invalid);
            }
            deadline.ensure_remaining()?;
        }
        Ok(())
    }
}

fn validate_config(config: &WifiMeshConfig) -> Result<(), KernelError> {
    let name = config.parent_interface.as_str();
    if config.runtime_id == [0; 16]
        || !(1..=15).contains(&name.len())
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'))
        || !(1..=32).contains(&config.mesh_id.len())
        || !config.mesh_id.iter().all(u8::is_ascii_graphic)
        || !(1..=32).contains(&config.maximum_peers)
        || !(((2412..=2472).contains(&config.frequency_mhz) && config.frequency_mhz % 5 == 2)
            || ((5000..=5900).contains(&config.frequency_mhz) && config.frequency_mhz % 5 == 0))
    {
        return Err(KernelError::Invalid);
    }
    addressing::validate(config)
}

fn interface_name(runtime: &[u8; 16]) -> String {
    let hex = runtime_hex(runtime);
    format!("vw{}", &hex[..13])
}

fn runtime_hex(runtime: &[u8; 16]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(32);
    for byte in runtime {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

fn index_attributes(index: u32) -> Result<Vec<u8>, KernelError> {
    let mut attrs = Vec::new();
    push_attribute(&mut attrs, IFINDEX, &index.to_ne_bytes())?;
    Ok(attrs)
}

fn create_attributes(wiphy: u32, name: &str) -> Result<Vec<u8>, KernelError> {
    let mut attrs = Vec::new();
    push_attribute(&mut attrs, WIPHY, &wiphy.to_ne_bytes())?;
    push_string_attribute(&mut attrs, IFNAME, name)?;
    push_attribute(&mut attrs, IFTYPE, &MESH_POINT.to_ne_bytes())?;
    push_attribute(&mut attrs, SOCKET_OWNER, &[])?;
    Ok(attrs)
}

fn join_attributes(index: u32, config: &WifiMeshConfig) -> Result<Vec<u8>, KernelError> {
    let mut attrs = index_attributes(index)?;
    push_attribute(&mut attrs, MESH_ID, &config.mesh_id)?;
    push_attribute(&mut attrs, WIPHY_FREQ, &config.frequency_mhz.to_ne_bytes())?;
    push_attribute(&mut attrs, CHANNEL_WIDTH, &1_u32.to_ne_bytes())?; // NL80211_CHAN_WIDTH_20
    push_attribute(
        &mut attrs,
        CENTER_FREQ1,
        &config.frequency_mhz.to_ne_bytes(),
    )?;
    let mut mesh = Vec::new();
    push_attribute(&mut mesh, 4, &config.maximum_peers.to_ne_bytes())?;
    push_attribute(&mut mesh, 6, &[1])?; // TTL=1, additional bound; mesh forwarding stays disabled.
    push_attribute(&mut mesh, 7, &[1])?; // Kernel open peering, no SAE claim.
    for kind in [14, 17, 19] {
        push_attribute(&mut mesh, kind, &[0])?;
    }
    push_attribute(&mut attrs, MESH_CONFIG | super::NLA_F_NESTED, &mesh)?;
    Ok(attrs)
}

fn query_interface(
    wireless: &mut Wireless,
    index: u32,
    deadline: HardDeadline,
) -> Result<Interface, KernelError> {
    let interface = Interface::parse(&wireless.query(
        GET_INTERFACE,
        NEW_INTERFACE,
        &index_attributes(index)?,
        deadline,
    )?)?;
    if interface.index != Some(index) {
        return Err(KernelError::Malformed);
    }
    Ok(interface)
}

fn verify_coexistence(
    wireless: &mut Wireless,
    route: &mut NetlinkClient,
    radio: &Radio,
    wiphy: u32,
    frequency: u32,
    deadline: HardDeadline,
) -> Result<(), KernelError> {
    let records = wireless.dump(GET_INTERFACE, NEW_INTERFACE, &[], deadline)?;
    if records.len() > 64 {
        return Err(KernelError::Malformed);
    }
    let mut active = Vec::new();
    for record in records {
        let interface = Interface::parse(&record)?;
        if interface.wiphy != wiphy {
            continue;
        }
        match interface.index {
            Some(index)
                if route.link_details_by_index(index, deadline)?.flags & libc::IFF_UP as u32
                    == 0 => {}
            _ => active.push(interface),
        }
    }
    radio.admit(&active, frequency)
}

fn verify_unblocked(wiphy: u32, deadline: HardDeadline) -> Result<(), KernelError> {
    let mut found = false;
    let entries = std::fs::read_dir(format!("/sys/class/ieee80211/phy{wiphy}"))?;
    for (count, entry) in entries.enumerate() {
        deadline.ensure_remaining()?;
        if count >= 128 {
            return Err(KernelError::Malformed);
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().and_then(|name| name.strip_prefix("rfkill")) else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|value| value.is_ascii_digit()) {
            continue;
        }
        found = true;
        for knob in ["soft", "hard"] {
            let mut value = String::new();
            File::open(entry.path().join(knob))?
                .take(16)
                .read_to_string(&mut value)?;
            if value.trim() != "0" {
                return Err(KernelError::Invalid);
            }
        }
    }
    if !found {
        return Err(KernelError::Invalid);
    }
    Ok(())
}
