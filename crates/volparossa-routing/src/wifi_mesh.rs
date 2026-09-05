//! Closed direct-mesh operations: an explicit local underlay, never an arbitrary radio command.

use super::{
    HelperProtocolError, HelperRequest, HelperResponse, HelperResult, context, handle,
    helper_request, helper_response, operation_digest, validate_request, validate_response,
};
use prost::Message;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use volparossa_core::is_local_lan_ip;

/// Create one new mesh interface on a verified existing wireless parent.
#[derive(Clone, PartialEq, Message)]
pub struct InstallWifiMesh {
    /// Nonzero random runtime identity, independent of route contexts.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_runtime_id: Vec<u8>,
    /// Existing wireless parent name; never a filesystem path or replacement target.
    #[prost(string, tag = "2")]
    pub parent_interface: String,
    /// Explicit common 1..=32-byte ASCII mesh identifier.
    #[prost(bytes = "vec", tag = "3")]
    pub mesh_id: Vec<u8>,
    /// Explicit 20MHz center frequency; the helper checks hardware/regulatory coexistence.
    #[prost(uint32, tag = "4")]
    pub frequency_mhz: u32,
    /// One RFC1918 or ULA host address on the new, helper-generated interface only.
    #[prost(bytes = "vec", tag = "5")]
    pub local_address: Vec<u8>,
    /// Non-default connected subnet prefix.
    #[prost(uint32, tag = "6")]
    pub prefix_len: u32,
    /// Bound on directly peered stations. Mesh forwarding remains disabled.
    #[prost(uint32, tag = "7")]
    pub maximum_peers: u32,
}

/// Read the exact owned mesh without scanning or changing channels.
#[derive(Clone, PartialEq, Message)]
pub struct InspectWifiMesh {
    /// Exact runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_runtime_id: Vec<u8>,
    /// Opaque helper-issued handle.
    #[prost(bytes = "vec", tag = "2")]
    pub mesh_handle: Vec<u8>,
}

/// Idempotently leave and remove only this mesh owner's interface.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyWifiMesh {
    /// Exact runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_runtime_id: Vec<u8>,
    /// Opaque helper-issued handle.
    #[prost(bytes = "vec", tag = "2")]
    pub mesh_handle: Vec<u8>,
}

/// Installed interface identity. No secret or radio-configuration authority is returned.
#[derive(Clone, PartialEq, Message)]
pub struct InstalledWifiMesh {
    /// Exact runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_runtime_id: Vec<u8>,
    /// Opaque helper-issued handle.
    #[prost(bytes = "vec", tag = "2")]
    pub mesh_handle: Vec<u8>,
    /// Actual generated interface name.
    #[prost(string, tag = "3")]
    pub interface: String,
    /// Actual kernel interface index.
    #[prost(uint32, tag = "4")]
    pub ifindex: u32,
    /// Actual wiphy index; zero is valid.
    #[prost(uint32, tag = "5")]
    pub wiphy: u32,
}

/// One currently observed station; counters do not measure unused airtime or link capacity.
#[derive(Clone, PartialEq, Message)]
pub struct WifiMeshPeer {
    /// Six-byte unicast station address, kept only in the runtime snapshot.
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
    /// Kernel mesh peering state is ESTABLISHED.
    #[prost(bool, tag = "2")]
    pub established: bool,
    /// Kernel received bytes.
    #[prost(uint64, tag = "3")]
    pub received_bytes: u64,
    /// Kernel transmitted bytes.
    #[prost(uint64, tag = "4")]
    pub transmitted_bytes: u64,
    /// Kernel received packets.
    #[prost(uint64, tag = "5")]
    pub received_packets: u64,
    /// Kernel transmitted packets.
    #[prost(uint64, tag = "6")]
    pub transmitted_packets: u64,
}

/// Exact runtime mesh identity and bounded real station counters.
#[derive(Clone, PartialEq, Message)]
pub struct WifiMeshSnapshot {
    /// Exact runtime identity.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_runtime_id: Vec<u8>,
    /// Exact owner handle.
    #[prost(bytes = "vec", tag = "2")]
    pub mesh_handle: Vec<u8>,
    /// Actual kernel interface index.
    #[prost(uint32, tag = "3")]
    pub ifindex: u32,
    /// Actual wiphy index.
    #[prost(uint32, tag = "4")]
    pub wiphy: u32,
    /// Observed frequency, not a request to retune.
    #[prost(uint32, tag = "5")]
    pub frequency_mhz: u32,
    /// The interface remains joined to its exact configured mesh.
    #[prost(bool, tag = "6")]
    pub joined: bool,
    /// Zero peers is valid while neighbors have not arrived.
    #[prost(message, repeated, tag = "7")]
    pub peers: Vec<WifiMeshPeer>,
}

/// Idempotent exact-owner retirement result.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyedWifiMesh {
    /// Whether the exact mesh interface existed before this request.
    #[prost(bool, tag = "1")]
    pub existed: bool,
}

fn frequency(value: u32) -> bool {
    ((2412..=2472).contains(&value) && value % 5 == 2)
        || ((5000..=5900).contains(&value) && value % 5 == 0)
}

pub(super) fn validate_install(value: &InstallWifiMesh) -> Result<(), HelperProtocolError> {
    context(&value.mesh_runtime_id)?;
    let name = value.parent_interface.as_str();
    if !(1..=15).contains(&name.len())
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        || !(1..=32).contains(&value.mesh_id.len())
        || !value.mesh_id.iter().all(u8::is_ascii_graphic)
        || !frequency(value.frequency_mhz)
        || !(1..=32).contains(&value.maximum_peers)
    {
        return Err(HelperProtocolError::Invalid("Wi-Fi mesh configuration"));
    }
    let ip = match value.local_address.as_slice() {
        &[a, b, c, d] => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes)
                .map_err(|_| HelperProtocolError::Invalid("mesh address"))?,
        )),
        _ => return Err(HelperProtocolError::Invalid("mesh local address")),
    };
    if !is_local_lan_ip(ip)
        || value.prefix_len == 0
        || value.prefix_len > if ip.is_ipv4() { 30 } else { 126 }
    {
        return Err(HelperProtocolError::Invalid("mesh local subnet"));
    }
    let (first, last) = match ip {
        IpAddr::V4(ip) => {
            let mask = u32::MAX << (32 - value.prefix_len);
            if u32::from(ip) & !mask == 0 || u32::from(ip) & !mask == !mask {
                return Err(HelperProtocolError::Invalid("mesh host address"));
            }
            (
                IpAddr::V4((u32::from(ip) & mask).into()),
                IpAddr::V4((u32::from(ip) | !mask).into()),
            )
        }
        IpAddr::V6(ip) => {
            let mask = u128::MAX << (128 - value.prefix_len);
            (
                IpAddr::V6((u128::from(ip) & mask).into()),
                IpAddr::V6((u128::from(ip) | !mask).into()),
            )
        }
    };
    if !is_local_lan_ip(first) || !is_local_lan_ip(last) {
        return Err(HelperProtocolError::Invalid(
            "mesh subnet must remain local",
        ));
    }
    Ok(())
}

pub(super) fn validate_installed(value: &InstalledWifiMesh) -> Result<(), HelperProtocolError> {
    context(&value.mesh_runtime_id)?;
    handle(&value.mesh_handle)?;
    if value.ifindex <= 1
        || !(3..=15).contains(&value.interface.len())
        || !value.interface.starts_with("vw")
        || !value.interface[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(HelperProtocolError::Invalid("mesh interface identity"));
    }
    Ok(())
}

pub(super) fn validate_snapshot(value: &WifiMeshSnapshot) -> Result<(), HelperProtocolError> {
    context(&value.mesh_runtime_id)?;
    handle(&value.mesh_handle)?;
    if value.ifindex <= 1 || !frequency(value.frequency_mhz) || value.peers.len() > 32 {
        return Err(HelperProtocolError::Invalid("mesh snapshot bounds"));
    }
    let mut seen = BTreeSet::new();
    for peer in &value.peers {
        if peer.address.len() != 6
            || peer.address.iter().all(|b| *b == 0)
            || peer.address[0] & 1 != 0
            || !seen.insert(&peer.address)
        {
            return Err(HelperProtocolError::Invalid("mesh station address"));
        }
    }
    Ok(())
}

/// Validate full request/digest/owner correlation for a no-FD mesh response.
///
/// # Errors
/// Rejects substituted request IDs, operation kinds, runtime IDs or handles.
pub fn validate_wifi_mesh_response(
    request: &HelperRequest,
    response: &HelperResponse,
) -> Result<(), HelperProtocolError> {
    use helper_request::Operation;
    use helper_response::Outcome;
    validate_request(request)?;
    validate_response(response)?;
    let operation = request
        .operation
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("mesh operation"))?;
    if !matches!(
        operation,
        Operation::InstallWifiMesh(_)
            | Operation::InspectWifiMesh(_)
            | Operation::DestroyWifiMesh(_)
    ) || request.request_id != response.request_id
        || response.operation_digest.as_slice() != operation_digest(request)?
    {
        return Err(HelperProtocolError::Invalid("mesh response correlation"));
    }
    if response.result != HelperResult::Ok as i32 {
        return Ok(());
    }
    let matched = match (operation, response.outcome.as_ref()) {
        (Operation::InstallWifiMesh(request), Some(Outcome::InstalledWifiMesh(value))) => {
            request.mesh_runtime_id == value.mesh_runtime_id
        }
        (Operation::InspectWifiMesh(request), Some(Outcome::WifiMeshSnapshot(value))) => {
            request.mesh_runtime_id == value.mesh_runtime_id
                && request.mesh_handle == value.mesh_handle
        }
        (Operation::DestroyWifiMesh(_), Some(Outcome::DestroyedWifiMesh(_))) => true,
        _ => false,
    };
    if !matched {
        return Err(HelperProtocolError::Invalid("mesh response owner"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HELPER_PROTOCOL_VERSION, decode_request, encode_request};

    fn install() -> InstallWifiMesh {
        InstallWifiMesh {
            mesh_runtime_id: vec![7; 16],
            parent_interface: "wlan0".into(),
            mesh_id: b"VOLPAROSSA-local".to_vec(),
            frequency_mhz: 2412,
            local_address: vec![192, 168, 247, 1],
            prefix_len: 24,
            maximum_peers: 8,
        }
    }

    #[test]
    fn wifi_mesh_wire_binds_runtime_operation_and_connected_subnet() {
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            operation: Some(helper_request::Operation::InstallWifiMesh(install())),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()[4..]).unwrap(),
            request
        );
        let mut response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            operation_digest: operation_digest(&request).unwrap().to_vec(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "OK".into(),
            outcome: Some(helper_response::Outcome::InstalledWifiMesh(
                InstalledWifiMesh {
                    mesh_runtime_id: vec![7; 16],
                    mesh_handle: vec![3; 32],
                    interface: "vw123abc".into(),
                    ifindex: 2,
                    wiphy: 0,
                },
            )),
        };
        assert!(validate_wifi_mesh_response(&request, &response).is_ok());
        response.request_id[0] ^= 1;
        assert!(validate_wifi_mesh_response(&request, &response).is_err());
        response.request_id = request.request_id.clone();
        let Some(helper_response::Outcome::InstalledWifiMesh(value)) = &mut response.outcome else {
            unreachable!()
        };
        value.mesh_runtime_id[0] ^= 1;
        assert!(validate_wifi_mesh_response(&request, &response).is_err());
        let mut invalid = install();
        invalid.prefix_len = 1;
        assert!(validate_install(&invalid).is_err());
        invalid.local_address = "fd12::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        invalid.prefix_len = 6;
        assert!(validate_install(&invalid).is_err());
        invalid.prefix_len = 64;
        assert!(validate_install(&invalid).is_ok());
    }
}
