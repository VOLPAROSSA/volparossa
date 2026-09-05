//! Connected local addressing only; refuse overlap before adding a new kernel route.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::super::{
    HardDeadline, KernelError, NLMSG_HEADER_LEN, NetlinkClient, attributes, read_u32,
};
use super::WifiMeshConfig;
use super::netlink::{dump, field, number, required};

const RTM_GETADDR: u16 = 22;
const RTM_NEWADDR: u16 = 20;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWROUTE: u16 = 24;

pub(super) fn validate(config: &WifiMeshConfig) -> Result<(), KernelError> {
    let bytes = config.local_address.as_slice();
    let (bits, value) = value(bytes)?;
    if config.prefix_len == 0 || config.prefix_len > bits - 2 {
        return Err(KernelError::Invalid);
    }
    let host_mask = host_mask(bits - config.prefix_len);
    let network = value & !host_mask;
    if !local(bits, network)
        || !local(bits, network | host_mask)
        || value == network
        || (bits == 32 && value == network | host_mask)
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

fn local(bits: u8, value: u128) -> bool {
    let ip = if bits == 32 {
        let Ok(value) = u32::try_from(value) else {
            return false;
        };
        IpAddr::V4(Ipv4Addr::from(value))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    };
    volparossa_core::is_local_lan_ip(ip)
}

fn value(bytes: &[u8]) -> Result<(u8, u128), KernelError> {
    match bytes {
        [a, b, c, d] => Ok((32, u128::from(u32::from_be_bytes([*a, *b, *c, *d])))),
        bytes if bytes.len() == 16 => Ok((
            128,
            u128::from_be_bytes(bytes.try_into().map_err(|_| KernelError::Invalid)?),
        )),
        _ => Err(KernelError::Invalid),
    }
}

fn host_mask(bits: u8) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    }
}

fn overlaps(
    left: &[u8],
    left_prefix: u8,
    right: &[u8],
    right_prefix: u8,
) -> Result<bool, KernelError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    let (bits, left) = value(left)?;
    let (_, right) = value(right)?;
    if left_prefix > bits || right_prefix > bits {
        return Err(KernelError::Malformed);
    }
    let mask = !host_mask(bits - left_prefix.min(right_prefix));
    Ok(left & mask == right & mask)
}

fn family(config: &WifiMeshConfig) -> u8 {
    if config.local_address.len() == 4 {
        2 // Linux AF_INET
    } else {
        10 // Linux AF_INET6
    }
}

fn address_dump(
    route: &mut NetlinkClient,
    config: &WifiMeshConfig,
    deadline: HardDeadline,
) -> Result<Vec<Vec<u8>>, KernelError> {
    let mut request = [0_u8; 8];
    request[0] = family(config);
    dump(route, RTM_GETADDR, RTM_NEWADDR, &request, deadline)
}

fn route_dump(
    route: &mut NetlinkClient,
    config: &WifiMeshConfig,
    deadline: HardDeadline,
) -> Result<Vec<Vec<u8>>, KernelError> {
    let mut request = [0_u8; 12];
    request[0] = family(config);
    dump(route, RTM_GETROUTE, RTM_NEWROUTE, &request, deadline)
}

pub(super) fn prove_subnet_available(
    route: &mut NetlinkClient,
    config: &WifiMeshConfig,
    deadline: HardDeadline,
) -> Result<(), KernelError> {
    for frame in address_dump(route, config, deadline)? {
        let payload = frame
            .get(NLMSG_HEADER_LEN..)
            .filter(|value| value.len() >= 8)
            .ok_or(KernelError::Malformed)?;
        if payload[0] != family(config) {
            continue;
        }
        let fields = attributes(&payload[8..])?;
        let address = field(&fields, 2)?
            .or(field(&fields, 1)?)
            .ok_or(KernelError::Malformed)?;
        if overlaps(
            &config.local_address,
            config.prefix_len,
            address,
            payload[1],
        )? {
            return Err(KernelError::Invalid);
        }
    }
    for frame in route_dump(route, config, deadline)? {
        let payload = frame
            .get(NLMSG_HEADER_LEN..)
            .filter(|value| value.len() >= 12)
            .ok_or(KernelError::Malformed)?;
        if payload[0] != family(config) || payload[1] == 0 {
            continue;
        }
        let fields = attributes(&payload[12..])?;
        if overlaps(
            &config.local_address,
            config.prefix_len,
            required(&fields, 1)?,
            payload[1],
        )? {
            return Err(KernelError::Invalid);
        }
    }
    Ok(())
}

pub(super) fn verify_address(
    route: &mut NetlinkClient,
    index: u32,
    config: &WifiMeshConfig,
    deadline: HardDeadline,
) -> Result<(), KernelError> {
    let mut found = false;
    for frame in address_dump(route, config, deadline)? {
        let payload = frame
            .get(NLMSG_HEADER_LEN..)
            .filter(|value| value.len() >= 8)
            .ok_or(KernelError::Malformed)?;
        if payload[0] != family(config) || read_u32(payload, 4) != Some(index) {
            continue;
        }
        let fields = attributes(&payload[8..])?;
        let address = field(&fields, 2)?
            .or(field(&fields, 1)?)
            .ok_or(KernelError::Malformed)?;
        if address == config.local_address && payload[1] == config.prefix_len {
            let flags = field(&fields, 8)?
                .map(number)
                .transpose()?
                .unwrap_or(u32::from(payload[2]));
            if flags & 8 != 0 || found {
                return Err(KernelError::Invalid);
            } // IFA_F_DADFAILED
            found = true;
        }
    }
    if !found {
        return Err(KernelError::Invalid);
    }
    let (_, address) = value(&config.local_address)?;
    let bits = if config.local_address.len() == 4 {
        32
    } else {
        128
    };
    let network = address & !host_mask(bits - config.prefix_len);
    for frame in route_dump(route, config, deadline)? {
        let payload = frame
            .get(NLMSG_HEADER_LEN..)
            .filter(|value| value.len() >= 12)
            .ok_or(KernelError::Malformed)?;
        if payload[0] != family(config)
            || payload[1] != config.prefix_len
            || payload[5] != 2
            || payload[7] != 1
        {
            continue;
        }
        let fields = attributes(&payload[12..])?;
        if field(&fields, 4)?.map(number).transpose()? == Some(index)
            && field(&fields, 5)?.is_none()
            && value(required(&fields, 1)?)?.1 == network
        {
            return Ok(());
        }
    }
    Err(KernelError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_connected_subnet_must_not_escape_private_ranges_or_overlap() {
        let mut config = super::super::tests::config();
        validate(&config).unwrap();
        config.prefix_len = 1;
        assert!(validate(&config).is_err());
        config.prefix_len = 24;
        config.local_address = vec![192, 168, 247, 0];
        assert!(validate(&config).is_err());
        config.local_address = vec![192, 168, 247, 255];
        assert!(validate(&config).is_err());
        config.local_address = Ipv6Addr::from(0xfd12_3456_0000_0000_0000_0000_0000_0001_u128)
            .octets()
            .to_vec();
        config.prefix_len = 64;
        validate(&config).unwrap();
        config.prefix_len = 6;
        assert!(validate(&config).is_err());
        assert!(overlaps(&[192, 168, 247, 1], 24, &[192, 168, 247, 2], 30).unwrap());
        assert!(!overlaps(&[192, 168, 247, 1], 24, &[192, 168, 246, 2], 24).unwrap());
    }
}
