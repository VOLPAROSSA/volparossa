//! Explicit direct-radio participation; no automatic channel switching or Internet route.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use volparossa_core::is_local_lan_ip;

use crate::{ConfigError, validation};

/// One operator-configured 20MHz 802.11s adjacency underlay, not an Internet uplink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WifiMeshConfig {
    /// Create a separate owned mesh interface when explicitly starting participation.
    pub enabled: bool,
    /// Acknowledge that 802.11s is open L2: encryption is provided by VOLPAROSSA above it.
    pub acknowledge_open_underlay: bool,
    /// Existing physical wireless interface; it is never replaced or retuned.
    pub parent_interface: String,
    /// Exact common mesh identifier, 1..=32 printable ASCII bytes when enabled.
    pub mesh_id: String,
    /// Explicit center frequency in MHz; hardware/regulatory/coexistence checks are additional.
    pub frequency_mhz: u32,
    /// Explicit, nonconflicting RFC1918 or ULA host address for the new interface.
    pub local_address: String,
    /// Connected subnet prefix; no default route is installed.
    pub prefix_len: u8,
    /// Maximum directly peered stations; kernel mesh forwarding is disabled.
    pub maximum_peers: u16,
}

impl Default for WifiMeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            acknowledge_open_underlay: false,
            parent_interface: String::new(),
            mesh_id: String::new(),
            frequency_mhz: 0,
            local_address: String::new(),
            prefix_len: 0,
            maximum_peers: 8,
        }
    }
}

impl WifiMeshConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=32).contains(&self.maximum_peers) {
            return Err(validation("wifi_mesh.maximum_peers", "must be 1..=32"));
        }
        if !self.enabled {
            return Ok(());
        }
        if !self.acknowledge_open_underlay {
            return Err(validation(
                "wifi_mesh.acknowledge_open_underlay",
                "explicitly acknowledge open L2; this mode does not provide SAE Wi-Fi encryption",
            ));
        }
        let name = self.parent_interface.as_str();
        if !(1..=15).contains(&name.len())
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(validation(
                "wifi_mesh.parent_interface",
                "must be one bounded interface name, not a path",
            ));
        }
        if !(1..=32).contains(&self.mesh_id.len())
            || !self.mesh_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(validation(
                "wifi_mesh.mesh_id",
                "must be 1..=32 visible ASCII bytes",
            ));
        }
        // This is only a shape bound. The kernel backend must verify the actual regulatory
        // channel flags and must not change another interface's active channel.
        if !(2412..=2472).contains(&self.frequency_mhz)
            && !(5000..=5900).contains(&self.frequency_mhz)
            || self.frequency_mhz % 5 != if self.frequency_mhz < 3000 { 2 } else { 0 }
        {
            return Err(validation(
                "wifi_mesh.frequency_mhz",
                "must be an explicit 2.4/5GHz 20MHz channel frequency",
            ));
        }
        let ip: IpAddr = self.local_address.parse().map_err(|_| {
            validation(
                "wifi_mesh.local_address",
                "must be an RFC1918 or ULA literal",
            )
        })?;
        if !is_local_lan_ip(ip)
            || self.prefix_len == 0
            || self.prefix_len > if ip.is_ipv4() { 30 } else { 126 }
        {
            return Err(validation(
                "wifi_mesh.local_address",
                "must be a local host address with a connected non-default subnet",
            ));
        }
        let (first, last) = match ip {
            IpAddr::V4(ip) => {
                let mask = u32::MAX << (32 - self.prefix_len);
                let host = u32::from(ip) & !mask;
                if host == 0 || host == !mask {
                    return Err(validation(
                        "wifi_mesh.local_address",
                        "network and broadcast addresses are not hosts",
                    ));
                }
                (
                    IpAddr::V4((u32::from(ip) & mask).into()),
                    IpAddr::V4((u32::from(ip) | !mask).into()),
                )
            }
            IpAddr::V6(ip) => {
                let mask = u128::MAX << (128 - self.prefix_len);
                (
                    IpAddr::V6((u128::from(ip) & mask).into()),
                    IpAddr::V6((u128::from(ip) | !mask).into()),
                )
            }
        };
        if !is_local_lan_ip(first) || !is_local_lan_ip(last) {
            return Err(validation(
                "wifi_mesh.prefix_len",
                "entire connected subnet must remain RFC1918 or ULA",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn wifi_mesh_requires_explicit_open_layer_and_local_geometry() {
        assert_eq!(
            Config::from_yaml("{}").unwrap().wifi_mesh,
            WifiMeshConfig::default()
        );
        let valid = WifiMeshConfig {
            enabled: true,
            acknowledge_open_underlay: true,
            parent_interface: "wlp4s0".into(),
            mesh_id: "VOLPAROSSA-local".into(),
            frequency_mhz: 2412,
            local_address: "192.168.247.1".into(),
            prefix_len: 24,
            maximum_peers: 8,
        };
        assert!(valid.validate().is_ok());
        for invalid in [
            WifiMeshConfig {
                acknowledge_open_underlay: false,
                ..valid.clone()
            },
            WifiMeshConfig {
                parent_interface: "../wlan0".into(),
                ..valid.clone()
            },
            WifiMeshConfig {
                mesh_id: "bad\nmesh".into(),
                ..valid.clone()
            },
            WifiMeshConfig {
                frequency_mhz: 0,
                ..valid.clone()
            },
            WifiMeshConfig {
                local_address: "8.8.8.8".into(),
                ..valid.clone()
            },
            WifiMeshConfig {
                local_address: "192.168.247.0".into(),
                ..valid.clone()
            },
            WifiMeshConfig {
                local_address: "192.168.247.255".into(),
                ..valid.clone()
            },
            WifiMeshConfig {
                prefix_len: 0,
                ..valid.clone()
            },
            WifiMeshConfig {
                prefix_len: 1,
                ..valid.clone()
            },
            WifiMeshConfig {
                local_address: "fd12:3456::1".into(),
                prefix_len: 6,
                ..valid.clone()
            },
            WifiMeshConfig {
                maximum_peers: 33,
                ..valid.clone()
            },
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
        assert!(
            WifiMeshConfig {
                local_address: "fd12:3456::1".into(),
                prefix_len: 64,
                ..valid
            }
            .validate()
            .is_ok()
        );
    }
}
