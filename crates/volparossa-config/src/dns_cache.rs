use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{ConfigError, validation};

/// Positive DNSSEC sharing uses RAM only and never changes the host's DNS configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCacheConfig {
    /// Permit independently validated positive answers and cache-only peer service.
    /// No roles, network listeners or Internet egress are activated by this flag.
    pub enabled: bool,
    /// Explicit trusted recursive DNS endpoint for collecting authenticated proof material.
    /// None selects no new upstream; ordinary system resolution remains the fallback.
    pub upstream: Option<SocketAddr>,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream: None,
        }
    }
}

impl DnsCacheConfig {
    pub(crate) fn validate(self) -> Result<(), ConfigError> {
        if let Some(upstream) = self.upstream {
            if !self.enabled {
                return Err(validation(
                    "dns_cache.upstream",
                    "requires dns_cache.enabled",
                ));
            }
            if upstream.port() != 53
                || upstream.ip().is_unspecified()
                || upstream.ip().is_multicast()
                || upstream.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
            {
                return Err(validation(
                    "dns_cache.upstream",
                    "requires an explicit unicast DNS endpoint on port 53",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_cache_never_selects_a_hidden_upstream_or_enables_roles() {
        let defaults = crate::Config::default();
        assert!(defaults.dns_cache.enabled);
        assert!(defaults.dns_cache.upstream.is_none());
        assert!(!defaults.roles.client && !defaults.roles.relay && !defaults.roles.exit);
        let configured: DnsCacheConfig = serde_yaml::from_str("upstream: '127.0.0.53:53'").unwrap();
        assert!(configured.validate().is_ok());
        for value in [
            "0.0.0.0:53",
            "224.0.0.1:53",
            "255.255.255.255:53",
            "127.0.0.53:443",
        ] {
            let value = DnsCacheConfig {
                enabled: true,
                upstream: Some(value.parse().unwrap()),
            };
            assert!(value.validate().is_err());
        }
        assert!(
            DnsCacheConfig {
                enabled: false,
                ..configured
            }
            .validate()
            .is_err()
        );
        assert!(serde_yaml::from_str::<DnsCacheConfig>("trust_peer_keys: true").is_err());
    }
}
