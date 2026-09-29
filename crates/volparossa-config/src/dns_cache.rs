use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{ConfigError, validation};

/// Explicit Exit-side fallback; configuring it never installs or starts a resolver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum DnsFallbackConfig {
    /// Preserve the existing OS resolver behavior for existing configurations.
    #[default]
    System,
    /// Use only an operator-provisioned trusted Exit-side Unbound service on a high loopback port.
    Unbound {
        /// This endpoint needs deployment isolation; loopback alone is not access control.
        endpoint: SocketAddr,
    },
    /// Packaged Exit-owned libunbound worker, with private inherited pipes and no DNS listener.
    UnboundPrivate {},
}

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
    /// Explicit fallback selection; Unbound failure never falls through to the OS resolver.
    pub fallback: DnsFallbackConfig,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream: None,
            fallback: DnsFallbackConfig::System,
        }
    }
}

impl DnsCacheConfig {
    pub(crate) fn validate(self) -> Result<(), ConfigError> {
        if matches!(self.fallback, DnsFallbackConfig::UnboundPrivate {})
            && (!self.enabled || self.upstream.is_some())
        {
            return Err(validation(
                "dns_cache.fallback",
                "private Unbound requires enabled cache and no separate upstream",
            ));
        }
        if let DnsFallbackConfig::Unbound { endpoint } = self.fallback {
            if !self.enabled || self.upstream.is_some() {
                return Err(validation(
                    "dns_cache.fallback",
                    "Unbound requires enabled cache and no separate upstream",
                ));
            }
            if !endpoint.ip().is_loopback() || endpoint.port() <= 1024 {
                return Err(validation(
                    "dns_cache.fallback.endpoint",
                    "requires an explicit loopback endpoint above port 1024",
                ));
            }
        }
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
                fallback: DnsFallbackConfig::System,
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

    #[test]
    fn unbound_is_explicit_loopback_only_and_never_a_second_hidden_upstream() {
        let configured: DnsCacheConfig =
            serde_yaml::from_str("fallback: { mode: unbound, endpoint: '127.0.0.1:5335' }")
                .unwrap();
        assert!(configured.validate().is_ok());
        assert_eq!(
            DnsCacheConfig::default().fallback,
            DnsFallbackConfig::System
        );
        for endpoint in [
            "127.0.0.1:53",
            "127.0.0.1:0",
            "0.0.0.0:5335",
            "1.1.1.1:5335",
        ] {
            let value = DnsCacheConfig {
                fallback: DnsFallbackConfig::Unbound {
                    endpoint: endpoint.parse().unwrap(),
                },
                ..configured
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
        assert!(
            DnsCacheConfig {
                upstream: Some("127.0.0.53:53".parse().unwrap()),
                ..configured
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<DnsCacheConfig>(
                "fallback: { mode: unbound, endpoint: '127.0.0.1:5335', allow_os_fallback: true }",
            )
            .is_err()
        );
    }

    #[test]
    fn private_unbound_never_accepts_a_worker_path_or_second_upstream() {
        let configured: DnsCacheConfig =
            serde_yaml::from_str("fallback: { mode: unbound_private }").unwrap();
        assert!(configured.validate().is_ok());
        assert_eq!(configured.fallback, DnsFallbackConfig::UnboundPrivate {});
        assert!(
            DnsCacheConfig {
                enabled: false,
                ..configured
            }
            .validate()
            .is_err()
        );
        assert!(
            DnsCacheConfig {
                upstream: Some("127.0.0.53:53".parse().unwrap()),
                ..configured
            }
            .validate()
            .is_err()
        );
        for field in [
            "executable: /tmp/custom",
            "endpoint: '127.0.0.1:5335'",
            "allow_os_fallback: true",
        ] {
            assert!(
                serde_yaml::from_str::<DnsCacheConfig>(&format!(
                    "fallback: {{ mode: unbound_private, {field} }}"
                ))
                .is_err()
            );
        }
    }
}
