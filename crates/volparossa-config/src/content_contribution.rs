use std::{
    net::SocketAddr,
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};

use crate::{ConfigError, validation};

/// Explicit storage and serving consent for verified public downloads, never private traffic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContentContributionConfig {
    /// Automatically contribute public native and freshly authorized cooperative HTTPS objects.
    /// Installation alone never creates a cache or listener.
    pub enabled: bool,
    /// Exact local listener socket; the runtime separately checks its advertised policy endpoint.
    pub bind_address: String,
    /// Canonical, policy-authorized DNS name used by remote consumers.
    pub advertised_hostname: String,
    /// Absolute private cache path. Only this service's owned cache may be reopened.
    pub cache: String,
    /// Maximum stored chunk payload, shared by received objects and incidental replicas.
    pub quota_bytes: u64,
    /// Maximum stored chunks, including small final chunks.
    pub max_entries: u32,
    /// Free filesystem space that must remain before admitting a chunk.
    pub min_free_bytes: u64,
    /// Maximum payload admitted per idle background batch.
    pub max_bytes: u64,
    /// Maximum chunks admitted per idle background batch.
    pub max_chunks: u32,
}

impl Default for ContentContributionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: String::new(),
            advertised_hostname: String::new(),
            cache: String::new(),
            quota_bytes: 64 * 1024 * 1024,
            max_entries: 256,
            min_free_bytes: 256 * 1024 * 1024,
            max_bytes: 1024 * 1024,
            max_chunks: 4,
        }
    }
}

impl ContentContributionConfig {
    pub(crate) fn validate(&self, relay: bool) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !relay {
            return Err(validation(
                "content_contribution.enabled",
                "requires relay participation",
            ));
        }
        let address = self.bind_address.parse::<SocketAddr>().map_err(|_| {
            validation(
                "content_contribution.bind_address",
                "requires an explicit local socket address",
            )
        })?;
        if address.port() < 1024
            || address.ip().is_multicast()
            || address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        {
            return Err(validation(
                "content_contribution.bind_address",
                "requires an unprivileged unicast or wildcard listener",
            ));
        }
        let hostname = &self.advertised_hostname;
        if hostname.len() > 253
            || !hostname.contains('.')
            || hostname.parse::<std::net::IpAddr>().is_ok()
            || hostname.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(validation(
                "content_contribution.advertised_hostname",
                "requires a canonical lowercase DNS name",
            ));
        }
        let path = Path::new(&self.cache);
        if !path.is_absolute()
            || self.cache.len() > 4096
            || self.cache.chars().any(char::is_control)
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || !path
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
        {
            return Err(validation(
                "content_contribution.cache",
                "requires a non-root absolute cache path without parent traversal",
            ));
        }
        if !(256 * 1024..=256 * 1024 * 1024).contains(&self.quota_bytes)
            || !(1..=1024).contains(&self.max_entries)
            || !(64..=1024 * 1024).contains(&self.max_bytes)
            || !(1..=4).contains(&self.max_chunks)
        {
            return Err(validation(
                "content_contribution",
                "requires a bounded cache and a batch of at most four chunks / one MiB",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_contribution_is_explicit_and_bounded() {
        let default = ContentContributionConfig::default();
        assert!(!default.enabled);
        assert!(default.cache.is_empty() && default.bind_address.is_empty());
        assert!(default.validate(false).is_ok());
        let valid = ContentContributionConfig {
            enabled: true,
            bind_address: "0.0.0.0:9443".into(),
            advertised_hostname: "cache.example.test".into(),
            cache: "/var/lib/volparossa/public-cache".into(),
            ..default
        };
        assert!(valid.validate(true).is_ok());
        assert!(valid.validate(false).is_err());
        for cache in ["/", "relative/cache", "/var/../cache", "/cache\n"] {
            assert!(
                ContentContributionConfig {
                    cache: cache.into(),
                    ..valid.clone()
                }
                .validate(true)
                .is_err()
            );
        }
        for hostname in [
            "",
            "127.0.0.1",
            "Cache.example.test",
            "-cache.example.test",
            "cache.example.test.",
        ] {
            assert!(
                ContentContributionConfig {
                    advertised_hostname: hostname.into(),
                    ..valid.clone()
                }
                .validate(true)
                .is_err()
            );
        }
        assert!(
            ContentContributionConfig {
                max_chunks: 5,
                ..valid.clone()
            }
            .validate(true)
            .is_err()
        );
        assert!(
            ContentContributionConfig {
                quota_bytes: 0,
                ..valid.clone()
            }
            .validate(true)
            .is_err()
        );
        assert!(
            ContentContributionConfig {
                bind_address: "0.0.0.0:0".into(),
                ..valid
            }
            .validate(true)
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<ContentContributionConfig>("share_private_traffic: true")
                .is_err()
        );
    }
}
