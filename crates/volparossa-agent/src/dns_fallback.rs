//! Resolver choice is independent of optional DNS proof retention and peer sharing.

use std::sync::Arc;

use volparossa_config::{DnsCacheConfig, DnsFallbackConfig};
use volparossa_udp::{DnsPeerBackend, ExitResolver};

use crate::AgentError;

pub(crate) fn configure(
    config: DnsCacheConfig,
    exit_enabled: bool,
    peers: Option<Arc<dyn DnsPeerBackend>>,
) -> Result<ExitResolver, AgentError> {
    configure_with_assets(
        config,
        exit_enabled,
        peers,
        ExitResolver::private_unbound_assets_installed,
    )
}

fn configure_with_assets(
    config: DnsCacheConfig,
    exit_enabled: bool,
    peers: Option<Arc<dyn DnsPeerBackend>>,
    assets_installed: impl FnOnce() -> bool,
) -> Result<ExitResolver, AgentError> {
    let resolver = ExitResolver::new(config.upstream, peers.filter(|_| config.enabled))
        .with_cache_enabled(config.enabled);
    match config.fallback {
        DnsFallbackConfig::System => Ok(resolver),
        DnsFallbackConfig::Unbound { endpoint } => resolver
            .with_unbound_fallback(endpoint)
            .map_err(|_| AgentError::UnsafeConfig),
        DnsFallbackConfig::UnboundPrivate {} => {
            // All-off and local-only nodes need no native asset and start no worker. Effective
            // roles are loaded before this point; changing roles already requires a restart.
            if exit_enabled && !assets_installed() {
                return Err(AgentError::PrivateDnsWorkerUnavailable);
            }
            resolver
                .with_private_unbound_fallback()
                .map_err(|_| AgentError::UnsafeConfig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentError, DnsCacheConfig, DnsFallbackConfig, configure_with_assets};

    #[test]
    fn private_dns_default_is_inert_without_exit_even_if_worker_is_not_installed() {
        for enabled in [false, true] {
            let resolver = configure_with_assets(
                DnsCacheConfig {
                    enabled,
                    ..DnsCacheConfig::default()
                },
                false,
                None,
                || panic!("an inactive Exit must not require or probe native assets"),
            )
            .unwrap();
            assert!(!resolver.has_shareable_proof(&[0; 32]));
        }
    }

    #[test]
    fn private_dns_effective_exit_checks_assets_even_when_caching_is_disabled() {
        for enabled in [false, true] {
            let config = DnsCacheConfig {
                enabled,
                ..DnsCacheConfig::default()
            };
            assert!(matches!(
                configure_with_assets(config, true, None, || false),
                Err(AgentError::PrivateDnsWorkerUnavailable)
            ));
            assert!(configure_with_assets(config, true, None, || true).is_ok());
        }
    }

    #[test]
    fn private_dns_explicit_system_optout_never_probes_native_assets() {
        let config = DnsCacheConfig {
            enabled: false,
            fallback: DnsFallbackConfig::System,
            ..DnsCacheConfig::default()
        };
        assert!(configure_with_assets(config, true, None, || panic!("explicit system")).is_ok());
    }
}
