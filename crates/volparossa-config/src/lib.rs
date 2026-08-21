//! Strict, fail-closed configuration for all VOLPAROSSA processes.

use std::{collections::HashSet, fmt, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use volparossa_core::OperatorId;

/// Wire protocol version implemented by this release.
pub const PROTOCOL_VERSION: u16 = 3;

/// Maximum number of addresses a node may listen on.
pub const MAX_LISTEN_ADDRESSES: usize = 16;
/// Maximum number of configured bootstrap peers.
pub const MAX_BOOTSTRAP_PEERS: usize = 64;
/// Maximum encoded byte length of one configured network address.
pub const MAX_NETWORK_ADDRESS_BYTES: usize = 2_048;

/// Errors returned while loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read configuration {path}: {source}")]
    Read {
        /// Path that failed.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// YAML was malformed or contained an unknown field.
    #[error("invalid YAML configuration: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// A semantically unsafe or inconsistent setting was found.
    #[error("unsafe or inconsistent configuration at {field}: {message}")]
    Validation {
        /// Dot-separated setting name.
        field: &'static str,
        /// Human-readable reason that contains no secret values.
        message: String,
    },
}

/// Deployment safety mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    /// Reject development keys and all direct-exit debug behaviour.
    #[default]
    Production,
    /// Permit explicitly opted-in local-only development facilities.
    Development,
}

impl fmt::Display for RuntimeMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => formatter.write_str("production"),
            Self::Development => formatter.write_str("development"),
        }
    }
}

/// Complete configuration shared by CLI validation and the agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Production versus explicitly local development operation.
    pub runtime_mode: RuntimeMode,
    /// Overlay identity and discovery settings.
    pub network: NetworkConfig,
    /// Independently enabled node roles.
    pub roles: RolesConfig,
    /// Exit and relay selection parameters.
    pub selection: SelectionConfig,
    /// Operator capacity limits.
    pub capacity: CapacityConfig,
    /// Route-context and interception safety settings.
    pub routing: RoutingConfig,
    /// TCP/MPTCP settings.
    pub tcp: TcpConfig,
    /// General UDP settings.
    pub udp: UdpConfig,
    /// Browser QUIC/MPQUIC settings.
    pub quic: QuicConfig,
    /// Shared whitelist settings.
    pub policy: PolicyConfig,
    /// Local data-minimisation settings.
    pub privacy: PrivacyConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            runtime_mode: RuntimeMode::Production,
            network: NetworkConfig::default(),
            roles: RolesConfig::default(),
            selection: SelectionConfig::default(),
            capacity: CapacityConfig::default(),
            routing: RoutingConfig::default(),
            tcp: TcpConfig::default(),
            udp: UdpConfig::default(),
            quic: QuicConfig::default(),
            policy: PolicyConfig::default(),
            privacy: PrivacyConfig::default(),
        }
    }
}

impl Config {
    /// Parses a YAML document and enforces all cross-field invariants.
    ///
    /// # Errors
    ///
    /// Returns an error when YAML decoding or any safety validation fails.
    pub fn from_yaml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_yaml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses, and validates a YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, YAML decoding fails, or validation fails.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml(&input)
    }

    /// Serialises a configuration for an operator-facing example or migration.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or YAML serialisation fails.
    pub fn to_yaml(&self) -> Result<String, ConfigError> {
        self.validate()?;
        serde_yaml::to_string(self).map_err(ConfigError::from)
    }

    /// Validates bounds and safety-sensitive relationships.
    ///
    /// # Errors
    ///
    /// Returns an error when a field or cross-field safety invariant is violated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_exact_version(self.network.protocol_version)?;
        if let Some(operator_id) = self.network.operator_id.as_deref() {
            OperatorId::new(operator_id).map_err(|_| {
                validation(
                    "network.operator_id",
                    "must be 1..=128 ASCII letters, digits, '-', '_', '.' or ':'",
                )
            })?;
        } else if self.roles.relay || self.roles.exit {
            return Err(validation(
                "network.operator_id",
                "an enabled relay or exit requires an explicit operator identity",
            ));
        }
        validate_range(
            "network.candidate_pool_size",
            self.network.candidate_pool_size,
            10,
            10_000,
        )?;
        validate_range(
            "network.advertisement_ttl_seconds",
            self.network.advertisement_ttl_seconds,
            30,
            3_600,
        )?;
        validate_network_addresses(&self.network)?;
        validate_selection(&self.selection)?;
        validate_capacity(self.roles, &self.capacity)?;
        validate_routing(self.runtime_mode, &self.routing)?;
        validate_tcp(self.tcp)?;
        validate_udp(&self.udp)?;
        validate_quic(self.quic, &self.selection)?;
        validate_policy(self.runtime_mode, self.roles, &self.policy)?;
        validate_privacy(self.runtime_mode, self.privacy)?;
        Ok(())
    }

    /// Returns true only for the conspicuous, explicit local debug bypass.
    #[must_use]
    pub fn direct_exit_debug_enabled(&self) -> bool {
        self.runtime_mode == RuntimeMode::Development && self.routing.direct_exit_debug
    }
}

/// Overlay discovery configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Human-readable network name.
    pub name: String,
    /// Strict wire protocol version.
    pub protocol_version: u16,
    /// Canonical operator identity; required only when relay or exit service is enabled.
    pub operator_id: Option<String>,
    /// libp2p listen multiaddresses; empty delegates to safe agent defaults.
    pub listen_addresses: Vec<String>,
    /// Replaceable bootstrap peer multiaddresses/peerlinks.
    pub bootstrap_peers: Vec<String>,
    /// Approximate bounded local candidate pool size.
    pub candidate_pool_size: usize,
    /// Maximum advertisement lifetime.
    pub advertisement_ttl_seconds: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            name: "VOLPAROSSA".into(),
            protocol_version: PROTOCOL_VERSION,
            operator_id: None,
            listen_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            candidate_pool_size: 200,
            advertisement_ttl_seconds: 300,
        }
    }
}

/// Independently enabled roles. Exit is deliberately off by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RolesConfig {
    /// Permit local client sessions.
    pub client: bool,
    /// Permit authorised relay forwarding.
    pub relay: bool,
    /// Permit policy-limited Internet egress.
    pub exit: bool,
}

impl Default for RolesConfig {
    fn default() -> Self {
        Self {
            client: true,
            relay: false,
            exit: false,
        }
    }
}

/// Path selection settings.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SelectionConfig {
    /// Target number of data-carrying MPTCP/MPQUIC paths.
    pub active_multipath_paths: u8,
    /// Hard minimum for required multipath.
    pub minimum_multipath_paths: u8,
    /// Hard maximum paths in one route context.
    pub maximum_multipath_paths: u8,
    /// Authorised and reachable paths that do not normally carry payload.
    pub warm_backup_paths: u8,
    /// Maximum RTT difference between active paths.
    pub maximum_rtt_spread_ms: u32,
    /// Fraction selected from new or poorly measured candidates.
    pub exploration_ratio: f64,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            active_multipath_paths: 4,
            minimum_multipath_paths: 2,
            maximum_multipath_paths: 8,
            warm_backup_paths: 2,
            maximum_rtt_spread_ms: 20,
            exploration_ratio: 0.10,
        }
    }
}

/// Explicit operator resource limits; zero means the corresponding role cannot accept sessions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapacityConfig {
    /// Relay upload Mbps ceiling.
    pub relay_upload_limit_mbps: u32,
    /// Relay download Mbps ceiling.
    pub relay_download_limit_mbps: u32,
    /// Exit upload Mbps ceiling.
    pub exit_upload_limit_mbps: u32,
    /// Exit download Mbps ceiling.
    pub exit_download_limit_mbps: u32,
    /// Maximum simultaneous relay sessions; zero disables serving.
    pub maximum_relay_sessions: u32,
    /// Maximum simultaneous exit sessions; zero disables serving.
    pub maximum_exit_sessions: u32,
}

/// Route context and interception configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// Default route-context lifetime.
    pub context_ttl_seconds: u64,
    /// Bounded LRU context count.
    pub maximum_active_contexts: usize,
    /// Deny traffic that cannot enter a valid VOLPAROSSA route.
    pub kill_switch: bool,
    /// Explicitly unsafe development-only client-to-exit bypass.
    pub direct_exit_debug: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            context_ttl_seconds: 600,
            maximum_active_contexts: 64,
            kill_switch: true,
            direct_exit_debug: false,
        }
    }
}

/// Supported TCP tunnel type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpTransport {
    /// Linux MPTCP socket with selected relay-bound subflows.
    #[default]
    Mptcp,
}

/// Supported MPTCP path-manager backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MptcpPathManager {
    /// Kernel path manager, the Debian 13 default.
    #[default]
    Kernel,
    /// Optional mptcpd integration, only after a proven kernel limitation.
    Mptcpd,
}

/// TCP proxy settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpConfig {
    /// Enable transparent TCP handling.
    pub enabled: bool,
    /// Required transport.
    pub transport: TcpTransport,
    /// Selected MPTCP path manager.
    pub mptcp_path_manager: MptcpPathManager,
    /// Development escape hatch; production validation always rejects it.
    pub allow_plain_tcp_fallback: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: TcpTransport::Mptcp,
            mptcp_path_manager: MptcpPathManager::Kernel,
            allow_plain_tcp_fallback: false,
        }
    }
}

/// General UDP tunnel type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpTransport {
    /// MASQUE/QUIC DATAGRAM constrained to one relay path.
    #[default]
    SinglePathQuic,
}

/// General UDP configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpConfig {
    /// Enable general UDP proxying.
    pub enabled: bool,
    /// Required transport.
    pub transport: UdpTransport,
    /// Association idle timeout.
    pub idle_timeout_seconds: u64,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: UdpTransport::SinglePathQuic,
            idle_timeout_seconds: 60,
        }
    }
}

/// QUIC/HTTP3 tunnel type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicTransport {
    /// MASQUE CONNECT-IP over genuine Multipath QUIC.
    #[default]
    MasqueConnectIpMpquic,
}

/// Browser QUIC settings.
// These booleans are independent security-policy switches in the stable operator-facing schema;
// combining them into a state enum would hide invalid combinations that validation must reject.
#[allow(
    clippy::struct_excessive_bools,
    reason = "stable security-policy schema"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
    /// Enable browser QUIC classification and tunnelling.
    pub enabled: bool,
    /// Required outer transport.
    pub transport: QuicTransport,
    /// Fail closed without the requested number of genuine paths.
    pub require_multipath: bool,
    /// Minimum data-carrying paths.
    pub minimum_paths: u8,
    /// Explicit degraded fallback; rejected by production validation.
    pub allow_degraded_single_path: bool,
    /// Redundancy is excluded from v1 and therefore must remain false.
    pub redundancy: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: QuicTransport::MasqueConnectIpMpquic,
            require_multipath: true,
            minimum_paths: 2,
            allow_degraded_single_path: false,
            redundancy: false,
        }
    }
}

/// Threshold whitelist verification settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Reject traffic whenever policy cannot be proven.
    pub fail_closed: bool,
    /// Local path to the threshold-signed canonical manifest.
    pub manifest_path: String,
    /// Required number of distinct trusted maintainer signatures.
    pub minimum_signatures: u8,
    /// Refuse ECH while the requested hostname cannot be verified.
    pub reject_ech: bool,
    /// Refuse TLS/QUIC without a verifiable SNI.
    pub reject_unverifiable_sni: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            fail_closed: true,
            manifest_path: String::new(),
            minimum_signatures: 3,
            reject_ech: true,
            reject_unverifiable_sni: true,
        }
    }
}

/// Privacy-sensitive persistence and metrics controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// Persist full destination hostnames; rejected outside development.
    pub persist_domain_logs: bool,
    /// Persist destination IPs; rejected outside development.
    pub persist_destination_ips: bool,
    /// Enable local-only aggregate metrics.
    pub metrics_enabled: bool,
    /// Fixed loopback TCP port for the label-free local metrics endpoint.
    pub metrics_port: u16,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            persist_domain_logs: false,
            persist_destination_ips: false,
            metrics_enabled: true,
            metrics_port: 9_767,
        }
    }
}

fn validation(field: &'static str, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        field,
        message: message.into(),
    }
}

fn validate_exact_version(version: u16) -> Result<(), ConfigError> {
    if version != PROTOCOL_VERSION {
        return Err(validation(
            "network.protocol_version",
            format!("expected exactly {PROTOCOL_VERSION}, got {version}"),
        ));
    }
    Ok(())
}

fn validate_network_addresses(network: &NetworkConfig) -> Result<(), ConfigError> {
    validate_address_list(
        "network.listen_addresses",
        &network.listen_addresses,
        MAX_LISTEN_ADDRESSES,
    )?;
    validate_address_list(
        "network.bootstrap_peers",
        &network.bootstrap_peers,
        MAX_BOOTSTRAP_PEERS,
    )
}

fn validate_address_list(
    field: &'static str,
    values: &[String],
    maximum_count: usize,
) -> Result<(), ConfigError> {
    if values.len() > maximum_count {
        return Err(validation(field, "contains too many addresses"));
    }

    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        if value.is_empty()
            || value.len() > MAX_NETWORK_ADDRESS_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(validation(
                field,
                "addresses must be bounded non-empty printable ASCII",
            ));
        }
        if !seen.insert(value.as_str()) {
            return Err(validation(field, "duplicate addresses are not allowed"));
        }
    }
    Ok(())
}

fn validate_range<T>(field: &'static str, value: T, min: T, max: T) -> Result<(), ConfigError>
where
    T: Copy + fmt::Display + PartialOrd,
{
    if value < min || value > max {
        return Err(validation(
            field,
            format!("must be between {min} and {max}, got {value}"),
        ));
    }
    Ok(())
}

fn validate_selection(selection: &SelectionConfig) -> Result<(), ConfigError> {
    validate_range(
        "selection.minimum_multipath_paths",
        selection.minimum_multipath_paths,
        2,
        8,
    )?;
    validate_range(
        "selection.maximum_multipath_paths",
        selection.maximum_multipath_paths,
        2,
        8,
    )?;
    if selection.minimum_multipath_paths > selection.active_multipath_paths
        || selection.active_multipath_paths > selection.maximum_multipath_paths
    {
        return Err(validation(
            "selection.active_multipath_paths",
            "must be between minimum_multipath_paths and maximum_multipath_paths",
        ));
    }
    validate_range(
        "selection.warm_backup_paths",
        selection.warm_backup_paths,
        0,
        8,
    )?;
    if selection
        .active_multipath_paths
        .saturating_add(selection.warm_backup_paths)
        > selection.maximum_multipath_paths
    {
        return Err(validation(
            "selection.warm_backup_paths",
            "active_multipath_paths plus warm_backup_paths cannot exceed maximum_multipath_paths",
        ));
    }
    validate_range(
        "selection.maximum_rtt_spread_ms",
        selection.maximum_rtt_spread_ms,
        1,
        1_000,
    )?;
    if !selection.exploration_ratio.is_finite()
        || !(0.01..=0.50).contains(&selection.exploration_ratio)
    {
        return Err(validation(
            "selection.exploration_ratio",
            "must be finite and between 0.01 and 0.50",
        ));
    }
    Ok(())
}

fn validate_capacity(roles: RolesConfig, capacity: &CapacityConfig) -> Result<(), ConfigError> {
    if roles.relay
        && (capacity.maximum_relay_sessions == 0
            || capacity.relay_upload_limit_mbps == 0
            || capacity.relay_download_limit_mbps == 0)
    {
        return Err(validation(
            "capacity.maximum_relay_sessions",
            "relay role requires positive session, upload, and download limits",
        ));
    }
    if roles.exit
        && (capacity.maximum_exit_sessions == 0
            || capacity.exit_upload_limit_mbps == 0
            || capacity.exit_download_limit_mbps == 0)
    {
        return Err(validation(
            "capacity.maximum_exit_sessions",
            "exit role requires positive session, upload, and download limits",
        ));
    }
    Ok(())
}

fn validate_routing(mode: RuntimeMode, routing: &RoutingConfig) -> Result<(), ConfigError> {
    validate_range(
        "routing.context_ttl_seconds",
        routing.context_ttl_seconds,
        60,
        3_600,
    )?;
    validate_range(
        "routing.maximum_active_contexts",
        routing.maximum_active_contexts,
        1,
        4_096,
    )?;
    if !routing.kill_switch && mode == RuntimeMode::Production {
        return Err(validation(
            "routing.kill_switch",
            "must remain enabled in production",
        ));
    }
    if routing.direct_exit_debug && mode != RuntimeMode::Development {
        return Err(validation(
            "routing.direct_exit_debug",
            "direct client-exit connections are development-only and disclose the client address",
        ));
    }
    Ok(())
}

fn validate_tcp(tcp: TcpConfig) -> Result<(), ConfigError> {
    if tcp.allow_plain_tcp_fallback {
        return Err(validation(
            "tcp.allow_plain_tcp_fallback",
            "silent ordinary-TCP fallback is never accepted by the v1 configuration",
        ));
    }
    Ok(())
}

fn validate_udp(udp: &UdpConfig) -> Result<(), ConfigError> {
    validate_range("udp.idle_timeout_seconds", udp.idle_timeout_seconds, 5, 600)
}

fn validate_quic(quic: QuicConfig, selection: &SelectionConfig) -> Result<(), ConfigError> {
    if quic.redundancy {
        return Err(validation(
            "quic.redundancy",
            "duplication and FEC are explicitly outside v1",
        ));
    }
    if quic.enabled && (!quic.require_multipath || quic.minimum_paths < 2) {
        return Err(validation(
            "quic.require_multipath",
            "enabled browser QUIC must require at least two genuine paths",
        ));
    }
    if quic.minimum_paths > selection.maximum_multipath_paths {
        return Err(validation(
            "quic.minimum_paths",
            "cannot exceed selection.maximum_multipath_paths",
        ));
    }
    if quic.allow_degraded_single_path {
        return Err(validation(
            "quic.allow_degraded_single_path",
            "unsafe single-path downgrade is disabled in the v1 configuration",
        ));
    }
    Ok(())
}

fn validate_policy(
    mode: RuntimeMode,
    roles: RolesConfig,
    policy: &PolicyConfig,
) -> Result<(), ConfigError> {
    if !policy.fail_closed {
        return Err(validation(
            "policy.fail_closed",
            "whitelist enforcement must fail closed",
        ));
    }
    if policy.minimum_signatures < 3 {
        return Err(validation(
            "policy.minimum_signatures",
            "at least three distinct maintainer signatures are required",
        ));
    }
    if !policy.reject_ech || !policy.reject_unverifiable_sni {
        return Err(validation(
            "policy.reject_ech",
            "v1 must reject ECH and unverifiable SNI",
        ));
    }
    if roles.exit && policy.manifest_path.trim().is_empty() {
        return Err(validation(
            "policy.manifest_path",
            "an enabled exit requires an explicit signed manifest",
        ));
    }
    if mode == RuntimeMode::Production && policy.manifest_path.contains("development") {
        return Err(validation(
            "policy.manifest_path",
            "production mode refuses paths marked as development policy",
        ));
    }
    Ok(())
}

fn validate_privacy(mode: RuntimeMode, privacy: PrivacyConfig) -> Result<(), ConfigError> {
    if mode == RuntimeMode::Production
        && (privacy.persist_domain_logs || privacy.persist_destination_ips)
    {
        return Err(validation(
            "privacy.persist_domain_logs",
            "production mode forbids durable destination metadata",
        ));
    }
    if privacy.metrics_enabled && privacy.metrics_port == 0 {
        return Err(validation(
            "privacy.metrics_port",
            "enabled metrics require a non-zero loopback port",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_and_match_wire_v3() {
        let config = Config::default();
        config.validate().expect("defaults must validate");
        assert_eq!(config.network.protocol_version, 3);
        assert_eq!(config.network.operator_id, None);
        assert!(config.roles.client);
        assert!(!config.roles.relay);
        assert!(!config.roles.exit);
        assert!(config.routing.kill_switch);
        assert!(!config.routing.direct_exit_debug);
        assert!(config.quic.require_multipath);
        assert_eq!(config.quic.minimum_paths, 2);
        assert!(!config.quic.allow_degraded_single_path);
        assert!(!config.quic.redundancy);
        assert!(config.policy.fail_closed);
    }

    #[test]
    fn shipped_default_yaml_is_the_validated_safe_default() {
        let shipped = include_str!("../../../config/examples/default.yaml");
        let actual = Config::from_yaml(shipped).expect("shipped default YAML must validate");
        assert_eq!(actual, Config::default());
    }

    #[test]
    fn unknown_safety_field_is_rejected() {
        let error = Config::from_yaml("routing:\n  permit_leaks: true\n")
            .expect_err("unknown field must fail");
        assert!(matches!(error, ConfigError::Yaml(_)));
    }

    #[test]
    fn v1_v2_and_unknown_wire_versions_are_rejected() {
        for version in [1, 2, 4] {
            let yaml = format!("network:\n  protocol_version: {version}\n");
            assert!(matches!(
                Config::from_yaml(&yaml),
                Err(ConfigError::Validation {
                    field: "network.protocol_version",
                    ..
                })
            ));
        }
    }

    #[test]
    fn operator_id_uses_the_core_canonical_bound_without_client_placeholder() {
        let mut config = Config::default();
        config.network.operator_id = Some("a".repeat(128));
        config.validate().expect("128-byte canonical operator ID");
        config.network.operator_id = Some("a".repeat(129));
        assert!(config.validate().is_err());
        config.network.operator_id = Some("operator with spaces".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn network_address_lists_are_bounded_printable_and_unique() {
        let mut config = Config::default();
        config.network.listen_addresses = (0..=MAX_LISTEN_ADDRESSES)
            .map(|index| format!("/ip6/::1/tcp/{}", 4_000 + index))
            .collect();
        assert!(config.validate().is_err());

        config.network.listen_addresses = vec![
            "/ip6/::1/tcp/4001".to_owned(),
            "/ip6/::1/tcp/4001".to_owned(),
        ];
        assert!(config.validate().is_err());

        config.network.listen_addresses.clear();
        config.network.bootstrap_peers = (0..=MAX_BOOTSTRAP_PEERS)
            .map(|index| format!("/dns/bootstrap-{index}.invalid/tcp/443"))
            .collect();
        assert!(config.validate().is_err());

        config.network.bootstrap_peers = vec!["not printable because space".to_owned()];
        assert!(config.validate().is_err());
        config.network.bootstrap_peers = vec!["x".repeat(MAX_NETWORK_ADDRESS_BYTES + 1)];
        assert!(config.validate().is_err());
    }

    #[test]
    fn exit_requires_explicit_limits_and_manifest() {
        let mut config = Config::default();
        config.roles.exit = true;
        assert!(config.validate().is_err());

        config.capacity.maximum_exit_sessions = 10;
        config.capacity.exit_upload_limit_mbps = 100;
        config.capacity.exit_download_limit_mbps = 100;
        assert!(config.validate().is_err());

        config.policy.manifest_path = "/etc/volparossa/policy.cbor".into();
        assert!(config.validate().is_err());

        config.network.operator_id = Some("operator-a".to_owned());
        config.validate().expect("fully explicit exit is valid");
    }

    #[test]
    fn production_rejects_direct_exit_and_metadata() {
        let mut config = Config::default();
        config.routing.direct_exit_debug = true;
        assert!(config.validate().is_err());

        config.routing.direct_exit_debug = false;
        config.privacy.persist_domain_logs = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn enabled_metrics_require_a_stable_loopback_port() {
        let mut config = Config::default();
        config.privacy.metrics_port = 0;
        assert!(config.validate().is_err());
        config.privacy.metrics_enabled = false;
        config
            .validate()
            .expect("disabled metrics need no listener");
    }

    #[test]
    fn development_direct_exit_is_explicit_and_detectable() {
        let mut config = Config {
            runtime_mode: RuntimeMode::Development,
            ..Config::default()
        };
        config.routing.direct_exit_debug = true;
        config
            .validate()
            .expect("explicit development bypass validates");
        assert!(config.direct_exit_debug_enabled());
    }

    #[test]
    fn no_plain_tcp_or_single_path_quic_downgrade() {
        let mut config = Config::default();
        config.tcp.allow_plain_tcp_fallback = true;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.quic.allow_degraded_single_path = true;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.quic.minimum_paths = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn active_and_warm_paths_fit_the_route_context_maximum() {
        let mut config = Config::default();
        config.selection.active_multipath_paths = 7;
        config.selection.warm_backup_paths = 2;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Validation {
                field: "selection.warm_backup_paths",
                ..
            })
        ));

        config.selection.active_multipath_paths = 6;
        config
            .validate()
            .expect("six active plus two warm paths fit the maximum of eight");
    }

    #[test]
    fn round_trip_preserves_a_valid_config() {
        let expected = Config::default();
        let yaml = expected.to_yaml().expect("serialize");
        let actual = Config::from_yaml(&yaml).expect("parse");
        assert_eq!(actual, expected);
    }
}
