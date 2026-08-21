//! Bounded, read-only host prerequisite diagnostics.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use volparossa_config::{Config, MptcpPathManager, RuntimeMode};
use volparossa_policy::{
    DEFAULT_MAINTAINER_COUNT, DEFAULT_MAXIMUM_CLOCK_SKEW_MS, DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS,
    MAX_SIGNED_MANIFEST_BYTES, MaintainerEnvironment, PolicyMode, TrustStore, TrustedMaintainer,
    VerificationPolicy, verify_manifest,
};
use volparossa_quic::NATIVE_API_VERSION;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_KERNEL_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROC_BYTES: usize = 2 * 1024 * 1024;
const MAX_SYSCTL_BYTES: usize = 4 * 1024;
const MAX_TRUST_FILE_BYTES: usize = 64 * 1024;
const MAX_UNIT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_DETAIL_BYTES: usize = 512;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_MPQUIC_BINARY: &str = "/usr/libexec/volparossa/volparossa-mpquic";
const POLICY_TRUST_FILE: &str = "policy-maintainers.json";
const TRUST_SCHEMA_VERSION: u32 = 1;
const RESERVED_TABLE_MIN: u64 = 7_600;
const RESERVED_TABLE_MAX: u64 = 7_699;
const RESERVED_MARK_MIN: u64 = 0x7600;
const RESERVED_MARK_MAX: u64 = 0x76ff;
const OVERLAY_PREFIX: [u8; 16] = [
    0xfd, 0x76, 0x6f, 0x6c, 0x70, 0x61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const OVERLAY_PREFIX_LENGTH: u8 = 48;

/// Result category for one read-only diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Prerequisite is present.
    Pass,
    /// Operation may be degraded or needs operator review.
    Warn,
    /// Safe operation is impossible.
    Fail,
}

/// One privacy-safe diagnostic result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Check {
    /// Stable diagnostic name.
    pub name: &'static str,
    /// Result category.
    pub status: CheckStatus,
    /// Bounded non-secret explanation.
    pub detail: String,
}

/// Complete doctor report.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    /// Individual checks.
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// True when no required prerequisite failed.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }
}

/// Performs diagnostics without binding or connecting sockets and without changing host state.
#[must_use]
pub fn run(config_path: &Path) -> DoctorReport {
    let loaded = load_configuration(config_path);
    let config = loaded.config.as_ref();
    let release = read_trimmed(Path::new("/proc/sys/kernel/osrelease"), 256).ok();
    let now_ms = unix_millis().ok();
    let mut checks = vec![
        operating_system_check(),
        architecture_check(std::env::consts::ARCH),
        kernel_check(release.as_deref()),
        mptcp_check(),
        sysctl_check(
            "mptcp_enabled",
            Path::new("/proc/sys/net/mptcp/enabled"),
            "1",
        ),
        mptcp_path_manager_check(config),
        wireguard_check(release.as_deref()),
        nftables_kernel_check(release.as_deref()),
        executable_check(
            "nftables_tool",
            &["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"],
        ),
        executable_check(
            "iproute2_tool",
            &["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip"],
        ),
        udp_check(false),
        udp_check(true),
        sysctl_check(
            "ipv6_enabled",
            Path::new("/proc/sys/net/ipv6/conf/all/disable_ipv6"),
            "0",
        ),
        sysctl_check(
            "ipv6_new_interfaces_enabled",
            Path::new("/proc/sys/net/ipv6/conf/default/disable_ipv6"),
            "0",
        ),
        capability_check(),
        service_sandbox_check(),
        route_collision_check(),
        reserved_policy_routing_check(),
        native_mpquic_check(Path::new(DEFAULT_MPQUIC_BINARY)),
        clock_sanity_check(now_ms),
        clock_synchronization_check(),
        loaded.check,
    ];
    checks.push(policy_manifest_check(config, config_path, now_ms));
    DoctorReport { checks }
}

struct LoadedConfiguration {
    config: Option<Config>,
    check: Check,
}

fn load_configuration(path: &Path) -> LoadedConfiguration {
    match load_config_bounded(path) {
        Ok(config) => LoadedConfiguration {
            config: Some(config),
            check: passed(
                "configuration",
                "configuration is bounded, integrity-protected, and semantically safe",
            ),
        },
        Err(_) => LoadedConfiguration {
            config: None,
            check: failed(
                "configuration",
                "configuration is absent, unsafe, oversized, or invalid",
            ),
        },
    }
}

/// Loads exactly the same bounded configuration input used by CLI validation.
pub(crate) fn load_config_bounded(path: &Path) -> Result<Config> {
    if !path.is_absolute() {
        bail!("configuration path must be absolute");
    }
    let bytes = read_integrity_file(path, MAX_CONFIG_BYTES)
        .context("configuration file is not a safe bounded regular file")?;
    let input = std::str::from_utf8(&bytes).context("configuration is not UTF-8")?;
    Config::from_yaml(input).context("configuration validation failed")
}

fn operating_system_check() -> Check {
    let bytes = ["/etc/os-release", "/usr/lib/os-release"]
        .into_iter()
        .find_map(|path| read_bounded(Path::new(path), 64 * 1024).ok());
    let Some(bytes) = bytes else {
        return failed(
            "operating_system",
            "cannot read bounded Debian os-release metadata",
        );
    };
    match parse_os_release(&bytes) {
        Some((identifier, version)) if identifier == "debian" && version == "13" => {
            passed("operating_system", "operating system is Debian 13")
        }
        Some(_) => failed("operating_system", "VOLPAROSSA requires Debian 13"),
        None => failed("operating_system", "/etc/os-release is malformed"),
    }
}

fn parse_os_release(bytes: &[u8]) -> Option<(String, String)> {
    let input = std::str::from_utf8(bytes).ok()?;
    let mut identifier = None;
    let mut version = None;
    for line in input.lines().take(512) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw) = line.split_once('=')?;
        let value = raw
            .strip_prefix('"')
            .and_then(|quoted| quoted.strip_suffix('"'))
            .unwrap_or(raw);
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            continue;
        }
        match key {
            "ID" => identifier = Some(value.to_owned()),
            "VERSION_ID" => version = Some(value.to_owned()),
            _ => {}
        }
    }
    Some((identifier?, version?))
}

fn architecture_check(architecture: &str) -> Check {
    if architecture == "x86_64" {
        passed(
            "architecture",
            "running binary and kernel userspace architecture is Debian amd64/x86_64",
        )
    } else {
        failed("architecture", "VOLPAROSSA requires Debian amd64/x86_64")
    }
}

fn kernel_check(release: Option<&str>) -> Check {
    let Some(release) = release else {
        return failed("kernel_version", "cannot read the running kernel release");
    };
    match parse_kernel_version(release) {
        Some(version) if version >= (6, 12) => passed(
            "kernel_version",
            format!("kernel {release} meets the Debian 13 6.12 baseline"),
        ),
        Some(_) => failed(
            "kernel_version",
            "running kernel is older than the Debian 13 6.12 baseline",
        ),
        None => failed("kernel_version", "running kernel release is malformed"),
    }
}

fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    if release.is_empty()
        || release.len() > 128
        || !release
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
    {
        return None;
    }
    let mut components = release.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.split('-').next()?.parse().ok()?;
    Some((major, minor))
}

fn mptcp_check() -> Check {
    match volparossa_mptcp::probe_kernel_support() {
        Ok(()) => passed(
            "mptcp_socket",
            "kernel accepts unconnected IPPROTO_MPTCP sockets",
        ),
        Err(_) => failed(
            "mptcp_socket",
            "kernel rejected an unconnected IPPROTO_MPTCP socket probe",
        ),
    }
}

fn mptcp_path_manager_check(config: Option<&Config>) -> Check {
    let Some(config) = config else {
        return failed(
            "mptcp_path_manager",
            "configuration unavailable; required path manager cannot be established",
        );
    };
    let (expected, description) = match config.tcp.mptcp_path_manager {
        MptcpPathManager::Kernel => ("0", "kernel"),
        MptcpPathManager::Mptcpd => ("1", "userspace/mptcpd"),
    };
    match read_trimmed(Path::new("/proc/sys/net/mptcp/pm_type"), MAX_SYSCTL_BYTES) {
        Ok(value) if value == expected => passed(
            "mptcp_path_manager",
            format!("{description} MPTCP path manager is selected"),
        ),
        Ok(_) => failed(
            "mptcp_path_manager",
            "net.mptcp.pm_type does not match the configured path manager",
        ),
        Err(_) => failed(
            "mptcp_path_manager",
            "cannot read the namespaced MPTCP path-manager sysctl",
        ),
    }
}

fn wireguard_check(release: Option<&str>) -> Check {
    kernel_feature_check(
        "wireguard_kernel",
        release,
        "CONFIG_WIREGUARD",
        "wireguard",
        "kernel/drivers/net/wireguard/wireguard",
    )
}

fn nftables_kernel_check(release: Option<&str>) -> Check {
    kernel_feature_check(
        "nftables_kernel",
        release,
        "CONFIG_NF_TABLES",
        "nf_tables",
        "kernel/net/netfilter/nf_tables",
    )
}

fn kernel_feature_check(
    name: &'static str,
    release: Option<&str>,
    config_key: &str,
    module_name: &str,
    module_relative: &str,
) -> Check {
    if Path::new("/sys/module").join(module_name).is_dir() {
        return passed(name, format!("{module_name} kernel feature is loaded"));
    }
    let Some(release) = release.filter(|value| parse_kernel_version(value).is_some()) else {
        return failed(name, "running kernel release is unavailable or unsafe");
    };
    if kernel_config(release)
        .as_deref()
        .is_some_and(|config| kernel_config_enabled(config, config_key))
    {
        return passed(
            name,
            format!("{config_key} is enabled in the running kernel configuration"),
        );
    }
    if module_is_installed(release, module_relative) {
        return passed(
            name,
            format!("{module_name} is installed for the running kernel"),
        );
    }
    failed(
        name,
        format!("cannot prove {config_key} support for the running kernel"),
    )
}

fn kernel_config(release: &str) -> Option<Vec<u8>> {
    for root in ["/boot", "/usr/lib/modules", "/lib/modules"] {
        let path = if root == "/boot" {
            PathBuf::from(root).join(format!("config-{release}"))
        } else {
            PathBuf::from(root).join(release).join("config")
        };
        if let Ok(bytes) = read_bounded(&path, MAX_KERNEL_CONFIG_BYTES) {
            return Some(bytes);
        }
    }
    None
}

fn kernel_config_enabled(config: &[u8], key: &str) -> bool {
    let Ok(input) = std::str::from_utf8(config) else {
        return false;
    };
    input.lines().any(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
            .is_some_and(|value| matches!(value, "y" | "m"))
    })
}

fn module_is_installed(release: &str, relative: &str) -> bool {
    for root in ["/usr/lib/modules", "/lib/modules"] {
        for suffix in [".ko", ".ko.xz", ".ko.zst", ".ko.gz"] {
            if PathBuf::from(root)
                .join(release)
                .join(format!("{relative}{suffix}"))
                .is_file()
            {
                return true;
            }
        }
    }
    false
}

fn udp_check(ipv6: bool) -> Check {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let name = if ipv6 { "udp_ipv6" } else { "udp_ipv4" };
    match Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(socket) => {
            drop(socket);
            passed(name, "kernel accepts an unbound UDP socket")
        }
        Err(_) => failed(name, "kernel rejected an unbound UDP socket probe"),
    }
}

fn capability_check() -> Check {
    let Ok(unit) = installed_service("volparossa-helper.service") else {
        return failed(
            "helper_capabilities",
            "installed helper unit is absent, unreadable, symlinked, or overridden",
        );
    };
    let Some(service) = parse_service_unit(&unit) else {
        return failed("helper_capabilities", "installed helper unit is malformed");
    };
    let required = ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_ADMIN"];
    if service.get("User").is_some_and(|value| value == "root")
        && service
            .get("Group")
            .is_some_and(|value| value == "volparossa")
        && value_set_matches(&service, "CapabilityBoundingSet", &required)
        && value_set_matches(&service, "AmbientCapabilities", &required)
    {
        passed(
            "helper_capabilities",
            "helper unit grants only CAP_NET_ADMIN, CAP_NET_RAW, and namespace CAP_SYS_ADMIN",
        )
    } else {
        failed(
            "helper_capabilities",
            "helper unit capability/user boundary does not match the reviewed profile",
        )
    }
}

#[derive(Clone, Copy)]
enum UnitKind {
    Agent,
    Helper,
    Native,
}

fn service_sandbox_check() -> Check {
    for (name, kind) in [
        ("volparossa-agent.service", UnitKind::Agent),
        ("volparossa-helper.service", UnitKind::Helper),
        ("volparossa-mpquic.service", UnitKind::Native),
    ] {
        let Ok(bytes) = installed_service(name) else {
            return failed(
                "service_sandbox",
                "a required service unit is absent, unreadable, symlinked, or overridden",
            );
        };
        let Some(service) = parse_service_unit(&bytes) else {
            return failed("service_sandbox", "a required service unit is malformed");
        };
        if !unit_has_required_sandbox(&service, kind) {
            return failed(
                "service_sandbox",
                "a required service unit does not match the reviewed sandbox profile",
            );
        }
    }
    passed(
        "service_sandbox",
        "agent, helper, and native units match their reviewed privilege sandboxes",
    )
}

fn unit_has_required_sandbox(service: &BTreeMap<String, String>, kind: UnitKind) -> bool {
    let common = [
        ("UMask", "0077"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateMounts", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectHostname", "yes"),
        ("LockPersonality", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("RestrictRealtime", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("SystemCallArchitectures", "native"),
        ("SystemCallErrorNumber", "EPERM"),
    ];
    if !common
        .iter()
        .all(|(key, expected)| service.get(*key).is_some_and(|value| value == expected))
    {
        return false;
    }

    let (user, executable, private_devices, kernel_tunables, namespaces, families, syscalls) =
        match kind {
            UnitKind::Agent => (
                "volparossa",
                "/usr/bin/volparossa-agent",
                "yes",
                "yes",
                "yes",
                ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"].as_slice(),
                ["@system-service", "@network-io"].as_slice(),
            ),
            UnitKind::Helper => (
                "root",
                "/usr/libexec/volparossa/volparossa-helper",
                "no",
                "no",
                "net",
                ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"].as_slice(),
                ["@system-service", "@network-io", "@mount"].as_slice(),
            ),
            UnitKind::Native => (
                "volparossa",
                "/usr/libexec/volparossa/volparossa-mpquic-launch",
                "yes",
                "yes",
                "yes",
                ["AF_UNIX", "AF_INET", "AF_INET6"].as_slice(),
                ["@system-service", "@network-io"].as_slice(),
            ),
        };
    service.get("User").is_some_and(|value| value == user)
        && service
            .get("Group")
            .is_some_and(|value| value == "volparossa")
        && service
            .get("ExecStart")
            .is_some_and(|value| value == executable)
        && service
            .get("PrivateDevices")
            .is_some_and(|value| value == private_devices)
        && service
            .get("ProtectKernelTunables")
            .is_some_and(|value| value == kernel_tunables)
        && service
            .get("RestrictNamespaces")
            .is_some_and(|value| value == namespaces)
        && value_set_matches(service, "RestrictAddressFamilies", families)
        && value_set_matches(service, "SystemCallFilter", syscalls)
        && match kind {
            UnitKind::Helper => true,
            UnitKind::Agent | UnitKind::Native => {
                service
                    .get("CapabilityBoundingSet")
                    .is_some_and(String::is_empty)
                    && service
                        .get("AmbientCapabilities")
                        .is_some_and(String::is_empty)
            }
        }
}

fn value_set_matches(service: &BTreeMap<String, String>, key: &str, expected: &[&str]) -> bool {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    service
        .get(key)
        .is_some_and(|value| value.split_ascii_whitespace().collect::<BTreeSet<_>>() == expected)
}

fn installed_service(name: &str) -> io::Result<Vec<u8>> {
    for root in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ] {
        if drop_in_exists(Path::new(root), name)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "service override requires explicit effective-profile review",
            ));
        }
    }
    for root in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ] {
        let path = Path::new(root).join(name);
        match read_bounded(&path, MAX_UNIT_BYTES) {
            Ok(bytes) => return Ok(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "service unit not found",
    ))
}

fn drop_in_exists(root: &Path, name: &str) -> io::Result<bool> {
    let directory = root.join(format!("{name}.d"));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for (index, entry) in entries.enumerate() {
        if index >= 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many service drop-ins",
            ));
        }
        if entry?
            .path()
            .extension()
            .is_some_and(|extension| extension == "conf")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_service_unit(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let input = std::str::from_utf8(bytes).ok()?;
    let mut service_section = false;
    let mut values = BTreeMap::new();
    for (index, raw) in input.lines().enumerate() {
        if index >= 2_048 || raw.len() > 4_096 || raw.ends_with('\\') {
            return None;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            service_section = line == "[Service]";
            continue;
        }
        if !service_section {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return None;
        }
        if matches!(
            key,
            "CapabilityBoundingSet"
                | "AmbientCapabilities"
                | "RestrictAddressFamilies"
                | "SystemCallFilter"
        ) && values.contains_key(key)
        {
            return None;
        }
        values.insert(key.to_owned(), value.trim().to_owned());
    }
    Some(values)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ipv6Route {
    destination: [u8; 16],
    prefix_length: u8,
    interface: String,
}

fn route_collision_check() -> Check {
    let Ok(bytes) = read_bounded(Path::new("/proc/net/ipv6_route"), MAX_PROC_BYTES) else {
        return failed(
            "overlay_route_collision",
            "cannot read the bounded kernel IPv6 route view",
        );
    };
    let Ok(routes) = parse_ipv6_routes(&bytes) else {
        return failed(
            "overlay_route_collision",
            "kernel IPv6 route view is malformed or exceeds parser bounds",
        );
    };
    let collisions = routes
        .into_iter()
        .filter(|route| {
            route.prefix_length != 0
                && prefixes_overlap(
                    route.destination,
                    route.prefix_length,
                    OVERLAY_PREFIX,
                    OVERLAY_PREFIX_LENGTH,
                )
        })
        .collect::<Vec<_>>();
    if collisions.is_empty() {
        return passed(
            "overlay_route_collision",
            "no active route overlaps fd76:6f6c:7061::/48",
        );
    }
    if collisions.iter().all(route_is_helper_owned) {
        warning(
            "overlay_route_collision",
            "active overlapping routes carry exact helper-owned WireGuard aliases",
        )
    } else {
        failed(
            "overlay_route_collision",
            "an active route overlaps the reserved fd76:6f6c:7061::/48 space",
        )
    }
}

fn parse_ipv6_routes(bytes: &[u8]) -> std::result::Result<Vec<Ipv6Route>, ()> {
    let input = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut routes = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if index >= 65_536 || line.len() > 512 {
            return Err(());
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            return Err(());
        }
        let destination = decode_ipv6_hex(fields[0]).ok_or(())?;
        let prefix_length = u8::from_str_radix(fields[1], 16).map_err(|_| ())?;
        if prefix_length > 128 || !valid_interface_name(fields[9]) {
            return Err(());
        }
        routes.push(Ipv6Route {
            destination,
            prefix_length,
            interface: fields[9].to_owned(),
        });
    }
    Ok(routes)
}

fn decode_ipv6_hex(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut address = [0_u8; 16];
    for (index, output) in address.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(address)
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < libc::IFNAMSIZ
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn prefixes_overlap(left: [u8; 16], left_bits: u8, right: [u8; 16], right_bits: u8) -> bool {
    let compared = usize::from(left_bits.min(right_bits));
    let whole_bytes = compared / 8;
    if left[..whole_bytes] != right[..whole_bytes] {
        return false;
    }
    let remaining = compared % 8;
    if remaining == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining);
    left[whole_bytes] & mask == right[whole_bytes] & mask
}

fn route_is_helper_owned(route: &Ipv6Route) -> bool {
    let path = Path::new("/sys/class/net")
        .join(&route.interface)
        .join("ifalias");
    read_trimmed(&path, 256)
        .is_ok_and(|alias| alias == format!("volparossa:wireguard:v1:{}", route.interface))
}

fn native_mpquic_check(path: &Path) -> Check {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return failed("native_mpquic", "native MPQUIC binary is not installed");
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
    {
        return failed(
            "native_mpquic",
            "native MPQUIC binary type, owner, mode, or executability is unsafe",
        );
    }
    let Ok(output) = run_bounded_command(path, &["--api-version"], 32, COMMAND_TIMEOUT) else {
        return failed(
            "native_mpquic",
            "native MPQUIC offline API probe failed or exceeded its bounds",
        );
    };
    if output.status.success() && native_api_output_compatible(&output.stdout) {
        passed(
            "native_mpquic",
            format!(
                "native binary and loader dependencies answered exact control API v{NATIVE_API_VERSION}"
            ),
        )
    } else {
        failed(
            "native_mpquic",
            "native MPQUIC binary is incompatible with the Rust control API",
        )
    }
}

fn native_api_output_compatible(output: &[u8]) -> bool {
    let expected = format!("{NATIVE_API_VERSION}\n");
    output == expected.as_bytes()
}

fn clock_sanity_check(now_ms: Option<u64>) -> Check {
    match now_ms {
        Some(milliseconds) if (1_704_067_200_000..=4_102_444_800_000).contains(&milliseconds) => {
            passed(
                "system_clock",
                "wall clock is within the accepted 2024-2100 sanity window",
            )
        }
        _ => failed(
            "system_clock",
            "wall clock is outside 2024-2100; signed TTL checks cannot be trusted",
        ),
    }
}

fn clock_synchronization_check() -> Check {
    if fs::symlink_metadata("/run/systemd/timesync/synchronized").is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
    }) {
        return passed(
            "clock_synchronization",
            "systemd-timesyncd has published its root-owned synchronization marker",
        );
    }
    let Some(path) = find_executable(&["/usr/bin/timedatectl", "/bin/timedatectl"]) else {
        return failed(
            "clock_synchronization",
            "clock synchronization cannot be established read-only",
        );
    };
    match run_bounded_command(
        &path,
        &["show", "--property=NTPSynchronized", "--value"],
        16,
        COMMAND_TIMEOUT,
    ) {
        Ok(output) if output.status.success() && output.stdout == b"yes\n" => passed(
            "clock_synchronization",
            "systemd reports an NTP-synchronized wall clock",
        ),
        _ => failed(
            "clock_synchronization",
            "systemd does not prove an NTP-synchronized wall clock",
        ),
    }
}

pub(crate) fn unix_millis() -> Result<u64> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_millis();
    u64::try_from(milliseconds).context("system time does not fit protocol timestamp")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    schema_version: u32,
    maintainers: Vec<TrustKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustKey {
    public_key_hex: String,
    environment: TrustEnvironment,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrustEnvironment {
    Production,
    Development,
}

/// Privacy-safe evidence returned by offline threshold verification.
pub(crate) struct PolicyEvidence {
    pub(crate) manifest_version: u64,
    pub(crate) policy_hash: [u8; 32],
    pub(crate) verified_signatures: usize,
    pub(crate) expires_at_ms: u64,
}

fn policy_manifest_check(
    config: Option<&Config>,
    config_path: &Path,
    now_ms: Option<u64>,
) -> Check {
    let (Some(config), Some(now_ms)) = (config, now_ms) else {
        return failed(
            "policy_manifest",
            "configuration or trustworthy wall-clock input is unavailable",
        );
    };
    if config.policy.manifest_path.trim().is_empty() {
        return failed(
            "policy_manifest",
            "no active policy manifest is configured; connections remain fail-closed",
        );
    }
    let Ok(trust_path) = policy_trust_path(config_path) else {
        return failed(
            "policy_manifest",
            "policy trust path cannot be derived from an absolute configuration path",
        );
    };
    match verify_policy_at(
        config,
        Path::new(&config.policy.manifest_path),
        &trust_path,
        now_ms,
    ) {
        Ok(evidence) => passed(
            "policy_manifest",
            format!(
                "active canonical policy v{} has {} trusted signatures and unexpired TTL",
                evidence.manifest_version, evidence.verified_signatures
            ),
        ),
        Err(_) => failed(
            "policy_manifest",
            "active policy/trust files failed bounded canonical threshold verification",
        ),
    }
}

fn policy_trust_path(config_path: &Path) -> Result<PathBuf> {
    if !config_path.is_absolute() {
        bail!("configuration path must be absolute");
    }
    let parent = config_path
        .parent()
        .context("configuration path has no parent")?;
    Ok(parent.join(POLICY_TRUST_FILE))
}

/// Verifies one manifest against the exact trust format consumed by the agent.
pub(crate) fn verify_policy_at(
    config: &Config,
    manifest_path: &Path,
    trust_path: &Path,
    now_ms: u64,
) -> Result<PolicyEvidence> {
    if !manifest_path.is_absolute() || !trust_path.is_absolute() {
        bail!("policy and trust paths must be absolute");
    }
    let trust_bytes = read_integrity_file(trust_path, MAX_TRUST_FILE_BYTES)
        .context("trust file is not a safe bounded regular file")?;
    let trust_file: TrustFile =
        serde_json::from_slice(&trust_bytes).context("trust file syntax is invalid")?;
    if trust_file.schema_version != TRUST_SCHEMA_VERSION {
        bail!("trust file schema is unsupported");
    }
    let mode = match config.runtime_mode {
        RuntimeMode::Production => PolicyMode::Production,
        RuntimeMode::Development => PolicyMode::Development,
    };
    if mode == PolicyMode::Production && trust_file.maintainers.len() != DEFAULT_MAINTAINER_COUNT {
        bail!("production trust requires exactly five maintainers");
    }
    let maintainers = trust_file
        .maintainers
        .into_iter()
        .map(|entry| trusted_maintainer(entry, mode))
        .collect::<Result<Vec<_>>>()?;
    let expected = maintainers.len();
    let store = TrustStore::new(mode, maintainers).context("trust set is invalid")?;
    let verification = VerificationPolicy::new(
        usize::from(config.policy.minimum_signatures),
        expected,
        DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS,
        DEFAULT_MAXIMUM_CLOCK_SKEW_MS,
    )
    .context("verification policy is invalid")?;
    let manifest = read_integrity_file(manifest_path, MAX_SIGNED_MANIFEST_BYTES)
        .context("manifest is not a safe bounded regular file")?;
    let verified = verify_manifest(&manifest, now_ms, &store, verification)
        .context("manifest threshold verification failed")?;
    verified
        .ensure_active_at(now_ms)
        .context("manifest is not active")?;
    Ok(PolicyEvidence {
        manifest_version: verified.manifest_version(),
        policy_hash: *verified.policy_hash(),
        verified_signatures: verified.verified_signatures(),
        expires_at_ms: verified.expires_at_ms(),
    })
}

fn trusted_maintainer(entry: TrustKey, mode: PolicyMode) -> Result<TrustedMaintainer> {
    if entry.public_key_hex.len() != 64 {
        bail!("maintainer public key has an invalid length");
    }
    let decoded = hex::decode(entry.public_key_hex).context("maintainer key is not hex")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("maintainer key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes).context("maintainer key is invalid")?;
    let environment = match entry.environment {
        TrustEnvironment::Production => MaintainerEnvironment::Production,
        TrustEnvironment::Development => MaintainerEnvironment::Development,
    };
    if mode == PolicyMode::Production && environment != MaintainerEnvironment::Production {
        bail!("development maintainer key is forbidden in production");
    }
    Ok(TrustedMaintainer::new(key, environment))
}

fn reserved_policy_routing_check() -> Check {
    let Some(ip) = find_executable(&["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip"]) else {
        return failed(
            "reserved_policy_routing",
            "iproute2 is unavailable for a bounded read-only rule/table query",
        );
    };
    let rules = run_bounded_command(
        &ip,
        &["-json", "-details", "rule", "show"],
        MAX_COMMAND_BYTES,
        COMMAND_TIMEOUT,
    );
    let routes = run_bounded_command(
        &ip,
        &["-json", "-details", "route", "show", "table", "all"],
        MAX_COMMAND_BYTES,
        COMMAND_TIMEOUT,
    );
    let (Ok(rules), Ok(routes)) = (rules, routes) else {
        return failed(
            "reserved_policy_routing",
            "bounded read-only route/rule queries failed or timed out",
        );
    };
    if !rules.status.success() || !routes.status.success() {
        return failed(
            "reserved_policy_routing",
            "read-only route/rule queries were rejected",
        );
    }
    let reserved = json_uses_reserved_routing(&rules.stdout).and_then(|found| {
        if found {
            Ok(true)
        } else {
            json_uses_reserved_routing(&routes.stdout)
        }
    });
    match reserved {
        Ok(false) => passed(
            "reserved_policy_routing",
            "route tables 7600-7699 and marks 0x7600-0x76ff are unused",
        ),
        Ok(true) => failed(
            "reserved_policy_routing",
            "reserved tables or marks are active and ownership cannot be proven read-only",
        ),
        Err(()) => failed(
            "reserved_policy_routing",
            "iproute2 returned malformed or excessive JSON",
        ),
    }
}

fn json_uses_reserved_routing(bytes: &[u8]) -> std::result::Result<bool, ()> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let entries = value.as_array().ok_or(())?;
    if entries.len() > 65_536 {
        return Err(());
    }
    for entry in entries {
        let object = entry.as_object().ok_or(())?;
        if object
            .get("table")
            .and_then(parse_json_identifier)
            .is_some_and(|value| (RESERVED_TABLE_MIN..=RESERVED_TABLE_MAX).contains(&value))
            || object
                .get("fwmark")
                .and_then(parse_json_identifier)
                .is_some_and(|value| (RESERVED_MARK_MIN..=RESERVED_MARK_MAX).contains(&value))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_json_identifier(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => {
            let token = text.split('/').next()?;
            token.strip_prefix("0x").map_or_else(
                || token.parse().ok(),
                |hex| u64::from_str_radix(hex, 16).ok(),
            )
        }
        _ => None,
    }
}

fn sysctl_check(name: &'static str, path: &Path, expected: &'static str) -> Check {
    match read_trimmed(path, MAX_SYSCTL_BYTES) {
        Ok(value) if value == expected => passed(
            name,
            format!("{} has the required value {expected}", path.display()),
        ),
        Ok(_) => failed(
            name,
            format!("{} does not have required value {expected}", path.display()),
        ),
        Err(_) => failed(name, format!("{} is unavailable", path.display())),
    }
}

fn executable_check(name: &'static str, candidates: &[&str]) -> Check {
    if find_executable(candidates).is_some() {
        passed(name, "required root-owned Debian executable is installed")
    } else {
        failed(
            name,
            "required root-owned non-writable Debian executable is unavailable",
        )
    }
}

fn find_executable(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().find_map(|candidate| {
        let path = PathBuf::from(candidate);
        fs::metadata(&path)
            .is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o111 != 0
                    && metadata.mode() & 0o022 == 0
            })
            .then_some(path)
    })
}

fn read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    if maximum == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero read bound",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is not a regular file",
        ));
    }
    let limit = u64::try_from(maximum)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read bound is too large"))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len().min(limit)).unwrap_or(maximum));
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds its read bound",
        ));
    }
    Ok(bytes)
}

fn read_integrity_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context("cannot open integrity-protected input")?;
    let metadata = file.metadata().context("cannot inspect input")?;
    let maximum_u64 = u64::try_from(maximum).context("input bound is too large")?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum_u64
    {
        bail!("input file type, links, mode, or length is unsafe");
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).context("input length does not fit memory bound")?,
    );
    file.by_ref()
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("cannot read integrity-protected input")?;
    if bytes.is_empty() || bytes.len() > maximum {
        bail!("input length changed or exceeded its bound");
    }
    Ok(bytes)
}

fn read_trimmed(path: &Path, maximum: usize) -> io::Result<String> {
    let bytes = read_bounded(path, maximum)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not UTF-8"))?;
    Ok(value.trim().to_owned())
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

fn run_bounded_command(
    program: &Path,
    arguments: &[&str],
    maximum: usize,
    timeout: Duration,
) -> io::Result<CommandOutput> {
    if maximum == 0 || timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command bounds are invalid",
        ));
    }
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("command stdout pipe is unavailable"))?;
    let limit = u64::try_from(maximum)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "command bound is too large"))?;
    let reader = thread::Builder::new()
        .name("volparossa-doctor-command".to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            stdout
                .take(limit.saturating_add(1))
                .read_to_end(&mut output)
                .map(|_| output)
        })?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "command timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = reader
        .join()
        .map_err(|_| io::Error::other("command reader panicked"))??;
    if stdout.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "command output exceeds its bound",
        ));
    }
    Ok(CommandOutput { status, stdout })
}

fn passed(name: &'static str, detail: impl Into<String>) -> Check {
    make_check(name, CheckStatus::Pass, detail)
}

fn warning(name: &'static str, detail: impl Into<String>) -> Check {
    make_check(name, CheckStatus::Warn, detail)
}

fn failed(name: &'static str, detail: impl Into<String>) -> Check {
    make_check(name, CheckStatus::Fail, detail)
}

fn make_check(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: bounded_detail(detail.into()),
    }
}

fn bounded_detail(detail: String) -> String {
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail;
    }
    let mut output = String::with_capacity(MAX_DETAIL_BYTES);
    for character in detail.chars() {
        if output.len() + character.len_utf8() + 3 > MAX_DETAIL_BYTES {
            break;
        }
        output.push(character);
    }
    output.push_str("...");
    output
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    };

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tempfile::tempdir;
    use volparossa_policy::{ManifestSpec, POLICY_PROTOCOL_VERSION, sign_manifest};

    use super::*;

    #[test]
    fn report_fails_closed_only_for_failures() {
        let warnings = DoctorReport {
            checks: vec![passed("ok", "ok"), warning("review", "review")],
        };
        assert!(warnings.is_usable());

        let failure = DoctorReport {
            checks: vec![passed("ok", "ok"), failed("bad", "required input missing")],
        };
        assert!(!failure.is_usable());
    }

    #[test]
    fn os_release_requires_exact_debian_thirteen() {
        let parsed = parse_os_release(
            b"# distribution metadata\nID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"ignored value\"\n",
        );
        assert_eq!(parsed, Some(("debian".to_owned(), "13".to_owned())));
        assert_ne!(
            parse_os_release(b"ID=debian\nVERSION_ID=12\n"),
            Some(("debian".to_owned(), "13".to_owned()))
        );
        assert_eq!(parse_os_release(b"ID=debian\nmalformed\n"), None);
    }

    #[test]
    fn kernel_version_parser_is_strict_and_uses_major_minor() {
        assert_eq!(parse_kernel_version("6.12.101+deb13-amd64"), Some((6, 12)));
        assert_eq!(parse_kernel_version("7.0-rc1"), Some((7, 0)));
        assert_eq!(parse_kernel_version("6"), None);
        assert_eq!(parse_kernel_version("../../6.12"), None);
        assert_eq!(parse_kernel_version("release.12"), None);
    }

    #[test]
    fn kernel_config_parser_accepts_only_enabled_builtin_or_module() {
        let config = b"CONFIG_MPTCP=y\nCONFIG_WIREGUARD=m\n# CONFIG_NF_TABLES is not set\n";
        assert!(kernel_config_enabled(config, "CONFIG_MPTCP"));
        assert!(kernel_config_enabled(config, "CONFIG_WIREGUARD"));
        assert!(!kernel_config_enabled(config, "CONFIG_NF_TABLES"));
        assert!(!kernel_config_enabled(config, "CONFIG_WIRE"));
    }

    #[test]
    fn service_unit_parser_is_section_scoped_and_bounded() {
        let unit = parse_service_unit(
            b"[Unit]\nUser=ignored\n[Service]\nUser=root\nGroup=volparossa\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN\n",
        )
        .expect("valid unit");
        assert_eq!(unit.get("User").map(String::as_str), Some("root"));
        assert!(value_set_matches(
            &unit,
            "CapabilityBoundingSet",
            &["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_NET_ADMIN"],
        ));
        assert!(parse_service_unit(b"[Service]\nUser=root\\\ncontinued\n").is_none());
        assert!(
            parse_service_unit(
                b"[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\nCapabilityBoundingSet=CAP_NET_ADMIN\n",
            )
            .is_none()
        );
    }

    #[test]
    fn reviewed_service_sandboxes_are_exact() {
        for kind in [UnitKind::Agent, UnitKind::Helper, UnitKind::Native] {
            let mut service = sandbox_fixture(kind);
            assert!(unit_has_required_sandbox(&service, kind));
            service.insert("NoNewPrivileges".to_owned(), "no".to_owned());
            assert!(!unit_has_required_sandbox(&service, kind));
        }
    }

    #[test]
    fn ipv6_route_parser_detects_broad_and_narrow_overlay_collisions() {
        let line = concat!(
            "fd766f6c706100000000000000000000 30 ",
            "00000000000000000000000000000000 00 ",
            "00000000000000000000000000000000 ",
            "00000064 00000001 00000000 00000001 vpc100000001\n"
        );
        let routes = parse_ipv6_routes(line.as_bytes()).expect("route");
        assert_eq!(routes.len(), 1);
        assert!(prefixes_overlap(
            routes[0].destination,
            routes[0].prefix_length,
            OVERLAY_PREFIX,
            OVERLAY_PREFIX_LENGTH,
        ));

        let mut broad_ula = [0_u8; 16];
        broad_ula[0] = 0xfd;
        assert!(prefixes_overlap(
            broad_ula,
            8,
            OVERLAY_PREFIX,
            OVERLAY_PREFIX_LENGTH,
        ));
        let mut unrelated = OVERLAY_PREFIX;
        unrelated[0] = 0x20;
        assert!(!prefixes_overlap(
            unrelated,
            16,
            OVERLAY_PREFIX,
            OVERLAY_PREFIX_LENGTH,
        ));
        assert!(parse_ipv6_routes(b"short route\n").is_err());
    }

    #[test]
    fn reserved_route_json_parser_handles_numeric_hex_and_named_tables() {
        assert_eq!(json_uses_reserved_routing(br#"[{"table":7601}]"#), Ok(true));
        assert_eq!(
            json_uses_reserved_routing(br#"[{"fwmark":"0x7601/0xffffffff"}]"#),
            Ok(true)
        );
        assert_eq!(
            json_uses_reserved_routing(br#"[{"table":"main"},{"table":7599}]"#),
            Ok(false)
        );
        assert_eq!(json_uses_reserved_routing(br"{}"), Err(()));
    }

    #[test]
    fn native_api_output_is_exact() {
        let exact = format!("{NATIVE_API_VERSION}\n");
        assert!(native_api_output_compatible(exact.as_bytes()));
        assert!(!native_api_output_compatible(
            format!(" {NATIVE_API_VERSION}\n").as_bytes()
        ));
        assert!(!native_api_output_compatible(
            format!("{NATIVE_API_VERSION}\nextra").as_bytes()
        ));
    }

    #[test]
    fn details_are_bounded_without_splitting_utf8() {
        let detail = bounded_detail("é".repeat(1_000));
        assert!(detail.len() <= MAX_DETAIL_BYTES);
        assert!(detail.ends_with("..."));
        assert!(std::str::from_utf8(detail.as_bytes()).is_ok());
    }

    #[test]
    fn configuration_loader_rejects_relative_symlink_and_writable_inputs() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.yaml");
        write_private(
            &config_path,
            Config::default().to_yaml().expect("config YAML").as_bytes(),
        );
        assert!(load_config_bounded(&config_path).is_ok());
        assert!(load_config_bounded(Path::new("config.yaml")).is_err());

        let link = directory.path().join("config-link.yaml");
        symlink(&config_path, &link).expect("symlink");
        assert!(load_config_bounded(&link).is_err());

        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o666))
            .expect("unsafe permissions");
        assert!(load_config_bounded(&config_path).is_err());
    }

    #[test]
    fn policy_check_verifies_active_three_of_five_agent_trust() {
        let directory = tempdir().expect("tempdir");
        let manifest_path = directory.path().join("policy.manifest");
        let trust_path = directory.path().join(POLICY_TRUST_FILE);
        let keys = [
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
            SigningKey::from_bytes(&[3; 32]),
            SigningKey::from_bytes(&[4; 32]),
            SigningKey::from_bytes(&[5; 32]),
        ];
        let maintainers = keys
            .iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect::<Vec<_>>();
        let store = TrustStore::new(PolicyMode::Production, maintainers).expect("trust store");
        let now_ms = 1_800_000_000_000;
        let specification = ManifestSpec::new(
            7,
            POLICY_PROTOCOL_VERSION,
            now_ms - 1_000,
            now_ms - 1_000,
            now_ms + 60_000,
        )
        .expect("manifest specification");
        let manifest = sign_manifest(&specification, &store, &[&keys[0], &keys[1], &keys[2]])
            .expect("signed manifest");
        write_private(&manifest_path, &manifest);
        write_private(&trust_path, &trust_json(&keys));

        let mut config = Config::default();
        config.policy.manifest_path = manifest_path.to_string_lossy().into_owned();
        let evidence =
            verify_policy_at(&config, &manifest_path, &trust_path, now_ms).expect("verified");
        assert_eq!(evidence.manifest_version, 7);
        assert_eq!(evidence.verified_signatures, 3);
        assert!(evidence.expires_at_ms > now_ms);

        fs::write(&trust_path, trust_json(&keys[..4])).expect("replace trust");
        assert!(verify_policy_at(&config, &manifest_path, &trust_path, now_ms).is_err());
    }

    fn sandbox_fixture(kind: UnitKind) -> BTreeMap<String, String> {
        let mut service = [
            ("Group", "volparossa"),
            ("UMask", "0077"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateMounts", "yes"),
            ("ProtectControlGroups", "yes"),
            ("ProtectKernelModules", "yes"),
            ("ProtectKernelLogs", "yes"),
            ("ProtectClock", "yes"),
            ("ProtectHostname", "yes"),
            ("LockPersonality", "yes"),
            ("MemoryDenyWriteExecute", "yes"),
            ("RestrictRealtime", "yes"),
            ("RestrictSUIDSGID", "yes"),
            ("SystemCallArchitectures", "native"),
            ("SystemCallErrorNumber", "EPERM"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect::<BTreeMap<_, _>>();
        match kind {
            UnitKind::Agent => {
                insert_fixture(
                    &mut service,
                    &[
                        ("User", "volparossa"),
                        ("ExecStart", "/usr/bin/volparossa-agent"),
                        ("PrivateDevices", "yes"),
                        ("ProtectKernelTunables", "yes"),
                        ("RestrictNamespaces", "yes"),
                        (
                            "RestrictAddressFamilies",
                            "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
                        ),
                        ("SystemCallFilter", "@system-service @network-io"),
                        ("CapabilityBoundingSet", ""),
                        ("AmbientCapabilities", ""),
                    ],
                );
            }
            UnitKind::Helper => {
                insert_fixture(
                    &mut service,
                    &[
                        ("User", "root"),
                        ("ExecStart", "/usr/libexec/volparossa/volparossa-helper"),
                        ("PrivateDevices", "no"),
                        ("ProtectKernelTunables", "no"),
                        ("RestrictNamespaces", "net"),
                        (
                            "RestrictAddressFamilies",
                            "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
                        ),
                        ("SystemCallFilter", "@system-service @network-io @mount"),
                    ],
                );
            }
            UnitKind::Native => {
                insert_fixture(
                    &mut service,
                    &[
                        ("User", "volparossa"),
                        (
                            "ExecStart",
                            "/usr/libexec/volparossa/volparossa-mpquic-launch",
                        ),
                        ("PrivateDevices", "yes"),
                        ("ProtectKernelTunables", "yes"),
                        ("RestrictNamespaces", "yes"),
                        ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
                        ("SystemCallFilter", "@system-service @network-io"),
                        ("CapabilityBoundingSet", ""),
                        ("AmbientCapabilities", ""),
                    ],
                );
            }
        }
        service
    }

    fn insert_fixture(service: &mut BTreeMap<String, String>, entries: &[(&str, &str)]) {
        service.extend(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        );
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("private file");
        file.write_all(bytes).expect("write private file");
    }

    fn trust_json(keys: &[SigningKey]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": TRUST_SCHEMA_VERSION,
            "maintainers": keys.iter().map(|key| json!({
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
                "environment": "production"
            })).collect::<Vec<_>>()
        }))
        .expect("trust JSON")
    }
}
