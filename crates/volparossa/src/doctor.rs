//! Bounded, read-only host prerequisite diagnostics.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use nix::unistd::{Gid, Group, User, getgrouplist};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use volparossa_config::{Config, MptcpPathManager, RuntimeMode};
use volparossa_policy::{
    DEFAULT_MAINTAINER_COUNT, DEFAULT_MAXIMUM_CLOCK_SKEW_MS, DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS,
    MAX_SIGNED_MANIFEST_BYTES, MaintainerEnvironment, PolicyMode, TrustStore, TrustedMaintainer,
    VerificationPolicy, verify_manifest,
};
use volparossa_quic::NATIVE_API_VERSION;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_KERNEL_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROC_BYTES: usize = 2 * 1024 * 1024;
const MAX_SYSCTL_BYTES: usize = 4 * 1024;
const MAX_TRUST_FILE_BYTES: usize = 64 * 1024;
const MAX_UNIT_BYTES: usize = 64 * 1024;
const MAX_SYSUSERS_BYTES: usize = 16 * 1024;
const MAX_SHADOW_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_DETAIL_BYTES: usize = 512;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_MPQUIC_BINARY: &str = "/usr/libexec/volparossa/volparossa-mpquic";
const DEFAULT_SYSUSERS_CONFIG: &str = "/usr/lib/sysusers.d/volparossa.conf";
const DEFAULT_SHADOW_FILE: &str = "/etc/shadow";
const DEFAULT_PASSWD_FILE: &str = "/etc/passwd";
const DEFAULT_GROUP_FILE: &str = "/etc/group";
const DEFAULT_NSSWITCH_FILE: &str = "/etc/nsswitch.conf";
const SHADOW_GROUP: &str = "shadow";
const AGENT_ACCOUNT: &str = "volparossa";
const WORKER_ACCOUNT: &str = "volparossa-worker";
const OPERATOR_GROUP: &str = "volparossa-users";
const MAX_PUBLIC_ACCOUNT_DATABASE_BYTES: usize = 1024 * 1024;
const MAX_NSSWITCH_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_DATABASE_LINE_BYTES: usize = 4096;
const SYSTEMD_RESERVED_ID: u32 = 65_535;
const POSIX_ACCESS_ACL_XATTR: &str = "system.posix_acl_access";
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
const HELPER_BOOTSTRAP_CAPABILITIES: [&str; 8] = [
    "CAP_KILL",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
];
const HELPER_SERVICE_MANAGER_CONTRACT: [(&str, &str); 14] = [
    ("Type", "simple"),
    ("ExitType", "main"),
    ("RemainAfterExit", "no"),
    ("SuccessExitStatus", ""),
    ("Restart", "on-failure"),
    ("RestartMode", "normal"),
    ("RestartSec", "3s"),
    ("RestartForceExitStatus", ""),
    ("RestartPreventExitStatus", "70 71"),
    ("KillMode", "control-group"),
    ("SendSIGKILL", "yes"),
    ("FinalKillSignal", "SIGKILL"),
    ("TimeoutStopFailureMode", "terminate"),
    ("TimeoutStopSec", "45s"),
];

const fn service_identity_id_is_valid(id: u32) -> bool {
    id != 0 && id != SYSTEMD_RESERVED_ID && id != u32::MAX
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalPasswdIdentity<'a> {
    name: &'a [u8],
    password: &'a [u8],
    uid: u32,
    gid: u32,
    gecos: &'a [u8],
    directory: &'a [u8],
    shell: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalGroupIdentity<'a> {
    name: &'a [u8],
    password: &'a [u8],
    gid: u32,
    members: &'a [u8],
}

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
        worker_identity_contract_check(),
        worker_account_lock_check(),
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
    if helper_capability_contract_matches(&service) {
        passed(
            "helper_capabilities",
            "helper unit grants exactly the reviewed eight-capability worker bootstrap set",
        )
    } else {
        failed(
            "helper_capabilities",
            "helper unit capability/user boundary does not match the reviewed profile",
        )
    }
}

fn helper_capability_contract_matches(service: &BTreeMap<String, String>) -> bool {
    service.get("User").is_some_and(|value| value == "root")
        && service
            .get("Group")
            .is_some_and(|value| value == "volparossa")
        && service.get("LimitCORE").is_some_and(|value| value == "0")
        && value_set_matches(
            service,
            "CapabilityBoundingSet",
            &HELPER_BOOTSTRAP_CAPABILITIES,
        )
        && value_set_matches(
            service,
            "AmbientCapabilities",
            &HELPER_BOOTSTRAP_CAPABILITIES,
        )
}

fn worker_identity_contract_check() -> Check {
    let contract = read_bounded(Path::new(DEFAULT_SYSUSERS_CONFIG), MAX_SYSUSERS_BYTES);
    if contract
        .as_deref()
        .is_ok_and(worker_sysusers_contract_matches)
    {
        passed(
            "worker_identity_contract",
            "installed sysusers contract declares a locked no-login worker with its own group and no service-group membership",
        )
    } else {
        failed(
            "worker_identity_contract",
            "installed sysusers contract is absent, unreadable, malformed, or not the reviewed isolated-worker profile",
        )
    }
}

fn worker_account_lock_check() -> Check {
    match live_account_identity_is_bound() {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return failed(
                "worker_account_lock",
                "live NSS, passwd, group, or initgroups identity is not bound to the reviewed local package accounts",
            );
        }
    }
    match read_locked_shadow_accounts(Path::new(DEFAULT_SHADOW_FILE)) {
        Ok(true) => passed(
            "worker_account_lock",
            "live local/NSS service identities have the reviewed agent password lock and worker account-wide lock",
        ),
        Ok(false) => failed(
            "worker_account_lock",
            "live agent/worker shadow entries are absent, malformed, duplicated, or unlocked",
        ),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => warning(
            "worker_account_lock",
            "live shadow account lock is unverified without elevated diagnostic access; helper startup rechecks it fail-closed",
        ),
        Err(_) => failed(
            "worker_account_lock",
            "live shadow account database is absent, unsafe, oversized, or unreadable",
        ),
    }
}

fn live_account_identity_is_bound() -> io::Result<bool> {
    let nsswitch =
        read_root_account_database(Path::new(DEFAULT_NSSWITCH_FILE), MAX_NSSWITCH_BYTES)?;
    if !nss_files_are_authoritative(&nsswitch) {
        return Ok(false);
    }
    let passwd = read_root_account_database(
        Path::new(DEFAULT_PASSWD_FILE),
        MAX_PUBLIC_ACCOUNT_DATABASE_BYTES,
    )?;
    let groups = read_root_account_database(
        Path::new(DEFAULT_GROUP_FILE),
        MAX_PUBLIC_ACCOUNT_DATABASE_BYTES,
    )?;
    let Some(agent) = local_passwd_identity(&passwd, AGENT_ACCOUNT) else {
        return Ok(false);
    };
    let Some(worker) = local_passwd_identity(&passwd, WORKER_ACCOUNT) else {
        return Ok(false);
    };
    let Some(agent_group) = local_group_identity(&groups, AGENT_ACCOUNT) else {
        return Ok(false);
    };
    let Some(operator_group) = local_group_identity(&groups, OPERATOR_GROUP) else {
        return Ok(false);
    };
    let Some(worker_group) = local_group_identity(&groups, WORKER_ACCOUNT) else {
        return Ok(false);
    };
    let Some(shadow_group) = local_group_identity(&groups, SHADOW_GROUP) else {
        return Ok(false);
    };
    if !local_account_contract_matches(
        agent,
        worker,
        agent_group,
        operator_group,
        worker_group,
        shadow_group,
        &groups,
    ) {
        return Ok(false);
    }
    let identities_match = nss_user_matches(AGENT_ACCOUNT, agent)
        && nss_user_matches(WORKER_ACCOUNT, worker)
        && nss_group_matches(AGENT_ACCOUNT, agent_group)
        && nss_group_matches(OPERATOR_GROUP, operator_group)
        && nss_group_matches(WORKER_ACCOUNT, worker_group)
        && nss_group_matches(SHADOW_GROUP, shadow_group)
        && account_groups_match(
            AGENT_ACCOUNT,
            agent.gid,
            &[agent_group.gid, operator_group.gid],
        )
        && account_groups_match(WORKER_ACCOUNT, worker.gid, &[worker_group.gid]);
    Ok(identities_match)
}

fn read_root_account_database(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    if maximum == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero account bound",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    let permissions = before.mode() & 0o7777;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || permissions & 0o400 == 0
        || permissions & !0o644 != 0
        || before.len() == 0
        || before.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe local account database",
        ));
    }
    let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
    let mut limited = file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    let after = limited.into_inner().metadata()?;
    if bytes.len() > maximum
        || u64::try_from(bytes.len()).ok() != Some(before.len())
        || !same_database_snapshot(&before, &after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local account database changed while read",
        ));
    }
    Ok(bytes)
}

fn same_database_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn nss_files_are_authoritative(bytes: &[u8]) -> bool {
    if !database_has_safe_physical_lines(bytes, true) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut seen = [false; 4];
    for raw_line in text.lines() {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        let Some((database, sources)) = line.split_once(':') else {
            continue;
        };
        let index = match database.trim() {
            "passwd" => 0,
            "group" => 1,
            "shadow" => 2,
            "initgroups" => 3,
            _ => continue,
        };
        let mut sources = sources.split_ascii_whitespace();
        if seen[index]
            || sources.next() != Some("files")
            || !matches!(sources.next(), None | Some("systemd"))
            || sources.next().is_some()
        {
            return false;
        }
        seen[index] = true;
    }
    seen[..3].iter().all(|entry| *entry)
}

fn database_has_safe_physical_lines(bytes: &[u8], allow_empty: bool) -> bool {
    if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes.contains(&0) || bytes.contains(&b'\r') {
        return false;
    }
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .all(|line| {
            line.len() <= MAX_ACCOUNT_DATABASE_LINE_BYTES && (allow_empty || !line.is_empty())
        })
}

fn parse_canonical_account_id(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes.first() == Some(&b'0')) {
        return None;
    }
    let mut value = 0_u32;
    for byte in bytes {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(digit))?;
    }
    (value != u32::MAX).then_some(value)
}

fn local_passwd_identity<'a>(bytes: &'a [u8], account: &str) -> Option<LocalPasswdIdentity<'a>> {
    if !database_has_safe_physical_lines(bytes, false) {
        return None;
    }
    let mut found = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next()?;
        let password = fields.next()?;
        let uid = parse_canonical_account_id(fields.next()?)?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        let gecos = fields.next()?;
        let directory = fields.next()?;
        let shell = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        if name == account.as_bytes() {
            if found.is_some() {
                return None;
            }
            found = Some(LocalPasswdIdentity {
                name,
                password,
                uid,
                gid,
                gecos,
                directory,
                shell,
            });
        }
    }
    let found = found?;
    let mut uid_uses = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        fields.next()?;
        fields.next()?;
        if parse_canonical_account_id(fields.next()?)? == found.uid {
            uid_uses = uid_uses.checked_add(1)?;
        }
    }
    (uid_uses == 1).then_some(found)
}

fn local_group_identity<'a>(bytes: &'a [u8], account: &str) -> Option<LocalGroupIdentity<'a>> {
    if !database_has_safe_physical_lines(bytes, false) {
        return None;
    }
    let mut found = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next()?;
        let password = fields.next()?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        let members = fields.next()?;
        if fields.next().is_some() || !local_group_member_list_is_canonical(members) {
            return None;
        }
        if name == account.as_bytes() {
            if found.is_some() {
                return None;
            }
            found = Some(LocalGroupIdentity {
                name,
                password,
                gid,
                members,
            });
        }
    }
    let found = found?;
    let mut gid_uses = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        fields.next()?;
        fields.next()?;
        if parse_canonical_account_id(fields.next()?)? == found.gid {
            gid_uses = gid_uses.checked_add(1)?;
        }
    }
    (gid_uses == 1).then_some(found)
}

fn local_group_member_list_is_canonical(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let members = bytes.split(|byte| *byte == b',').collect::<Vec<_>>();
    members.iter().enumerate().all(|(index, member)| {
        !member.is_empty() && !members[..index].iter().any(|earlier| earlier == member)
    })
}

fn local_account_contract_matches(
    agent: LocalPasswdIdentity<'_>,
    worker: LocalPasswdIdentity<'_>,
    agent_group: LocalGroupIdentity<'_>,
    operator_group: LocalGroupIdentity<'_>,
    worker_group: LocalGroupIdentity<'_>,
    shadow_group: LocalGroupIdentity<'_>,
    groups: &[u8],
) -> bool {
    let group_ids = [
        agent_group.gid,
        operator_group.gid,
        worker_group.gid,
        shadow_group.gid,
    ];
    agent.name == AGENT_ACCOUNT.as_bytes()
        && worker.name == WORKER_ACCOUNT.as_bytes()
        && agent.password == b"x"
        && worker.password == b"x"
        && service_identity_id_is_valid(agent.uid)
        && service_identity_id_is_valid(worker.uid)
        && agent.uid != worker.uid
        && agent.gid == agent_group.gid
        && worker.gid == worker_group.gid
        && agent.directory == b"/var/lib/volparossa"
        && worker.directory == b"/nonexistent"
        && agent.shell == b"/usr/sbin/nologin"
        && worker.shell == b"/usr/sbin/nologin"
        && agent_group.name == AGENT_ACCOUNT.as_bytes()
        && operator_group.name == OPERATOR_GROUP.as_bytes()
        && worker_group.name == WORKER_ACCOUNT.as_bytes()
        && shadow_group.name == SHADOW_GROUP.as_bytes()
        && [
            agent_group.password,
            operator_group.password,
            worker_group.password,
            shadow_group.password,
        ]
        .into_iter()
        .all(|password| password == b"x")
        && group_ids.into_iter().all(service_identity_id_is_valid)
        && group_ids
            .iter()
            .enumerate()
            .all(|(index, gid)| !group_ids[..index].contains(gid))
        && agent_group.members.is_empty()
        && worker_group.members.is_empty()
        && group_members_contain(operator_group.members, AGENT_ACCOUNT)
        && !group_members_contain(operator_group.members, WORKER_ACCOUNT)
        && !group_members_contain(shadow_group.members, AGENT_ACCOUNT)
        && !group_members_contain(shadow_group.members, WORKER_ACCOUNT)
        && local_group_ids_match(
            groups,
            AGENT_ACCOUNT,
            agent.gid,
            &[agent_group.gid, operator_group.gid],
        )
        && local_group_ids_match(groups, WORKER_ACCOUNT, worker.gid, &[worker_group.gid])
}

fn local_group_ids_match(bytes: &[u8], account: &str, primary_gid: u32, expected: &[u32]) -> bool {
    let Some(mut observed) = local_group_ids_for_account(bytes, account, primary_gid) else {
        return false;
    };
    let mut expected = expected.to_vec();
    observed.sort_unstable();
    expected.sort_unstable();
    observed == expected
}

fn local_group_ids_for_account(bytes: &[u8], account: &str, primary_gid: u32) -> Option<Vec<u32>> {
    let mut groups = vec![primary_gid];
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        fields.next()?;
        fields.next()?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        let members = fields.next()?;
        if fields.next().is_some() || !local_group_member_list_is_canonical(members) {
            return None;
        }
        if group_members_contain(members, account) {
            groups.push(gid);
        }
    }
    groups.sort_unstable();
    groups.dedup();
    Some(groups)
}

fn group_members_contain(bytes: &[u8], account: &str) -> bool {
    !bytes.is_empty()
        && bytes
            .split(|byte| *byte == b',')
            .any(|member| member == account.as_bytes())
}

fn nss_user_matches(account: &str, local: LocalPasswdIdentity<'_>) -> bool {
    let Ok(Some(by_name)) = User::from_name(account) else {
        return false;
    };
    let Ok(Some(by_uid)) = User::from_uid(nix::unistd::Uid::from_raw(local.uid)) else {
        return false;
    };
    by_name == by_uid
        && by_name.name == account
        && by_name.passwd.as_bytes() == local.password
        && by_name.uid.as_raw() == local.uid
        && by_name.gid.as_raw() == local.gid
        && by_name.gecos.as_bytes() == local.gecos
        && by_name.dir.as_os_str().as_bytes() == local.directory
        && by_name.shell.as_os_str().as_bytes() == local.shell
}

fn nss_group_matches(account: &str, local: LocalGroupIdentity<'_>) -> bool {
    let Ok(Some(by_name)) = Group::from_name(account) else {
        return false;
    };
    let Ok(Some(by_gid)) = Group::from_gid(Gid::from_raw(local.gid)) else {
        return false;
    };
    by_name == by_gid
        && by_name.name == account
        && by_name.passwd.as_bytes() == local.password
        && by_name.gid.as_raw() == local.gid
        && local_group_members_match(local.members, &by_name.mem)
}

fn local_group_members_match(bytes: &[u8], members: &[String]) -> bool {
    if bytes.is_empty() {
        return members.is_empty();
    }
    let mut expected = bytes.split(|byte| *byte == b',');
    members
        .iter()
        .all(|member| expected.next() == Some(member.as_bytes()))
        && expected.next().is_none()
}

fn account_groups_match(account: &str, primary_gid: u32, expected: &[u32]) -> bool {
    let Ok(name) = CString::new(account) else {
        return false;
    };
    let Ok(observed) = getgrouplist(&name, Gid::from_raw(primary_gid)) else {
        return false;
    };
    let mut observed = observed.into_iter().map(Gid::as_raw).collect::<Vec<_>>();
    observed.sort_unstable();
    if observed.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    observed == expected
}

fn validate_posix_access_acl_probe(result: Result<usize, rustix::io::Errno>) -> io::Result<()> {
    match result {
        Err(error) if error == rustix::io::Errno::NODATA => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadow account database has a POSIX access ACL",
        )),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("shadow POSIX access ACL probe failed: {error}"),
        )),
    }
}

fn validate_no_posix_access_acl(file: &fs::File) -> io::Result<()> {
    // One byte is enough for an existence probe without unsafe code. A present POSIX ACL is larger
    // and returns ERANGE; even a zero/one-byte value returns success. Both paths are rejected. Only
    // explicit absence is accepted; an unsupported ACL query cannot prove exclusivity and fails.
    let mut probe = [0_u8; 1];
    let result = rustix::fs::fgetxattr(file, POSIX_ACCESS_ACL_XATTR, &mut probe[..]);
    validate_posix_access_acl_probe(result)
}

fn read_locked_shadow_accounts(path: &Path) -> io::Result<bool> {
    let shadow_gid = Group::from_name(SHADOW_GROUP)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "shadow group missing"))?
        .gid
        .as_raw();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || !shadow_permissions_are_safe(before.mode(), before.gid(), shadow_gid)
        || before.len() == 0
        || before.len() > u64::try_from(MAX_SHADOW_BYTES).unwrap_or(u64::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe shadow account database",
        ));
    }
    validate_no_posix_access_acl(&file)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SHADOW_BYTES.saturating_add(1)));
    let mut limited = file.take(
        u64::try_from(MAX_SHADOW_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    );
    limited.read_to_end(&mut bytes)?;
    let after = limited.into_inner().metadata()?;
    if bytes.len() > MAX_SHADOW_BYTES
        || u64::try_from(bytes.len()).ok() != Some(before.len())
        || !same_database_snapshot(&before, &after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized shadow account database",
        ));
    }
    Ok(shadow_accounts_match_contract(&bytes))
}

fn shadow_permissions_are_safe(mode: u32, gid: u32, shadow_gid: u32) -> bool {
    let permissions = mode & 0o7777;
    permissions & 0o400 != 0
        && permissions & !0o640 == 0
        && (permissions & 0o040 == 0 || gid == shadow_gid)
}

fn shadow_accounts_match_contract(bytes: &[u8]) -> bool {
    if !database_has_safe_physical_lines(bytes, false) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut agent_locked = None;
    let mut worker_locked = None;
    for line in text.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            return false;
        };
        let Some(password) = fields.next() else {
            return false;
        };
        let Some(_last_change) = fields.next() else {
            return false;
        };
        let Some(_minimum_age) = fields.next() else {
            return false;
        };
        let Some(_maximum_age) = fields.next() else {
            return false;
        };
        let Some(_warning_period) = fields.next() else {
            return false;
        };
        let Some(_inactivity_period) = fields.next() else {
            return false;
        };
        let Some(account_expiry) = fields.next() else {
            return false;
        };
        let Some(_reserved) = fields.next() else {
            return false;
        };
        if fields.next().is_some() {
            return false;
        }
        if name == AGENT_ACCOUNT {
            if agent_locked.is_some() {
                return false;
            }
            agent_locked = Some(password.starts_with('!'));
        } else if name == WORKER_ACCOUNT {
            if worker_locked.is_some() {
                return false;
            }
            worker_locked = Some(password.starts_with('!') && account_expiry == "1");
        }
    }
    agent_locked == Some(true) && worker_locked == Some(true)
}

fn worker_sysusers_contract_matches(bytes: &[u8]) -> bool {
    let Some(directives) = parse_sysusers_directives(bytes) else {
        return false;
    };
    let expected = [
        ["g", "volparossa", "-", "", "", ""],
        ["g", "volparossa-users", "-", "", "", ""],
        ["g", "volparossa-worker", "-", "", "", ""],
        [
            "u",
            "volparossa",
            "VOLPAROSSA system service",
            "/var/lib/volparossa",
            "/usr/sbin/nologin",
            "",
        ],
        [
            "u!",
            "volparossa-worker",
            "VOLPAROSSA isolated route worker",
            "/nonexistent",
            "/usr/sbin/nologin",
            "",
        ],
        ["m", "volparossa", "volparossa-users", "", "", ""],
    ];
    directives == expected
}

fn parse_sysusers_directives(bytes: &[u8]) -> Option<Vec<[&str; 6]>> {
    let input = std::str::from_utf8(bytes).ok()?;
    let mut directives = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if directives.len() >= 128 {
            return None;
        }
        let fields = split_sysusers_fields(line)?;
        let directive = match fields.as_slice() {
            [kind @ ("g" | "m"), name, id] => [*kind, *name, *id, "", "", ""],
            [kind @ ("u" | "u!"), name, "-", gecos, home, shell] => {
                [*kind, *name, *gecos, *home, *shell, ""]
            }
            _ => return None,
        };
        directives.push(directive);
    }
    Some(directives)
}

fn split_sysusers_fields(line: &str) -> Option<Vec<&str>> {
    let mut fields = Vec::new();
    let mut start = None;
    let mut quoted = false;
    let mut closed_quote = false;
    for (index, character) in line.char_indices() {
        if !character.is_ascii() || character.is_ascii_control() {
            return None;
        }
        if closed_quote {
            if character.is_ascii_whitespace() {
                closed_quote = false;
                continue;
            }
            return None;
        }
        match character {
            '"' => {
                if quoted {
                    fields.push(&line[start?..index]);
                    start = None;
                    closed_quote = true;
                } else if start.is_some() {
                    return None;
                }
                quoted = !quoted;
            }
            value if value.is_ascii_whitespace() && !quoted => {
                if let Some(field_start) = start.take() {
                    fields.push(&line[field_start..index]);
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(index);
                }
            }
        }
    }
    if quoted {
        return None;
    }
    if let Some(field_start) = start {
        fields.push(&line[field_start..]);
    }
    (!fields.is_empty()).then_some(fields)
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
    if !common_unit_sandbox_matches(service, kind) {
        return false;
    }

    let protect_control_groups = match kind {
        UnitKind::Helper => "strict",
        UnitKind::Agent | UnitKind::Native => "yes",
    };
    let (
        user,
        executable,
        private_devices,
        kernel_tunables,
        namespaces,
        families,
        allowed_syscalls,
        denied_syscalls,
    ) = match kind {
        UnitKind::Agent => (
            "volparossa",
            "/usr/bin/volparossa-agent",
            "yes",
            "yes",
            "yes",
            ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"].as_slice(),
            ["@system-service", "@network-io"].as_slice(),
            [].as_slice(),
        ),
        UnitKind::Helper => (
            "root",
            "/usr/libexec/volparossa/volparossa-helper",
            "no",
            "no",
            "net",
            ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"].as_slice(),
            ["@system-service", "@network-io", "seccomp"].as_slice(),
            ["~@mount"].as_slice(),
        ),
        UnitKind::Native => (
            "volparossa",
            "/usr/libexec/volparossa/volparossa-mpquic-launch",
            "yes",
            "yes",
            "yes",
            ["AF_UNIX", "AF_INET", "AF_INET6"].as_slice(),
            ["@system-service", "@network-io"].as_slice(),
            [].as_slice(),
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
            .get("ProtectControlGroups")
            .is_some_and(|value| value == protect_control_groups)
        && service
            .get("ProtectKernelTunables")
            .is_some_and(|value| value == kernel_tunables)
        && service
            .get("RestrictNamespaces")
            .is_some_and(|value| value == namespaces)
        && value_set_matches(service, "RestrictAddressFamilies", families)
        && system_call_filter_matches(service, allowed_syscalls, denied_syscalls)
        && match kind {
            UnitKind::Helper => helper_has_required_custody_sandbox(service),
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

fn common_unit_sandbox_matches(service: &BTreeMap<String, String>, kind: UnitKind) -> bool {
    // systemd v257 implements RestrictSUIDSGID by rejecting every openat2(2) call because seccomp
    // cannot inspect the indirect open_how mode. The privileged helper deliberately requires
    // openat2 without an unsafe openat fallback for pinned process/cgroup/namespace resolution.
    // The unprivileged services do not have that requirement and retain the restriction.
    let restrict_suid_sgid = match kind {
        UnitKind::Helper => "no",
        UnitKind::Agent | UnitKind::Native => "yes",
    };
    [
        ("UMask", "0077"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateMounts", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectHostname", "yes"),
        ("LockPersonality", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("RestrictRealtime", "yes"),
        ("RestrictSUIDSGID", restrict_suid_sgid),
        ("SystemCallArchitectures", "native"),
        ("SystemCallErrorNumber", "EPERM"),
    ]
    .iter()
    .all(|(key, expected)| service.get(*key).is_some_and(|value| value == expected))
}

fn system_call_filter_matches(
    service: &BTreeMap<String, String>,
    expected_allowed: &[&str],
    expected_denied: &[&str],
) -> bool {
    let Some(value) = service.get("SystemCallFilter") else {
        return false;
    };
    let mut rules = value.lines();
    let Some(allowed) = rules.next() else {
        return false;
    };
    let allowed = allowed.split_ascii_whitespace().collect::<BTreeSet<_>>();
    if allowed != expected_allowed.iter().copied().collect::<BTreeSet<_>>() {
        return false;
    }

    if expected_denied.is_empty() {
        return rules.next().is_none();
    }
    let Some(denied) = rules.next() else {
        return false;
    };
    denied.split_ascii_whitespace().collect::<BTreeSet<_>>()
        == expected_denied.iter().copied().collect::<BTreeSet<_>>()
        && rules.next().is_none()
}

fn helper_has_required_custody_sandbox(service: &BTreeMap<String, String>) -> bool {
    [
        ("LimitCORE", "0"),
        ("NotifyAccess", "main"),
        ("FileDescriptorStoreMax", "128"),
        ("FileDescriptorStorePreserve", "yes"),
        ("Delegate", "no"),
        ("PrivatePIDs", "no"),
    ]
    .iter()
    .chain(HELPER_SERVICE_MANAGER_CONTRACT.iter())
    .all(|(key, expected)| service.get(*key).is_some_and(|value| value == expected))
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
    let mut values: BTreeMap<String, String> = BTreeMap::new();
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
            "CapabilityBoundingSet" | "AmbientCapabilities" | "RestrictAddressFamilies"
        ) && values.contains_key(key)
        {
            return None;
        }
        let value = value.trim();
        if key == "SystemCallFilter" {
            if value.is_empty() {
                return None;
            }
            if let Some(existing) = values.get_mut(key) {
                existing.push('\n');
                existing.push_str(value);
            } else {
                values.insert(key.to_owned(), value.to_owned());
            }
        } else {
            values.insert(key.to_owned(), value.to_owned());
        }
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

    fn valid_posix_access_acl() -> [u8; 36] {
        let mut acl = [0_u8; 36];
        acl[0..4].copy_from_slice(&2_u32.to_le_bytes());
        for (index, (tag, permission)) in [(1_u16, 0o6_u16), (4, 0o6), (16, 0o4), (32, 0)]
            .into_iter()
            .enumerate()
        {
            let offset = 4 + index * 8;
            acl[offset..offset + 2].copy_from_slice(&tag.to_le_bytes());
            acl[offset + 2..offset + 4].copy_from_slice(&permission.to_le_bytes());
            acl[offset + 4..offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        acl
    }

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
        let repeated_filter = parse_service_unit(
            b"[Service]\nSystemCallFilter=@system-service @network-io seccomp\nSystemCallFilter=~@mount\n",
        )
        .expect("ordered system-call filter rules");
        assert_eq!(
            repeated_filter.get("SystemCallFilter").map(String::as_str),
            Some("@system-service @network-io seccomp\n~@mount")
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
    fn packaged_unprivileged_units_match_the_doctor_sandbox_contract() {
        for (unit, kind) in [
            (
                include_bytes!("../../../packaging/systemd/volparossa-agent.service").as_slice(),
                UnitKind::Agent,
            ),
            (
                include_bytes!("../../../packaging/systemd/volparossa-mpquic.service").as_slice(),
                UnitKind::Native,
            ),
        ] {
            let service = parse_service_unit(unit).expect("packaged service unit");
            assert!(unit_has_required_sandbox(&service, kind));

            let mut without_private_mounts = service;
            without_private_mounts.remove("PrivateMounts");
            assert!(!unit_has_required_sandbox(&without_private_mounts, kind));
        }
    }

    #[test]
    fn helper_openat2_compatibility_exception_is_kind_specific() {
        let mut helper = sandbox_fixture(UnitKind::Helper);
        assert_eq!(
            helper.get("RestrictSUIDSGID").map(String::as_str),
            Some("no")
        );
        helper.insert("RestrictSUIDSGID".to_owned(), "yes".to_owned());
        assert!(!unit_has_required_sandbox(&helper, UnitKind::Helper));

        for kind in [UnitKind::Agent, UnitKind::Native] {
            let mut service = sandbox_fixture(kind);
            assert_eq!(
                service.get("RestrictSUIDSGID").map(String::as_str),
                Some("yes")
            );
            service.insert("RestrictSUIDSGID".to_owned(), "no".to_owned());
            assert!(!unit_has_required_sandbox(&service, kind));
        }
    }

    #[test]
    fn packaged_helper_has_only_the_reviewed_worker_bootstrap_capabilities() {
        let helper = parse_service_unit(include_bytes!(
            "../../../packaging/systemd/volparossa-helper.service"
        ))
        .expect("packaged helper unit");
        assert!(unit_has_required_sandbox(&helper, UnitKind::Helper));
        assert!(helper_capability_contract_matches(&helper));
        assert_eq!(
            helper.get("SystemCallFilter").map(String::as_str),
            Some("@system-service @network-io seccomp\n~@mount")
        );
        assert_eq!(
            helper.get("ProtectControlGroups").map(String::as_str),
            Some("strict")
        );
        assert_eq!(helper.get("Delegate").map(String::as_str), Some("no"));
        assert_eq!(helper.get("PrivatePIDs").map(String::as_str), Some("no"));
        assert_eq!(
            helper.get("RestrictSUIDSGID").map(String::as_str),
            Some("no")
        );
        assert_eq!(helper.get("LimitCORE").map(String::as_str), Some("0"));
        assert_eq!(
            helper.get("FileDescriptorStoreMax").map(String::as_str),
            Some("128")
        );
        assert_eq!(
            helper
                .get("FileDescriptorStorePreserve")
                .map(String::as_str),
            Some("yes")
        );
        assert_eq!(helper.get("NotifyAccess").map(String::as_str), Some("main"));
        for (key, expected) in HELPER_SERVICE_MANAGER_CONTRACT {
            assert_eq!(helper.get(key).map(String::as_str), Some(expected));
        }

        for (key, relaxed) in [
            ("ProtectControlGroups", "yes"),
            ("Delegate", "yes"),
            ("PrivatePIDs", "yes"),
            ("Type", "notify"),
            ("ExitType", "cgroup"),
            ("RemainAfterExit", "yes"),
            ("SuccessExitStatus", "70"),
            ("Restart", "always"),
            ("RestartMode", "direct"),
            ("RestartSec", "infinity"),
            ("RestartForceExitStatus", "70"),
            ("RestartPreventExitStatus", "70"),
            ("KillMode", "mixed"),
            ("SendSIGKILL", "no"),
            ("FinalKillSignal", "SIGABRT"),
            ("TimeoutStopFailureMode", "abort"),
            ("TimeoutStopSec", "infinity"),
        ] {
            let mut service = helper.clone();
            service.insert(key.to_owned(), relaxed.to_owned());
            assert!(!unit_has_required_sandbox(&service, UnitKind::Helper));
        }

        let mut dumpable = helper.clone();
        dumpable.insert("LimitCORE".to_owned(), "infinity".to_owned());
        assert!(!unit_has_required_sandbox(&dumpable, UnitKind::Helper));
        assert!(!helper_capability_contract_matches(&dumpable));

        for omitted in HELPER_BOOTSTRAP_CAPABILITIES {
            let mut missing = helper.clone();
            let reduced = HELPER_BOOTSTRAP_CAPABILITIES
                .iter()
                .copied()
                .filter(|capability| *capability != omitted)
                .collect::<Vec<_>>()
                .join(" ");
            missing.insert("CapabilityBoundingSet".to_owned(), reduced.clone());
            missing.insert("AmbientCapabilities".to_owned(), reduced);
            assert!(
                !helper_capability_contract_matches(&missing),
                "omitted {omitted}"
            );
        }

        let mut extra = helper.clone();
        extra.insert(
            "CapabilityBoundingSet".to_owned(),
            format!("{} CAP_SYS_PTRACE", HELPER_BOOTSTRAP_CAPABILITIES.join(" ")),
        );
        extra.insert(
            "AmbientCapabilities".to_owned(),
            format!("{} CAP_SYS_PTRACE", HELPER_BOOTSTRAP_CAPABILITIES.join(" ")),
        );
        assert!(!helper_capability_contract_matches(&extra));

        let mut mismatched_ambient = helper;
        mismatched_ambient.insert(
            "AmbientCapabilities".to_owned(),
            "CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN".to_owned(),
        );
        assert!(!helper_capability_contract_matches(&mismatched_ambient));
    }

    #[test]
    fn packaged_helper_requires_ordered_explicit_mount_syscall_denial() {
        let helper = parse_service_unit(include_bytes!(
            "../../../packaging/systemd/volparossa-helper.service"
        ))
        .expect("packaged helper unit");

        for invalid_filter in [
            "@system-service @network-io seccomp @mount\n~@mount",
            "@system-service @network-io seccomp",
            "~@mount\n@system-service @network-io seccomp",
        ] {
            let mut invalid = helper.clone();
            invalid.insert("SystemCallFilter".to_owned(), invalid_filter.to_owned());
            assert!(!unit_has_required_sandbox(&invalid, UnitKind::Helper));
        }
    }

    #[test]
    fn packaged_worker_sysusers_contract_is_fully_locked_and_group_isolated() {
        let packaged = include_bytes!("../../../packaging/systemd/volparossa.sysusers");
        assert!(worker_sysusers_contract_matches(packaged));

        let text = std::str::from_utf8(packaged).expect("UTF-8 sysusers contract");
        let unlocked = text.replacen("u!     volparossa-worker", "u      volparossa-worker", 1);
        assert!(!worker_sysusers_contract_matches(unlocked.as_bytes()));

        let login_shell = text.replacen(
            "/nonexistent         /usr/sbin/nologin",
            "/nonexistent         /bin/sh",
            1,
        );
        assert!(!worker_sysusers_contract_matches(login_shell.as_bytes()));

        let service_group_member = format!("{text}m volparossa-worker volparossa\n");
        assert!(!worker_sysusers_contract_matches(
            service_group_member.as_bytes()
        ));

        let wrong_primary_group = text.replacen(
            "u!     volparossa-worker  -",
            "u!     volparossa-worker  -:volparossa",
            1,
        );
        assert!(!worker_sysusers_contract_matches(
            wrong_primary_group.as_bytes()
        ));

        let concatenated_fields = text.replacen("worker\" /nonexistent", "worker\"/nonexistent", 1);
        assert!(!worker_sysusers_contract_matches(
            concatenated_fields.as_bytes()
        ));
    }

    #[test]
    fn live_account_nss_order_is_local_only_and_action_free() {
        for valid in [
            b"passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n".as_slice(),
            b"# canonical local accounts\npasswd: files\ngroup: files\nshadow: files\ninitgroups: files\n",
        ] {
            assert!(nss_files_are_authoritative(valid));
        }
        for invalid in [
            b"passwd: sss files\ngroup: files\nshadow: files\n".as_slice(),
            b"passwd: files sss\ngroup: files\nshadow: files\n",
            b"passwd: files [SUCCESS=continue] sss\ngroup: files\nshadow: files\n",
            b"passwd: files\ngroup: files\n",
            b"passwd: files\ngroup: files\nshadow: files",
        ] {
            assert!(!nss_files_are_authoritative(invalid));
        }
    }

    #[test]
    fn live_local_account_contract_rejects_id_aliases_and_group_leaks() {
        let passwd = concat!(
            "volparossa:x:20001:20011:agent:/var/lib/volparossa:/usr/sbin/nologin\n",
            "volparossa-worker:x:20002:20012:worker:/nonexistent:/usr/sbin/nologin\n",
        );
        let groups = concat!(
            "volparossa:x:20011:\n",
            "volparossa-users:x:20013:volparossa\n",
            "volparossa-worker:x:20012:\n",
            "shadow:x:42:\n",
        );
        let contract = |passwd_bytes: &[u8], group_bytes: &[u8]| {
            let Some(agent_group) = local_group_identity(group_bytes, AGENT_ACCOUNT) else {
                return false;
            };
            let Some(operator_group) = local_group_identity(group_bytes, OPERATOR_GROUP) else {
                return false;
            };
            let Some(worker_group) = local_group_identity(group_bytes, WORKER_ACCOUNT) else {
                return false;
            };
            let Some(shadow_group) = local_group_identity(group_bytes, SHADOW_GROUP) else {
                return false;
            };
            local_account_contract_matches(
                local_passwd_identity(passwd_bytes, AGENT_ACCOUNT).expect("agent"),
                local_passwd_identity(passwd_bytes, WORKER_ACCOUNT).expect("worker"),
                agent_group,
                operator_group,
                worker_group,
                shadow_group,
                group_bytes,
            )
        };
        assert!(contract(passwd.as_bytes(), groups.as_bytes()));
        assert!(contract(
            passwd.as_bytes(),
            groups
                .replace(
                    "volparossa-users:x:20013:volparossa",
                    "volparossa-users:x:20013:volparossa,alice",
                )
                .as_bytes()
        ));
        for reserved_passwd in [
            passwd.replace("volparossa:x:20001:", "volparossa:x:65535:"),
            passwd.replace("volparossa-worker:x:20002:", "volparossa-worker:x:65535:"),
        ] {
            assert!(!contract(reserved_passwd.as_bytes(), groups.as_bytes()));
        }
        for reserved_group in [
            groups.replace("volparossa:x:20011:", "volparossa:x:65535:"),
            groups.replace("volparossa-users:x:20013:", "volparossa-users:x:65535:"),
            groups.replace("volparossa-worker:x:20012:", "volparossa-worker:x:65535:"),
            groups.replace("shadow:x:42:", "shadow:x:65535:"),
        ] {
            assert!(!contract(passwd.as_bytes(), reserved_group.as_bytes()));
        }
        assert!(!contract(
            passwd.as_bytes(),
            groups
                .replace("shadow:x:42:", "shadow:x:42:volparossa-worker")
                .as_bytes()
        ));
        assert!(!contract(
            passwd.as_bytes(),
            groups
                .replace(
                    "volparossa-users:x:20013:volparossa",
                    "volparossa-users:x:20013:volparossa,volparossa-worker",
                )
                .as_bytes()
        ));
        assert!(!contract(
            passwd.as_bytes(),
            groups
                .replace(
                    "volparossa-users:x:20013:volparossa",
                    "volparossa-users:x:20013:",
                )
                .as_bytes()
        ));
        assert!(
            local_passwd_identity(
                concat!(
                    "alias:x:20002:30000:alias:/nonexistent:/usr/sbin/nologin\n",
                    "volparossa-worker:x:20002:20012:worker:/nonexistent:/usr/sbin/nologin\n",
                )
                .as_bytes(),
                WORKER_ACCOUNT,
            )
            .is_none()
        );
    }

    #[test]
    fn live_shadow_parser_requires_locked_agent_and_account_locked_worker() {
        let shadow = |agent_password: &str, worker_password: &str| {
            format!(
                "root:*:20000:0:99999:7:::\n{AGENT_ACCOUNT}:{agent_password}:20000::::::\n{WORKER_ACCOUNT}:{worker_password}:20000:::::1:\n"
            )
        };
        for agent_password in ["!", "!!", "!$y$j9T$disabled", "!*"] {
            for worker_password in ["!", "!!", "!$y$j9T$disabled", "!*"] {
                assert!(shadow_accounts_match_contract(
                    shadow(agent_password, worker_password).as_bytes()
                ));
            }
        }
        for shadow in [
            shadow("$6$live", "!*"),
            shadow("*", "!*"),
            shadow("", "!*"),
            shadow("!*", "$6$live"),
            shadow("!*", "*"),
            shadow("!*", ""),
            format!("{AGENT_ACCOUNT}:!*:20000::::::\n{WORKER_ACCOUNT}:!*:20000::::::\n"),
            format!("{AGENT_ACCOUNT}:!*:20000::::::\n"),
            format!("{WORKER_ACCOUNT}:!*:20000:::::1:\n"),
            format!(
                "{AGENT_ACCOUNT}:!*:20000::::::\n{AGENT_ACCOUNT}:!:20000::::::\n{WORKER_ACCOUNT}:!*:20000:::::1:\n"
            ),
            format!(
                "{AGENT_ACCOUNT}:!*:20000::::::\n{WORKER_ACCOUNT}:!*:20000:::::1:\n{WORKER_ACCOUNT}:!:20000:::::1:\n"
            ),
            format!("{AGENT_ACCOUNT}:!*:20000::::::\n{WORKER_ACCOUNT}:!:20000:::::1"),
            "root:*:20000:0:99999:7:::\n".to_owned(),
        ] {
            assert!(!shadow_accounts_match_contract(shadow.as_bytes()));
        }
        assert!(!shadow_accounts_match_contract(&[0xff]));
    }

    #[test]
    fn live_shadow_metadata_rejects_mutable_executable_or_broad_access() {
        let shadow_gid = 42;
        for mode in [0o400, 0o440, 0o600, 0o640] {
            assert!(shadow_permissions_are_safe(mode, shadow_gid, shadow_gid));
        }
        assert!(shadow_permissions_are_safe(0o600, 12_345, shadow_gid));
        for mode in [0o000, 0o200, 0o660, 0o700, 0o644, 0o4640] {
            assert!(!shadow_permissions_are_safe(mode, shadow_gid, shadow_gid));
        }
        assert!(!shadow_permissions_are_safe(0o640, 12_345, shadow_gid));
    }

    #[test]
    fn live_shadow_posix_access_acl_probe_is_explicit_and_fail_closed() {
        validate_posix_access_acl_probe(Err(rustix::io::Errno::NODATA))
            .expect("explicitly absent access ACL");
        for result in [
            Ok(0),
            Ok(1),
            Ok(36),
            Err(rustix::io::Errno::RANGE),
            Err(rustix::io::Errno::NOTSUP),
            Err(rustix::io::Errno::OPNOTSUPP),
            Err(rustix::io::Errno::ACCESS),
            Err(rustix::io::Errno::PERM),
            Err(rustix::io::Errno::IO),
            Err(rustix::io::Errno::NOSYS),
        ] {
            let error = validate_posix_access_acl_probe(result).expect_err("ACL must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }

        let directory = tempdir().expect("temporary directory");
        let file =
            fs::File::create(directory.path().join("shadow")).expect("temporary shadow file");
        match rustix::fs::fsetxattr(
            &file,
            POSIX_ACCESS_ACL_XATTR,
            &valid_posix_access_acl(),
            rustix::fs::XattrFlags::empty(),
        ) {
            Ok(()) => {
                let error = validate_no_posix_access_acl(&file)
                    .expect_err("an installed access ACL must be rejected");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            Err(error)
                if error == rustix::io::Errno::NOTSUP || error == rustix::io::Errno::OPNOTSUPP =>
            {
                let error = validate_no_posix_access_acl(&file)
                    .expect_err("unsupported ACL inspection must fail closed");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            Err(error) => panic!("valid access ACL fixture failed: {error}"),
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
        let restrict_suid_sgid = match kind {
            UnitKind::Helper => "no",
            UnitKind::Agent | UnitKind::Native => "yes",
        };
        let mut service = [
            ("Group", "volparossa"),
            ("UMask", "0077"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateMounts", "yes"),
            ("ProtectKernelModules", "yes"),
            ("ProtectKernelLogs", "yes"),
            ("ProtectClock", "yes"),
            ("ProtectHostname", "yes"),
            ("LockPersonality", "yes"),
            ("MemoryDenyWriteExecute", "yes"),
            ("RestrictRealtime", "yes"),
            ("RestrictSUIDSGID", restrict_suid_sgid),
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
                        ("ProtectControlGroups", "yes"),
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
                        ("ProtectControlGroups", "strict"),
                        ("Delegate", "no"),
                        ("PrivatePIDs", "no"),
                        ("ProtectKernelTunables", "no"),
                        ("RestrictNamespaces", "net"),
                        (
                            "RestrictAddressFamilies",
                            "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
                        ),
                        (
                            "SystemCallFilter",
                            "@system-service @network-io seccomp\n~@mount",
                        ),
                        ("LimitCORE", "0"),
                        ("NotifyAccess", "main"),
                        ("FileDescriptorStoreMax", "128"),
                        ("FileDescriptorStorePreserve", "yes"),
                    ],
                );
                insert_fixture(&mut service, &HELPER_SERVICE_MANAGER_CONTRACT);
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
                        ("ProtectControlGroups", "yes"),
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
