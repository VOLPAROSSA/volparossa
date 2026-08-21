//! Fail-closed relay forwarding policy compiled by the fixed Debian nftables frontend.
//!
//! The workspace has no audited encoder for nested `nf_tables` expressions and no
//! libnftnl binding. Reimplementing payload, meta, lookup, limit, and verdict expression
//! ABIs here would create an unaudited privileged parser. Debian packaging already makes
//! nftables a hard runtime dependency, so this module uses only the absolute
//! `/usr/sbin/nft -f -` frontend. The complete internally rendered ruleset is one
//! netlink batch; no shell, agent-supplied text, command output, or output parsing exists.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    net::Ipv6Addr,
    os::unix::{fs::PermissionsExt as _, process::CommandExt as _},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use nix::{
    sys::{prctl, signal::Signal},
    unistd::{geteuid, getppid},
};
use thiserror::Error;
use volparossa_routing::MAX_HELPER_RATE_MBPS;
use volparossa_wireguard::{EndpointRole, interface_name, overlay_prefix};

const NFT_BINARY: &str = "/usr/sbin/nft";
/// Fixed internal mode which applies parent-death protection before the nftables exec.
#[doc(hidden)]
pub const INTERNAL_NFT_FRONTEND_ARGUMENT: &str = "--internal-nft-frontend-v1";
const NFT_TABLE: &str = "volparossa_relay";
const MAX_FENCE_TTL_SECONDS: u64 = 15 * 60;
const MAX_NFT_BATCH_BYTES: usize = 16 * 1024;
const NFT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(3);
const NFT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RATE_BURST_BYTES: u64 = 65_535;
const BITS_PER_MEGABIT: u64 = 1_000_000;
const BITS_PER_BYTE: u64 = 8;

/// A fixed failure at the internal relay-fence boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RelayFenceError {
    /// A typed value disagreed with the helper-derived topology.
    #[error("invalid relay fence topology")]
    Invalid,
    /// The absolute reservation expiry is not active.
    #[error("relay fence reservation is expired")]
    Expired,
    /// An active path already has a different fence.
    #[error("relay fence conflicts with active state")]
    Conflict,
    /// The fixed Debian nftables frontend is unavailable.
    #[error("nftables frontend is unavailable")]
    Unsupported,
    /// The nftables frontend rejected the complete atomic batch.
    #[error("nftables rejected relay fence")]
    Rejected,
    /// The fixed nftables execution deadline elapsed.
    #[error("nftables relay fence timed out")]
    Timeout,
    /// A bounded process or clock operation failed.
    #[error("relay fence backend I/O failed")]
    Io,
}

/// Fully derived policy data; it contains no agent-controlled strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelayFenceSpec {
    path_id: u8,
    prefix: Ipv6Addr,
    relay_client_interface: String,
    relay_exit_interface: String,
    expires_at_unix: u64,
    maximum_up_bytes_per_second: u64,
    maximum_down_bytes_per_second: u64,
}

impl RelayFenceSpec {
    /// Derive the exact fence from already validated v3 reservation state.
    pub(crate) fn derive(
        route_context_id: [u8; 16],
        path_id: u32,
        expires_at_unix: u64,
        maximum_up_mbps: u32,
        maximum_down_mbps: u32,
        now_unix: u64,
    ) -> Result<Self, RelayFenceError> {
        let path_id = u8::try_from(path_id).map_err(|_| RelayFenceError::Invalid)?;
        let expected_prefix =
            overlay_prefix(route_context_id, path_id).map_err(|_| RelayFenceError::Invalid)?;
        let remaining = expires_at_unix
            .checked_sub(now_unix)
            .filter(|seconds| *seconds > 0)
            .ok_or(RelayFenceError::Expired)?;
        if remaining > MAX_FENCE_TTL_SECONDS
            || maximum_up_mbps == 0
            || maximum_up_mbps > MAX_HELPER_RATE_MBPS
            || maximum_down_mbps == 0
            || maximum_down_mbps > MAX_HELPER_RATE_MBPS
        {
            return Err(RelayFenceError::Invalid);
        }

        let relay_client_interface =
            interface_name(route_context_id, path_id, EndpointRole::RelayClient)
                .map_err(|_| RelayFenceError::Invalid)?;
        let relay_exit_interface =
            interface_name(route_context_id, path_id, EndpointRole::RelayExit)
                .map_err(|_| RelayFenceError::Invalid)?;
        if !safe_interface_name(&relay_client_interface)
            || !safe_interface_name(&relay_exit_interface)
        {
            return Err(RelayFenceError::Invalid);
        }

        Ok(Self {
            path_id,
            prefix: expected_prefix.network(),
            relay_client_interface,
            relay_exit_interface,
            expires_at_unix,
            maximum_up_bytes_per_second: mbps_to_bytes(maximum_up_mbps),
            maximum_down_bytes_per_second: mbps_to_bytes(maximum_down_mbps),
        })
    }

    /// Return the path used to prove that both `WireGuard` links exist.
    pub(crate) const fn path_id(&self) -> u8 {
        self.path_id
    }

    /// Return the hard absolute expiry for a post-install stale check.
    pub(crate) const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

/// Pure state machine for exact idempotency and conflict-safe replacement.
#[derive(Debug, Default)]
pub(crate) struct RelayFenceRegistry {
    table_installed: bool,
    active: BTreeMap<u8, RelayFenceSpec>,
}

impl RelayFenceRegistry {
    /// Build an immutable update without changing committed state.
    pub(crate) fn plan(
        &self,
        specification: RelayFenceSpec,
        now_unix: u64,
    ) -> Result<RelayFencePlan, RelayFenceError> {
        let mut next = self.active.clone();
        next.retain(|_, fence| fence.expires_at_unix > now_unix);
        if let Some(existing) = next.get(&specification.path_id) {
            return if existing == &specification {
                Ok(RelayFencePlan::Present)
            } else {
                Err(RelayFenceError::Conflict)
            };
        }
        next.insert(specification.path_id, specification);
        let batch = render_batch(&next, now_unix, self.table_installed)?;
        Ok(RelayFencePlan::Install(RelayFenceUpdate { next, batch }))
    }

    /// Commit only after the complete nftables transaction succeeded.
    pub(crate) fn commit(&mut self, update: RelayFenceUpdate) {
        self.active = update.next;
        self.table_installed = true;
    }
}

/// A planned idempotent result or one complete atomic ruleset replacement.
pub(crate) enum RelayFencePlan {
    /// The exact still-active policy is already committed.
    Present,
    /// The private batch must succeed before state is committed.
    Install(RelayFenceUpdate),
}

/// Private rendered policy which cannot be constructed from request text.
pub(crate) struct RelayFenceUpdate {
    next: BTreeMap<u8, RelayFenceSpec>,
    batch: String,
}

impl RelayFenceUpdate {
    /// Execute the fixed absolute nftables frontend with a bounded deadline.
    pub(crate) fn apply(&self) -> Result<(), RelayFenceError> {
        execute_nft(&self.batch)
    }
}

/// Read current Unix seconds without accepting a caller-controlled clock.
pub(crate) fn unix_time_now() -> Result<u64, RelayFenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RelayFenceError::Io)
}

/// Exec the fixed nftables frontend after binding its lifetime to the namespace worker.
///
/// This mode is internal to the root helper. It accepts no arguments or caller-selected path;
/// standard input is the private batch pipe already created by the namespace worker.
///
/// # Errors
///
/// Returns an error if root, parent-death setup, or the absolute nftables exec is unavailable.
#[doc(hidden)]
pub fn run_internal_nft_frontend() -> Result<(), io::Error> {
    if !geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "internal nftables frontend requires root",
        ));
    }
    let original_parent = getppid();
    prctl::set_pdeathsig(Signal::SIGKILL)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    if getppid() != original_parent {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "namespace worker exited during nftables setup",
        ));
    }

    Err(Command::new(NFT_BINARY)
        .arg("-f")
        .arg("-")
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec())
}

fn mbps_to_bytes(rate_mbps: u32) -> u64 {
    u64::from(rate_mbps) * BITS_PER_MEGABIT / BITS_PER_BYTE
}

fn safe_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn render_batch(
    active: &BTreeMap<u8, RelayFenceSpec>,
    now_unix: u64,
    replace: bool,
) -> Result<String, RelayFenceError> {
    if active.is_empty() {
        return Err(RelayFenceError::Invalid);
    }

    let mut batch = String::with_capacity(4_096);
    if replace {
        writeln!(batch, "delete table inet {NFT_TABLE}").map_err(|_| RelayFenceError::Invalid)?;
    }
    writeln!(batch, "table inet {NFT_TABLE} {{").map_err(|_| RelayFenceError::Invalid)?;

    for fence in active.values() {
        let remaining = fence
            .expires_at_unix
            .checked_sub(now_unix)
            .filter(|seconds| *seconds > 0)
            .ok_or(RelayFenceError::Expired)?;
        writeln!(
            batch,
            "    set lease_p{} {{\n        type ipv6_addr;\n        flags interval, timeout;\n        elements = {{ {}/112 timeout {}s }};\n    }}",
            fence.path_id, fence.prefix, remaining
        )
        .map_err(|_| RelayFenceError::Invalid)?;
    }

    batch.push_str(
        "    chain input {\n        type filter hook input priority filter; policy drop;\n    }\n",
    );
    batch.push_str(
        "    chain output {\n        type filter hook output priority filter; policy drop;\n    }\n",
    );
    batch.push_str(
        "    chain forward {\n        type filter hook forward priority filter; policy drop;\n",
    );
    for fence in active.values() {
        render_direction(
            &mut batch,
            fence,
            &fence.relay_client_interface,
            &fence.relay_exit_interface,
            fence.maximum_up_bytes_per_second,
        )?;
        render_direction(
            &mut batch,
            fence,
            &fence.relay_exit_interface,
            &fence.relay_client_interface,
            fence.maximum_down_bytes_per_second,
        )?;
    }
    batch.push_str("    }\n}\n");

    if batch.len() > MAX_NFT_BATCH_BYTES || !batch.is_ascii() || batch.as_bytes().contains(&0) {
        return Err(RelayFenceError::Invalid);
    }
    Ok(batch)
}

fn render_direction(
    batch: &mut String,
    fence: &RelayFenceSpec,
    incoming: &str,
    outgoing: &str,
    maximum_bytes_per_second: u64,
) -> Result<(), RelayFenceError> {
    writeln!(
        batch,
        "        iifname \"{incoming}\" oifname \"{outgoing}\" ip6 saddr @lease_p{} ip6 daddr @lease_p{} meta time < {} limit rate over {maximum_bytes_per_second} bytes/second burst {RATE_BURST_BYTES} bytes drop",
        fence.path_id, fence.path_id, fence.expires_at_unix
    )
    .map_err(|_| RelayFenceError::Invalid)?;
    writeln!(
        batch,
        "        iifname \"{incoming}\" oifname \"{outgoing}\" ip6 saddr @lease_p{} ip6 daddr @lease_p{} meta time < {} accept",
        fence.path_id, fence.path_id, fence.expires_at_unix
    )
    .map_err(|_| RelayFenceError::Invalid)
}

pub(crate) fn execute_nft(batch: &str) -> Result<(), RelayFenceError> {
    if batch.is_empty()
        || batch.len() > MAX_NFT_BATCH_BYTES
        || !batch.is_ascii()
        || batch.as_bytes().contains(&0)
    {
        return Err(RelayFenceError::Invalid);
    }
    ensure_nft_frontend()?;
    let executable = std::env::current_exe().map_err(|_| RelayFenceError::Io)?;

    let deadline = Instant::now() + NFT_EXECUTION_TIMEOUT;
    let mut command = Command::new(executable);
    command
        .arg(INTERNAL_NFT_FRONTEND_ARGUMENT)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| RelayFenceError::Io)?;
    let Some(mut input) = child.stdin.take() else {
        stop_child(&mut child);
        return Err(RelayFenceError::Io);
    };
    let bytes = batch.as_bytes().to_vec();
    let Ok(writer) = thread::Builder::new()
        .name("volparossa-nft-input".to_owned())
        .spawn(move || input.write_all(&bytes).map_err(|_| RelayFenceError::Io))
    else {
        stop_child(&mut child);
        return Err(RelayFenceError::Io);
    };

    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(RelayFenceError::Rejected),
            Ok(None) if Instant::now() < deadline => thread::sleep(NFT_POLL_INTERVAL),
            Ok(None) => {
                stop_child(&mut child);
                break Err(RelayFenceError::Timeout);
            }
            Err(_) => {
                stop_child(&mut child);
                break Err(RelayFenceError::Io);
            }
        }
    };
    let write_result = writer.join().map_err(|_| RelayFenceError::Io)?;
    match outcome {
        Ok(()) => write_result,
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_nft_frontend() -> Result<(), RelayFenceError> {
    validate_nft_frontend(Path::new(NFT_BINARY))
}

fn validate_nft_frontend(path: &Path) -> Result<(), RelayFenceError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            RelayFenceError::Unsupported
        } else {
            RelayFenceError::Io
        }
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(RelayFenceError::Unsupported);
    }
    Ok(())
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn specification(route: [u8; 16], path_id: u8) -> RelayFenceSpec {
        RelayFenceSpec::derive(route, u32::from(path_id), NOW + 120, 1, 2, NOW)
            .expect("valid fence")
    }

    #[test]
    fn derive_rejects_invalid_path_expiry_and_rates() {
        let route = [7; 16];
        RelayFenceSpec::derive(route, 1, NOW + 60, 1, 1, NOW).expect("exact derived policy");
        assert_eq!(
            RelayFenceSpec::derive(route, 0, NOW + 60, 1, 1, NOW),
            Err(RelayFenceError::Invalid)
        );
        assert_eq!(
            RelayFenceSpec::derive(route, 1, NOW, 1, 1, NOW),
            Err(RelayFenceError::Expired)
        );
        assert_eq!(
            RelayFenceSpec::derive(route, 1, NOW + MAX_FENCE_TTL_SECONDS + 1, 1, 1, NOW),
            Err(RelayFenceError::Invalid)
        );
        assert_eq!(
            RelayFenceSpec::derive(route, 1, NOW + 60, 0, 1, NOW),
            Err(RelayFenceError::Invalid)
        );
        assert_eq!(
            RelayFenceSpec::derive(route, 1, NOW + 60, MAX_HELPER_RATE_MBPS + 1, 1, NOW,),
            Err(RelayFenceError::Invalid)
        );
    }

    #[test]
    fn rendered_policy_is_default_deny_exact_expiring_and_has_no_nat() {
        let route = [9; 16];
        let fence = specification(route, 1);
        let expected_client = interface_name(route, 1, EndpointRole::RelayClient).expect("name");
        let expected_exit = interface_name(route, 1, EndpointRole::RelayExit).expect("name");
        let expected_prefix = overlay_prefix(route, 1).expect("prefix");
        let mut active = BTreeMap::new();
        active.insert(1, fence);
        let batch = render_batch(&active, NOW, false).expect("render");

        assert!(batch.starts_with("table inet volparossa_relay {\n"));
        assert_eq!(batch.matches("policy drop;").count(), 3);
        assert_eq!(batch.matches(" accept\n").count(), 2);
        assert_eq!(batch.matches(" limit rate over ").count(), 2);
        assert_eq!(
            batch
                .matches("bytes/second burst 65535 bytes drop\n")
                .count(),
            2
        );
        assert!(batch.contains("limit rate over 125000 bytes/second"));
        assert!(batch.contains("limit rate over 250000 bytes/second"));
        assert_eq!(batch.matches(&expected_client).count(), 4);
        assert_eq!(batch.matches(&expected_exit).count(), 4);
        assert!(batch.contains(&format!("{}/112 timeout 120s", expected_prefix.network())));
        assert_eq!(batch.matches("meta time < 1700000120").count(), 4);
        assert!(!batch.contains("nat"));
        assert!(!batch.contains("masquerade"));
        assert!(!batch.contains("snat"));
        assert!(!batch.contains("dnat"));
        assert!(!batch.contains("redirect"));
        assert!(batch.len() <= MAX_NFT_BATCH_BYTES);
        assert!(batch.is_ascii());
    }

    #[test]
    fn registry_is_exactly_idempotent_and_conflict_preserves_active_policy() {
        let route = [3; 16];
        let first = specification(route, 1);
        let mut registry = RelayFenceRegistry::default();
        let RelayFencePlan::Install(update) =
            registry.plan(first.clone(), NOW).expect("initial plan")
        else {
            panic!("initial policy must install");
        };
        assert!(!update.batch.starts_with("delete table"));
        registry.commit(update);

        assert!(matches!(
            registry.plan(first, NOW + 1).expect("idempotent"),
            RelayFencePlan::Present
        ));
        let conflict =
            RelayFenceSpec::derive(route, 1, NOW + 120, 5, 2, NOW).expect("conflicting policy");
        assert!(matches!(
            registry.plan(conflict, NOW),
            Err(RelayFenceError::Conflict)
        ));

        let second = specification(route, 2);
        let RelayFencePlan::Install(replacement) = registry.plan(second, NOW).expect("second path")
        else {
            panic!("second path must rebuild atomically");
        };
        assert!(
            replacement
                .batch
                .starts_with("delete table inet volparossa_relay\ntable inet")
        );
        let first_set = replacement.batch.find("set lease_p1").expect("path one");
        let second_set = replacement.batch.find("set lease_p2").expect("path two");
        assert!(first_set < second_set);
    }

    #[test]
    fn expired_state_is_replaced_not_reported_present() {
        let route = [4; 16];
        let old = RelayFenceSpec::derive(route, 1, NOW + 1, 1, 1, NOW).expect("old fence");
        let mut registry = RelayFenceRegistry::default();
        let RelayFencePlan::Install(update) = registry.plan(old, NOW).expect("install") else {
            panic!("install expected");
        };
        registry.commit(update);

        let renewed =
            RelayFenceSpec::derive(route, 1, NOW + 200, 1, 1, NOW + 2).expect("renewed fence");
        let RelayFencePlan::Install(update) = registry.plan(renewed, NOW + 2).expect("replace")
        else {
            panic!("expired state must be replaced");
        };
        assert!(update.batch.starts_with("delete table"));
        assert!(update.batch.contains("timeout 198s"));
    }

    #[test]
    fn missing_fixed_frontend_has_a_stable_unsupported_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("nft");

        assert_eq!(
            validate_nft_frontend(&missing),
            Err(RelayFenceError::Unsupported)
        );
    }
}
