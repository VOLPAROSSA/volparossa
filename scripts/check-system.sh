#!/bin/sh
# Read-only Debian 13 prerequisite inspection. This script never changes kernel or network state.
set -eu

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

policy_manifest=${VOLPAROSSA_POLICY_MANIFEST:-}
failures=0
warnings=0

usage() {
    printf '%s\n' 'Usage: scripts/check-system.sh [--policy /path/to/manifest]'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --policy)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            policy_manifest=$2
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

pass() { printf 'PASS  %s\n' "$1"; }
warn() { printf 'WARN  %s\n' "$1"; warnings=$((warnings + 1)); }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

printf '%s\n' \
    'VOLPAROSSA read-only system check' \
    'No modules, sysctls, sockets, routes, rules, firewalls, interfaces, namespaces, DNS, or services are changed.'

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ]; then
        pass 'operating system is Debian 13'
    else
        fail "operating system is ${ID:-unknown} ${VERSION_ID:-unknown}; Debian 13 is required"
    fi
else
    fail '/etc/os-release is unreadable'
fi

if command -v dpkg >/dev/null 2>&1 && [ "$(dpkg --print-architecture)" = amd64 ]; then
    pass 'architecture is amd64'
else
    fail 'architecture is not Debian amd64 or dpkg is unavailable'
fi

kernel_release=$(uname -r)
kernel_major=$(printf '%s' "$kernel_release" | awk -F. '{print $1}')
kernel_minor=$(printf '%s' "$kernel_release" | awk -F. '{print $2}')
if [ "${kernel_major:-0}" -gt 6 ] || { [ "${kernel_major:-0}" -eq 6 ] && [ "${kernel_minor:-0}" -ge 12 ]; }; then
    pass "kernel $kernel_release is at least the Debian 13 baseline"
else
    warn "kernel $kernel_release is older than the expected Debian 13 baseline; verify support"
fi

required_commands='cargo rustc rustfmt cargo-clippy pkg-config protoc git just shellcheck ip nft wg systemctl'
for command_name in $required_commands; do
    if command -v "$command_name" >/dev/null 2>&1; then
        pass "command available: $command_name"
    else
        fail "command missing: $command_name"
    fi
done

if cargo deny --version >/dev/null 2>&1; then
    if cargo deny check advisories --disable-fetch >/dev/null 2>&1; then
        pass 'cargo deny advisory parser and local RustSec database are usable'
    else
        warn 'cargo deny is installed but its offline advisory gate is not green; require CVSS 4.0-capable cargo-deny >= 0.18.6 and inspect matched advisories'
    fi
else
    warn 'diagnostic/native command missing: cargo deny'
fi

optional_commands='clang cmake ninja valgrind jq tcpdump tc iperf3 perf getcap timedatectl'
for command_name in $optional_commands; do
    if command -v "$command_name" >/dev/null 2>&1; then
        pass "diagnostic/native command available: $command_name"
    else
        warn "diagnostic/native command missing: $command_name"
    fi
done

if [ -r /proc/sys/net/mptcp/enabled ]; then
    mptcp_enabled=$(sed -n '1p' /proc/sys/net/mptcp/enabled)
    if [ "$mptcp_enabled" = 1 ]; then
        pass 'kernel MPTCP is available and enabled'
    else
        fail "kernel MPTCP sysctl reads '$mptcp_enabled' (script did not change it)"
    fi
else
    fail 'kernel MPTCP sysctl is absent'
fi

kernel_config=/boot/config-$kernel_release
if [ -r "$kernel_config" ]; then
    if grep -Eq '^CONFIG_MPTCP=y$' "$kernel_config"; then
        pass 'kernel config contains CONFIG_MPTCP=y'
    else
        fail 'kernel config does not contain CONFIG_MPTCP=y'
    fi
    if grep -Eq '^CONFIG_WIREGUARD=(y|m)$' "$kernel_config"; then
        pass 'kernel config contains WireGuard support'
    else
        fail 'kernel config does not show WireGuard support'
    fi
    if grep -Eq '^CONFIG_IPV6=y$' "$kernel_config"; then
        pass 'kernel config contains IPv6 support'
    else
        fail 'kernel config does not contain IPv6 support'
    fi
else
    warn "kernel config $kernel_config is unreadable; no module was loaded to probe it"
    if [ -d /sys/module/wireguard ]; then
        pass 'WireGuard module is already loaded'
    else
        warn 'WireGuard module is not currently visible; this check does not load modules'
    fi
fi

if [ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    ipv6_disabled=$(sed -n '1p' /proc/sys/net/ipv6/conf/all/disable_ipv6)
    if [ "$ipv6_disabled" = 0 ]; then
        pass 'IPv6 is not globally disabled'
    else
        fail "IPv6 disable flag reads '$ipv6_disabled' (script did not change it)"
    fi
else
    fail 'IPv6 sysctl is unavailable'
fi

if [ -r /proc/net/udp ] && [ -r /proc/net/udp6 ]; then
    pass 'kernel exposes IPv4 and IPv6 UDP tables'
else
    fail 'IPv4 or IPv6 UDP table is unavailable'
fi

if command -v pkg-config >/dev/null 2>&1; then
    for library_name in sqlite3 openssl libevent libmnl libnl-genl-3.0; do
        if pkg-config --exists "$library_name"; then
            pass "development library available: $library_name"
        else
            warn "development library missing: $library_name"
        fi
    done
fi

if command -v timedatectl >/dev/null 2>&1; then
    clock_sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [ "$clock_sync" = yes ]; then
        pass 'systemd reports synchronized wall clock'
    else
        warn 'systemd does not report a synchronized wall clock; signed TTL checks may fail'
    fi
else
    warn 'timedatectl unavailable; clock synchronization not verified'
fi

if command -v ip >/dev/null 2>&1; then
    if ip rule show 2>/dev/null | grep -Eq '(^|[^0-9])(7600|76[0-9][0-9])([^0-9]|$)'; then
        warn 'an existing policy rule appears to use VOLPAROSSA-reserved table range 7600-7699'
    else
        pass 'no visible policy rule conflicts with table range 7600-7699'
    fi
    if ip route show table all 2>/dev/null | grep -Eq '(^|[[:space:]])76[0-9][0-9]([[:space:]]|$)'; then
        warn 'an existing route appears to use VOLPAROSSA-reserved table range 7600-7699'
    else
        pass 'no visible route conflicts with table range 7600-7699'
    fi
fi

for binary_path in /usr/bin/volparossa-agent /usr/libexec/volparossa/volparossa-helper /usr/libexec/volparossa/volparossa-mpquic; do
    if [ -e "$binary_path" ]; then
        if [ -x "$binary_path" ]; then
            pass "installed executable present: $binary_path"
        else
            fail "installed runtime is not executable: $binary_path"
        fi
    else
        warn "runtime not installed: $binary_path"
    fi
done

if [ -n "$policy_manifest" ]; then
    if [ -f "$policy_manifest" ] && [ -r "$policy_manifest" ]; then
        pass 'configured policy manifest is a readable regular file (cryptographic verification requires the CLI)'
    else
        fail 'configured policy manifest is absent, unreadable, or not a regular file'
    fi
else
    warn 'no policy manifest path supplied; exits and connections must fail closed'
fi

printf '\nSummary: %s failure(s), %s warning(s). No changes made.\n' "$failures" "$warnings"
[ "$failures" -eq 0 ]
