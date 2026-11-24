#!/bin/sh
# Install only reviewed Debian development packages after an explicit preview and confirmation.
set -eu

export LC_ALL=C

print_only=0
with_mptcpd=0

usage() {
    printf '%s\n' \
        'Usage: scripts/bootstrap-debian13-dev.sh [--print-only] [--with-mptcpd]' \
        '' \
        '  --print-only    Resolve and print apt packages; make no changes.' \
        '  --with-mptcpd   Include the optional mptcpd backend development packages.'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --print-only) print_only=1 ;;
        --with-mptcpd) with_mptcpd=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ ! -r /etc/os-release ]; then
    printf '%s\n' 'Cannot read /etc/os-release; Debian 13 is required.' >&2
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != debian ] || [ "${VERSION_ID:-}" != 13 ]; then
    printf 'Refusing unsupported host: ID=%s VERSION_ID=%s (need Debian 13).\n' \
        "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
    exit 1
fi

if ! command -v dpkg >/dev/null 2>&1 || [ "$(dpkg --print-architecture)" != amd64 ]; then
    printf '%s\n' 'Refusing unsupported architecture; Debian amd64 is required.' >&2
    exit 1
fi
if ! command -v apt-cache >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' 'apt-cache and apt-get are required.' >&2
    exit 1
fi

# Each capability lists acceptable packages in preference order.
requirements='C/C++ build toolchain|build-essential
Clang compiler|clang
CMake|cmake
Ninja|ninja-build
pkg-config|pkg-config
Rust compiler|rustc
Cargo|cargo
Git|git
Rust formatter|rustfmt
Rust Clippy linter|rust-clippy
Debian package builder|dpkg-dev
debhelper|debhelper
just task runner|just
shell script static analysis|shellcheck
IP routing diagnostics|iproute2
nftables diagnostics|nftables
WireGuard diagnostics|wireguard-tools
Protocol Buffers compiler|protobuf-compiler
SQLite development headers|libsqlite3-dev
OpenSSL development headers|libssl-dev
libmnl development headers|libmnl-dev
libnl core development headers|libnl-3-dev
libnl generic-netlink development headers|libnl-genl-3-dev
libevent development headers|libevent-dev
Linux capability inspection|libcap2-bin
native memory checker|valgrind
JSON acceptance-report tooling|jq
namespace capture tooling|tcpdump
traffic shaping and throughput test tooling|iperf3'
if [ "$with_mptcpd" -eq 1 ]; then
    requirements="${requirements}
optional mptcpd daemon|mptcpd
optional mptcpd plugins|mptcpd-plugins
optional libmptcpd development headers|libmptcpd3-dev libmptcpd-dev"
fi

names=$(printf '%s\n' "$requirements" | awk -F '|' '{print $2}')
# The names are fixed above and intentionally split into individual arguments.
# shellcheck disable=SC2086
if ! policy=$(apt-cache policy $names 2>/dev/null); then
    printf '%s\n' 'Could not read the current apt package policy. No changes were made.' >&2
    exit 1
fi
resolved=$(printf '%s\n' "$policy" | awk -v requirements="$requirements" '
    /^[^[:space:]]+:$/ {
        name = $1
        sub(/:.*/, "", name)
    }
    $1 == "Candidate:" && !(name in versions) { versions[name] = $2 }
    END {
        count = split(requirements, rows, "\n")
        for (i = 1; i <= count; i++) {
            split(rows[i], fields, /[|]/)
            n = split(fields[2], options, " ")
            for (j = 1; j <= n; j++) {
                name = options[j]
                if (versions[name] != "" && versions[name] != "(none)") break
            }
            if (j > n) {
                missing = missing fields[1] ": " fields[2] "\n"
            } else if (!(name in selected)) {
                print name, versions[name]
                selected[name] = 1
            }
        }
        if (missing != "") {
            print "Required package capabilities were not found in the current apt metadata:" > "/dev/stderr"
            printf "%s", missing > "/dev/stderr"
            print "No changes were made. Review Debian 13 sources and update apt metadata yourself, then retry." > "/dev/stderr"
            exit 1
        }
    }
')

printf '%s\n' \
    'VOLPAROSSA Debian 13 development package preview' \
    'No route, DNS, firewall, interface, namespace, sysctl, service role, or VPN setting will be changed.' \
    '' \
    'Resolved apt packages:'

set --
while read -r package_name version; do
    printf '  %-28s candidate %s\n' "$package_name" "$version"
    set -- "$@" "$package_name"
done <<EOF
$resolved
EOF

printf '\nExact install command:\n  apt-get install --no-install-recommends'
printf ' %s' "$@"
printf '\n'

if [ "$print_only" -eq 1 ]; then
    printf '%s\n' 'Print-only mode: no changes made.'
    exit 0
fi

printf '\nInstall these Debian packages? [y/N] '
if ! IFS= read -r answer; then
    printf '\n%s\n' 'No answer received; no changes made.' >&2
    exit 1
fi
case "$answer" in
    y|Y|yes|YES) ;;
    *) printf '%s\n' 'Declined; no changes made.'; exit 0 ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    apt-get install --no-install-recommends "$@"
else
    if ! command -v sudo >/dev/null 2>&1; then
        printf '%s\n' 'sudo is unavailable; re-run as root after reviewing the command.' >&2
        exit 1
    fi
    sudo apt-get install --no-install-recommends "$@"
fi

printf '%s\n' \
    'Package installation completed.' \
    'No VOLPAROSSA network configuration or service role was enabled.'
