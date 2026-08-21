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

packages=''
missing=''

candidate_version() {
    apt-cache policy "$1" 2>/dev/null | awk '/^[[:space:]]*Candidate:/ { print $2; exit }'
}

add_package() {
    purpose=$1
    shift
    selected=''
    for package_name in "$@"; do
        version=$(candidate_version "$package_name")
        if [ -n "$version" ] && [ "$version" != '(none)' ]; then
            selected=$package_name
            break
        fi
    done
    if [ -z "$selected" ]; then
        missing="${missing}${purpose}: $*\n"
        return
    fi
    case " $packages " in
        *" $selected "*) ;;
        *) packages="${packages}${packages:+ }${selected}" ;;
    esac
}

add_package 'C/C++ build toolchain' build-essential
add_package 'Clang compiler' clang
add_package 'CMake' cmake
add_package 'Ninja' ninja-build
add_package 'pkg-config' pkg-config
add_package 'Rust compiler' rustc
add_package 'Cargo' cargo
add_package 'Git' git
add_package 'Rust formatter' rustfmt
add_package 'Rust Clippy linter' rust-clippy
add_package 'Debian package builder' dpkg-dev
add_package 'debhelper' debhelper
add_package 'just task runner' just
add_package 'shell script static analysis' shellcheck
add_package 'IP routing diagnostics' iproute2
add_package 'nftables diagnostics' nftables
add_package 'WireGuard diagnostics' wireguard-tools
add_package 'Protocol Buffers compiler' protobuf-compiler
add_package 'SQLite development headers' libsqlite3-dev
add_package 'OpenSSL development headers' libssl-dev
add_package 'libmnl development headers' libmnl-dev
add_package 'libnl core development headers' libnl-3-dev
add_package 'libnl generic-netlink development headers' libnl-genl-3-dev
add_package 'libevent development headers' libevent-dev
add_package 'Linux capability inspection' libcap2-bin
add_package 'native memory checker' valgrind
add_package 'JSON acceptance-report tooling' jq
add_package 'namespace capture tooling' tcpdump
add_package 'traffic shaping and throughput test tooling' iperf3

if [ "$with_mptcpd" -eq 1 ]; then
    add_package 'optional mptcpd daemon' mptcpd
    add_package 'optional mptcpd plugins' mptcpd-plugins
    add_package 'optional libmptcpd development headers' libmptcpd3-dev libmptcpd-dev
fi

if [ -n "$missing" ]; then
    printf '%s\n' 'Required package capabilities were not found in the current apt metadata:' >&2
    # The text is assembled only from fixed package names above.
    printf '%b' "$missing" >&2
    printf '%s\n' \
        'No changes were made. Review Debian 13 sources and update apt metadata yourself, then retry.' >&2
    exit 1
fi

printf '%s\n' \
    'VOLPAROSSA Debian 13 development package preview' \
    'No route, DNS, firewall, interface, namespace, sysctl, service role, or VPN setting will be changed.' \
    '' \
    'Resolved apt packages:'

for package_name in $packages; do
    printf '  %-28s candidate %s\n' "$package_name" "$(candidate_version "$package_name")"
done

printf '\nExact install command:\n  apt-get install --no-install-recommends'
for package_name in $packages; do
    printf ' %s' "$package_name"
done
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

set --
for package_name in $packages; do
    set -- "$@" "$package_name"
done
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
