#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Disposable VOLPAROSSA acceptance underlay for Debian 13.
# Mutation functions deliberately remain unreachable until a reviewed fixed driver exists.
# shellcheck disable=SC2034,SC2317
set -eu
umask 077

PREFIX=vp1
UNDERLAY=${PREFIX}-underlay
NODE_MAP='1 client
2 relay-a
3 relay-b
4 relay-c
5 relay-d
6 relay-backup-a
7 relay-backup-b
8 exit-a
9 exit-b
10 web-server
11 http3-server
12 udp-echo-server
13 bootstrap-a
14 bootstrap-b'
APPROVE=no
MODE=preview
SNAPSHOT_DIRECTORY=
CLEANED=no
TOPOLOGY_STARTED=no
BEFORE_CAPTURED=no

usage() {
    printf '%s\n' 'usage:'
    printf '%s\n' '  tests/netns/topology.sh --preview'
    printf '%s\n' '  tests/netns/topology.sh --cleanup  # ownership-safe refusal'
    printf '%s\n' '  tests/netns/topology.sh --run      # blocked until fixed driver exists'
}

namespace_name() {
    printf '%s-%s' "$PREFIX" "$1"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$1" >&2
        exit 69
    }
}

print_plan() {
    printf '%s\n' 'VOLPAROSSA disposable namespace plan (no change has been made):'
    printf '  create infrastructure namespace: %s\n' "$UNDERLAY"
    printf '%s\n' "$NODE_MAP" | while read -r index node; do
        namespace=$(namespace_name "$node")
        printf '  create %-28s with temporary veth v%02dn/v%02du\n' "$namespace" "$index" "$index"
        printf '    final veth names: %s/eth0 <-> %s/u%02d\n' "$namespace" "$UNDERLAY" "$index"
        printf '    IPv4 node/underlay: 10.240.%s.2/30 <-> 10.240.%s.1/30\n' "$index" "$index"
        printf '    IPv4 default in node: via 10.240.%s.1 dev eth0\n' "$index"
        printf '    IPv6 node/underlay: fd76:1:%s::2/64 <-> fd76:1:%s::1/64\n' "$index" "$index"
        printf '    IPv6 default in node: via fd76:1:%s::1 dev eth0\n' "$index"
    done
    printf '%s\n' '  inside vp1-underlay: set IPv4 and IPv6 forwarding to 1'
    printf '%s\n' '  inside vp1-underlay: nft add table inet volparossa_test'
    printf '%s\n' '  inside vp1-underlay: nft add chain inet volparossa_test forward { type filter hook forward priority 0; policy accept; }'
    printf '%s\n' '  inside vp1-underlay: tc u02 delay 15ms rate 30mbit'
    printf '%s\n' '  inside vp1-underlay: tc u03 delay 35ms rate 20mbit'
    printf '%s\n' '  inside vp1-underlay: tc u04 delay 60ms 5ms loss 1% rate 15mbit'
    printf '%s\n' '  inside vp1-underlay: tc u05 delay 90ms 10ms loss 2% rate 10mbit'
    printf '%s\n' '  inside vp1-underlay: tc u06 delay 45ms rate 12mbit'
    printf '%s\n' '  inside vp1-underlay: tc u07 delay 75ms rate 8mbit'
    printf '%s\n' '  execute only a fixed reviewed repository acceptance driver'
    printf '%s\n' '  cleanup: delete only exact listed namespaces created after collision checks'
    printf '%s\n' '  standalone cleanup is refused because it has no in-process ownership proof'
    printf '%s\n' '  no host namespace, interface, sysctl, route, rule, DNS, VPN, or firewall change is planned'
    printf '%s\n' '  verify: host routes/rules, links, namespaces, WireGuard, MPTCP, sysctls, nftables, and DNS unchanged'
}

known_namespaces() {
    printf '%s\n' "$UNDERLAY"
    printf '%s\n' "$NODE_MAP" | while read -r _index node; do
        namespace_name "$node"
        printf '\n'
    done
}

refuse_collisions() {
    namespace_file=$SNAPSHOT_DIRECTORY/known-namespaces
    known_namespaces >"$namespace_file"
    while read -r namespace; do
        [ -n "$namespace" ] || continue
        if ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null 2>&1; then
            printf 'refusing to reuse existing namespace: %s\n' "$namespace" >&2
            exit 73
        fi
    done <"$namespace_file"
}

host_fingerprint() {
    destination=$1
    {
        printf '%s\n' '[ipv4-routes]'
        ip -j -4 route show table all
        printf '%s\n' '[ipv6-routes]'
        ip -j -6 route show table all
        printf '%s\n' '[ipv4-rules]'
        ip -j -4 rule show
        printf '%s\n' '[ipv6-rules]'
        ip -j -6 rule show
        printf '%s\n' '[links]'
        ip -j -d link show
        printf '%s\n' '[network-namespaces]'
        ip netns list | LC_ALL=C sort
        printf '%s\n' '[nftables-stateless]'
        nft --stateless --json list ruleset
        printf '%s\n' '[wireguard-config-redacted]'
        # `wg ... dump` includes private/preshared keys plus volatile handshakes and byte
        # counters. Never persist those. Keep only stable public configuration needed to prove
        # that this runner did not add/remove interfaces or peers or change allowed prefixes.
        wg show all dump | awk '
            NF == 5 {
                print $1, "<private-key-redacted>", $3, $4, $5
                next
            }
            NF >= 9 {
                print $1, $2, "<preshared-key-redacted>", "<endpoint-volatile>", $5,
                    "<handshake-volatile>", "<rx-volatile>", "<tx-volatile>", $9
            }
        '
        printf '%s\n' '[mptcp-endpoints]'
        ip mptcp endpoint show
        printf '%s\n' '[mptcp-limits]'
        ip mptcp limits show
        printf '%s\n' '[forwarding-sysctls]'
        sysctl -n net.ipv4.ip_forward
        sysctl -n net.ipv6.conf.all.forwarding
        printf '%s\n' '[dns-target]'
        readlink -f /etc/resolv.conf
        printf '%s\n' '[dns-content]'
        sha256sum /etc/resolv.conf
    } >"$destination"
}

require_platform() {
    [ "$(uname -s)" = Linux ] || {
        printf '%s\n' 'network-namespace acceptance requires Linux' >&2
        exit 69
    }
    [ -r /etc/os-release ] || {
        printf '%s\n' 'cannot verify Debian release' >&2
        exit 69
    }
    # The path is fixed distribution-owned metadata.
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID-}" != debian ] || [ "${VERSION_ID-}" != 13 ]; then
        printf '%s\n' 'network-namespace acceptance requires Debian 13' >&2
        exit 69
    fi
}

remove_snapshot() {
    case $SNAPSHOT_DIRECTORY in
        /tmp/volparossa-netns.??????)
            rm -r -- "$SNAPSHOT_DIRECTORY"
            ;;
        *)
            printf 'refusing unsafe temporary cleanup target: %s\n' "$SNAPSHOT_DIRECTORY" >&2
            return 1
            ;;
    esac
    SNAPSHOT_DIRECTORY=
}

cleanup() {
    [ "$CLEANED" = no ] || return 0
    CLEANED=yes
    cleanup_status=0
    set +e
    printf '%s\n' "$NODE_MAP" | while read -r _index node; do
        ip netns del "$(namespace_name "$node")" 2>/dev/null
    done
    ip netns del "$UNDERLAY" 2>/dev/null

    if known_namespaces | while read -r namespace; do
        [ -n "$namespace" ] || continue
        if ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null 2>&1; then
            exit 1
        fi
    done
    then
        :
    else
        cleanup_status=1
    fi
    set -e
    return "$cleanup_status"
}

finalize() {
    original_status=$?
    trap - EXIT HUP INT TERM
    safety_status=0

    if [ "$TOPOLOGY_STARTED" = yes ] && ! cleanup; then
        printf '%s\n' 'SAFETY FAILURE: one or more owned namespaces survived cleanup' >&2
        safety_status=90
    fi

    if [ "$BEFORE_CAPTURED" = yes ]; then
        if ! host_fingerprint "$SNAPSHOT_DIRECTORY/after"; then
            printf '%s\n' 'SAFETY FAILURE: unable to capture post-cleanup host state' >&2
            safety_status=90
        elif ! cmp -s "$SNAPSHOT_DIRECTORY/before" "$SNAPSHOT_DIRECTORY/after"; then
            printf '%s\n' 'SAFETY FAILURE: host routes/rules, links, namespaces, WireGuard, MPTCP, sysctls, DNS, or firewall changed' >&2
            safety_status=90
        fi
    fi

    if [ -n "$SNAPSHOT_DIRECTORY" ]; then
        if [ "$safety_status" -eq 0 ]; then
            if ! remove_snapshot; then
                safety_status=90
            fi
        else
            printf 'before/after evidence retained at %s\n' "$SNAPSHOT_DIRECTORY" >&2
        fi
    fi

    if [ "$safety_status" -ne 0 ]; then
        exit "$safety_status"
    fi
    exit "$original_status"
}

create_node() {
    index=$1
    node=$2
    namespace=$(namespace_name "$node")
    node_link=$(printf 'v%02dn' "$index")
    underlay_link=$(printf 'v%02du' "$index")
    underlay_name=$(printf 'u%02d' "$index")

    ip netns add "$namespace"
    ip link add "$node_link" type veth peer name "$underlay_link"
    ip link set "$node_link" netns "$namespace"
    ip link set "$underlay_link" netns "$UNDERLAY"
    ip -n "$namespace" link set "$node_link" name eth0
    ip -n "$UNDERLAY" link set "$underlay_link" name "$underlay_name"
    ip -n "$namespace" link set lo up
    ip -n "$UNDERLAY" link set "$underlay_name" up
    ip -n "$namespace" link set eth0 up
    ip -n "$namespace" address add "10.240.$index.2/30" dev eth0
    ip -n "$UNDERLAY" address add "10.240.$index.1/30" dev "$underlay_name"
    ip -n "$namespace" -6 address add "fd76:1:$index::2/64" dev eth0 nodad
    ip -n "$UNDERLAY" -6 address add "fd76:1:$index::1/64" dev "$underlay_name" nodad
    ip -n "$namespace" route add default via "10.240.$index.1" dev eth0
    ip -n "$namespace" -6 route add default via "fd76:1:$index::1" dev eth0
}

configure_netem() {
    ip netns exec "$UNDERLAY" tc qdisc replace dev u02 root netem delay 15ms rate 30mbit
    ip netns exec "$UNDERLAY" tc qdisc replace dev u03 root netem delay 35ms rate 20mbit
    ip netns exec "$UNDERLAY" tc qdisc replace dev u04 root netem delay 60ms 5ms loss 1% rate 15mbit
    ip netns exec "$UNDERLAY" tc qdisc replace dev u05 root netem delay 90ms 10ms loss 2% rate 10mbit
    ip netns exec "$UNDERLAY" tc qdisc replace dev u06 root netem delay 45ms rate 12mbit
    ip netns exec "$UNDERLAY" tc qdisc replace dev u07 root netem delay 75ms rate 8mbit
}

create_topology() {
    ip netns add "$UNDERLAY"
    ip -n "$UNDERLAY" link set lo up
    ip netns exec "$UNDERLAY" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "$UNDERLAY" sysctl -q -w net.ipv6.conf.all.forwarding=1
    printf '%s\n' "$NODE_MAP" | while read -r index node; do
        create_node "$index" "$node"
    done
    ip netns exec "$UNDERLAY" nft add table inet volparossa_test
    ip netns exec "$UNDERLAY" nft 'add chain inet volparossa_test forward { type filter hook forward priority 0; policy accept; }'
    configure_netem
}

if [ "${1-}" = --preview ]; then
    [ "$#" -eq 1 ] || { usage >&2; exit 64; }
    print_plan
    exit 0
fi

if [ "${1-}" = --cleanup ]; then
    [ "$#" -eq 1 ] || { usage >&2; exit 64; }
    print_plan
    printf '%s\n' \
        'BLOCKED: standalone cleanup has no in-process ownership proof.' \
        'No namespace was deleted; cleanup runs only in the creating process trap.' >&2
    exit 77
fi

[ "${1-}" = --run ] || { usage >&2; exit 64; }
print_plan
printf '%s\n' \
    'BLOCKED: privileged execution is disabled until a fixed reviewed acceptance driver exists.' \
    'Arbitrary commands are never accepted by this root-capable topology script.' \
    'No network or host state was changed.' >&2
exit 77
