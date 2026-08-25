#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed, fail-closed entry point for the future disposable lifecycle worker.
set -eu

usage() {
    printf '%s\n' \
        'usage:' \
        '  tests/netns/topology.sh --preview' \
        '  tests/netns/topology.sh --run      # blocked until the namespace-local nftables policy driver exists' \
        '  tests/netns/topology.sh --cleanup  # always refuses unowned standalone cleanup'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA isolated lifecycle plan (no change has been made):' \
        '  capture a privacy-safe digest manifest of host network state' \
        '  enter fixed anonymous network, mount, and PID namespaces' \
        '  make the inherited mount tree recursively private' \
        '  mount bounded private /run and PID-bound private /proc inside that sandbox' \
        '  prove exact RTNL, stable canonical IPv4 forwarding, and zero-table nftables baselines' \
        '  emit one pinned BOOTSTRAP_READY and one canonical affine GO authorization' \
        '  current slice: publish two live nsfs pins and create two fixed veth pairs, each through one atomic RTM_NEWLINK' \
        '  configure four fixed IPv4 /30 addresses, disable IPv6 address generation, and prove all four links active with their exact kernel route side effects' \
        '  install and prove endpoint A 10.241.2.2/32 via 10.241.1.1 and endpoint B 10.241.1.2/32 via 10.241.2.1 as exact main-table static routes' \
        '  delete veth B then A as the sole route-removal mechanism, prove all three namespaces pristine, retire every affine owner, and reverse every private-run object' \
        '  future full topology: retain the roots, pins, veth pairs, addressed links, and exact routes after GO until final teardown' \
        '  install a namespace-local nftables forward chain with policy drop' \
        '  permit only the fixed lifecycle probe between the two test endpoints' \
        '  bind every cleanup decision to the recorded namespace mount inode' \
        '  tear down in reverse order and verify zero owned objects remain' \
        '  capture the same host digest manifest and require an exact match' \
        '  emit BLOCKED lifecycle evidence; no A01-A15 datapath claim is implied' \
        '  never alter host routes, rules, links, DNS, VPN, firewall, or sysctls'
}

case ${1-} in
    --preview)
        [ "$#" -eq 1 ] || { usage >&2; exit 64; }
        print_plan
        exit 0
        ;;
    --cleanup)
        [ "$#" -eq 1 ] || { usage >&2; exit 64; }
        print_plan
        printf '%s\n' \
            'BLOCKED: standalone cleanup has no in-process inode-bound ownership proof.' \
            'No namespace or other network object was inspected or deleted.' >&2
        exit 77
        ;;
    --run)
        [ "$#" -eq 1 ] || {
            printf '%s\n' 'the fixed lifecycle worker never accepts a command or argument' >&2
            usage >&2
            exit 64
        }
        print_plan
        printf '%s\n' \
            'BLOCKED: the Rust runner now proves active fixed links and two exact main-table static endpoint /32 routes, then removes those routes solely by deleting veth B followed by A and proves complete pristine namespace/private-run rollback before exact TERM/EOF/reap. It creates no default route, forwarding change, nftables object, packet, probe, ownership manifest, or topology readiness, and produces no TOPOLOGY_READY, A14, A15, or acceptance evidence; this shell entry point remains non-executing until the namespace-local nftables policy driver exists.' \
            'This invocation created no namespace, link, address, route, rule, firewall object, VPN, or sysctl.' >&2
        exit 77
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
