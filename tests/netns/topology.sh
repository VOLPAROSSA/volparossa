#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed, fail-closed entry point for the future disposable lifecycle worker.
set -eu

usage() {
    printf '%s\n' \
        'usage:' \
        '  tests/netns/topology.sh --preview' \
        '  tests/netns/topology.sh --run      # blocked until isolated bootstrap exists' \
        '  tests/netns/topology.sh --cleanup  # always refuses unowned standalone cleanup'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA isolated lifecycle plan (no change has been made):' \
        '  capture a privacy-safe digest manifest of host network state' \
        '  enter fixed anonymous network, mount, and PID namespaces' \
        '  mount a private tmpfs at /run inside that sandbox' \
        '  create two run-scoped named namespaces only inside the private /run' \
        '  create both ends of two run-scoped veth pairs only inside the sandbox' \
        '  add exact local routes; do not add a default route' \
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
            'BLOCKED: the fixed process supervisor exists, but isolated namespace bootstrap is not present.' \
            'No namespace, link, route, rule, firewall object, VPN, or sysctl was changed.' >&2
        exit 77
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
