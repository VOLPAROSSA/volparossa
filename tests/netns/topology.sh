#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed, fail-closed entry point for the future disposable lifecycle worker.
set -eu

usage() {
    printf '%s\n' \
        'usage:' \
        '  tests/netns/topology.sh --preview' \
        '  tests/netns/topology.sh --run      # blocked until the post-GO Rust topology driver exists' \
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
        '  current slice: create roots and slots, publish and visit two pristine live nsfs pins, then ordinarily unmount B/A and reverse-roll back every private-run object' \
        '  future full topology: retain those roots, slots, and run-scoped named namespaces after GO until final teardown' \
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
            'BLOCKED: the Rust runner proves anonymous namespaces, PID 1, fixed private mounts, exact RTNL, stable canonical IPv4 forwarding, zero nftables tables bracketed by unchanged generation 1, one pinned BOOTSTRAP_READY, canonical GO, descriptor-relative private-run roots and slots, two distinct live run-bound nsfs pins, their full pristine network state, ordinary reverse unmount, exact filesystem rollback, and TERM/EOF/reap. It creates no veth, address, route, nftables object, ownership manifest, or topology readiness and produces no TOPOLOGY_READY, A14, A15, or acceptance evidence; this shell entry point remains non-executing until the post-GO network-topology driver exists.' \
            'This invocation created no namespace, link, route, rule, firewall object, VPN, or sysctl.' >&2
        exit 77
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
