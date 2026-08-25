#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed, fail-closed entry point for the future disposable lifecycle worker.
set -eu

usage() {
    printf '%s\n' \
        'usage:' \
        '  tests/netns/topology.sh --preview' \
        '  tests/netns/topology.sh --run      # blocked until packet-level policy proof exists' \
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
        '  configure four fixed IPv4 /30 addresses, disable IPv6 address generation, and prove the all-NONE barrier while all four links remain down' \
        '  atomically install and prove the run-bound generation-2 parent FORWARD drop policy with exactly two ordered ICMP allow rules, each counter directly before accept, followed by one unconditional counter directly before drop' \
        '  require all three typed rule counters to read exactly packets=0 and bytes=0 in every fresh complete policy observation' \
        '  behind that exact policy, conditionally establish 1 in the disposable parent namespace ip_forward record and retain its exact original 0 or 1 value' \
        '  activate and prove all four links with their exact kernel qdisc and route side effects while the policy remains exact' \
        '  install and prove endpoint A 10.241.2.2/32 via 10.241.1.1 and endpoint B 10.241.1.2/32 via 10.241.2.1 as exact main-table static routes' \
        '  retain and reprove that policy while deleting veth B then A, restore the exact original parent ip_forward record, prove the enumerated restored phase under generation 2, delete only its table handle, prove semantic-empty generation 3, then retire lower owners after final reproof' \
        '  treat only that exact forwarding record as restored; other IPv4 devconf state is discarded only when the disposable parent namespace is destroyed' \
        '  future full topology: send the fixed lifecycle probe and prove the exact policy behaviour before final teardown' \
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
            'BLOCKED: the Rust runner now installs and proves the sole exact generation-2 parent FORWARD policy before link activation: two ordered ICMP allow rules each place one inline counter directly before accept, followed by one unconditional inline counter directly before drop, and every fresh complete policy observation requires all three typed counters to be exactly packets=0 and bytes=0. It conditionally establishes IPv4 forwarding only in its disposable parent network namespace, retains that exact zero-counter policy through the two endpoint routes, installs exactly four affine NUD_PERMANENT IPv4 neighbours in canonical parent A/B then endpoint A/B order, and semantically proves exactly those records with zero probes and zero proxy neighbours while excluding only validated volatile NDA_CACHEINFO telemetry. Before veth B/A deletion it explicitly removes the neighbours in reverse endpoint B/A then parent B/A order, proves the exact routed state restored, and re-proves the zero-counter policy. It then restores the exact original ip_forward record, proves the enumerated restored phase, deletes only the observed table handle, proves semantic-empty generation 3, and completes private-run rollback before exact TERM/EOF/reap. An original 0 requires one bounded enable write and one restore write; an original 1 takes the no-write path. The outer host setting remains unchanged; other IPv4 devconf state is outside the record proof and is discarded only when the disposable namespace is destroyed. This creates no packet, packet-absence, counter-stability, probe, ownership manifest, datapath, or topology readiness evidence; the shell entry point remains non-executing until packet-level policy proof exists and produces no TOPOLOGY_READY, A14, A15, or acceptance evidence.' \
            'This invocation created no namespace, link, address, route, rule, firewall object, VPN, or sysctl.' >&2
        exit 77
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
