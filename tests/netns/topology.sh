#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed, fail-closed entry point for the future disposable lifecycle worker.
set -eu

usage() {
    printf '%s\n' \
        'usage:' \
        '  tests/netns/topology.sh --preview' \
        '  tests/netns/topology.sh --run      # non-executing; use the dedicated fixed-ICMP gate' \
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
        '  require all three typed rule counters to read exactly packets=0 and bytes=0 before consuming packet authority' \
        '  behind that exact policy, conditionally establish 1 in the disposable parent namespace ip_forward record and retain its exact original 0 or 1 value' \
        '  activate and prove all four links with their exact kernel qdisc and route side effects while the policy remains exact' \
        '  install and prove endpoint A 10.241.2.2/32 via 10.241.1.1 and endpoint B 10.241.1.2/32 via 10.241.2.1 as exact main-table static routes' \
        '  install and prove four exact affine permanent neighbours with zero probes and zero proxy neighbours' \
        '  in endpoint A issue one no-retry 40-byte raw ICMPv4 echo request bound to the full canonical run ID and receive one exact 60-byte reply before the absolute deadline' \
        '  after socket close, require two identical generation-bracketed policy observations at exactly 1/60, 1/60, and 0/0 plus one-RX/one-TX and 74-byte RX/TX telemetry on every veth end' \
        '  remove the neighbours in reverse order, prove exact routed state and unchanged post-echo link telemetry, then reprove the exact counter profile' \
        '  downgrade to counter-agnostic cleanup authority, delete veth B then A, restore the exact original parent ip_forward record, prove the enumerated restored phase under generation 2, delete only its table handle, prove semantic-empty generation 3, then retire lower owners after final reproof' \
        '  treat only that exact forwarding record as restored; other IPv4 devconf state is discarded only when the disposable parent namespace is destroyed' \
        '  keep this shell entry point non-mutating; the dedicated Rust gate executes the integrated fixed-ICMP proof' \
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
            'BLOCKED: the dedicated Rust runner now proves one fixed run-bound ICMPv4 echo request/reply exchange: one no-retry 40-byte request from endpoint A, one exact 60-byte reply, two identical generation-bracketed policy observations at request/reply/drop packets/bytes 1/60, 1/60, and 0/0, and matching one-RX/one-TX plus 74-byte RX/TX telemetry on every veth end. It then removes all four permanent neighbours, preserves the post-echo telemetry, uses counter-agnostic cleanup authority, deletes both veth pairs and the observed policy table, restores the exact parent ip_forward record, proves semantic-empty generation 3, and completes private-run rollback and exact TERM/EOF/reap. This shell entry point deliberately remains non-executing; run the dedicated fixed-ICMP gate for that evidence. Neither path proves packet absence, packet-capture privacy, a general VPN datapath, an ownership manifest, network-topology readiness, TOPOLOGY_READY, forced-crash cleanup, A14, A15, or acceptance evidence.' \
            'This invocation created no namespace, link, address, route, rule, firewall object, VPN, or sysctl.' >&2
        exit 77
        ;;
    *)
        usage >&2
        exit 64
        ;;
esac
