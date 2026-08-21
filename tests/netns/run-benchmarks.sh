#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Safe benchmark dispatcher: report the missing privileged benchmark driver.
set -eu

MODE=PREVIEW
SEEN_MODE=no

usage() {
    printf '%s\n' 'usage: tests/netns/run-benchmarks.sh [--preview|--execute]'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --preview)
            [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }
            MODE=PREVIEW
            SEEN_MODE=yes
            ;;
        --execute)
            [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }
            MODE=EXECUTE
            SEEN_MODE=yes
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown benchmark-runner option: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
    esac
    shift
done

printf '%s\n' \
    'BLOCKED: no reviewed privileged benchmark driver is present.' \
    'No namespace, traffic-control rule, process, interface, route, firewall rule, or sysctl was changed.' >&2

printf '%s\n' '{'
printf '%s\n' '  "schema_version": 1,'
printf '%s\n' '  "report_kind": "benchmark",'
printf '  "requested_mode": "%s",\n' "$MODE"
printf '%s\n' '  "attempted": false,'
printf '%s\n' '  "measurements": ['
first=yes
for measurement_id in \
    B01_SINGLE_RELAY_TCP B02_FOUR_RELAY_MPTCP B03_SINGLE_PATH_QUIC \
    B04_MULTIPATH_QUIC B05_RTT_SPREAD B06_PACKET_LOSS B07_JITTER \
    B08_RELAY_CAPACITY B09_CPU B10_MEMORY B11_CONTEXT_SWITCHES \
    B12_WIREGUARD_OVERHEAD B13_ROUTE_SETUP B14_DHT_DISCOVERY B15_FAILOVER
do
    if [ "$first" = yes ]; then
        first=no
    else
        printf '%s\n' ','
    fi
    printf '    {"id":"%s","result":"SKIPPED","reason":{"code":"BENCHMARK_DRIVER_UNAVAILABLE","message":"The benchmark was not executed."},"metrics":[]}' \
        "$measurement_id"
done
printf '\n%s\n' '  ],'
printf '%s\n' '  "overall": "BLOCKED"'
printf '%s\n' '}'

exit 77
