#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Test-only preflight, not the full two-Exit C05 acceptance scenario.
set -eu

usage() {
    printf '%s\n' \
        'usage: dns-cache-proof.sh --plan' \
        '       dns-cache-proof.sh --execute --yes --fixture ABSOLUTE_DIR --binary ABSOLUTE_BUILT_EXAMPLE --output NEW_ABSOLUTE_DIR' \
        'Uses only previously collected public DNS data; downloads no binaries or code.' \
        'Creates one disposable user/network namespace; enables only its loopback.' \
        'If user namespaces are denied, explicit VOLPAROSSA_TEST_ALLOW_SUDO_NETNS=1' \
        'permits sudo only to create network/PID namespaces and drop back to the original UID.' \
        'The replay server and validator run with every capability cleared and no-new-privileges.' \
        'Starts bounded loopback TCP1053 replay, executes the unchanged-root Rust collector,' \
        'requires A+AAAA root validation and local cache reuse, then closes the listener.' \
        'Does not change host DNS, routes, firewall, sysctls, interfaces, or root anchors.' \
        'This proves only collector/local-cache behavior; no ordinary Client or peer-cache pass.'
}

fixture='' binary='' output='' execute=no confirmed=no
while [ "$#" -gt 0 ]; do
    case $1 in
        --plan) usage; exit 0 ;;
        --execute) execute=yes; shift ;;
        --yes) confirmed=yes; shift ;;
        --fixture) [ "$#" -ge 2 ] || exit 64; fixture=$2; shift 2 ;;
        --binary) [ "$#" -ge 2 ] || exit 64; binary=$2; shift 2 ;;
        --output) [ "$#" -ge 2 ] || exit 64; output=$2; shift 2 ;;
        *) usage >&2; exit 64 ;;
    esac
done
[ "$execute:$confirmed" = yes:yes ] || { usage >&2; exit 64; }
case $fixture:$binary:$output in /*:/*:/*) ;; *) usage >&2; exit 64 ;; esac
[ -d "$fixture" ] && [ ! -L "$fixture" ] && [ -f "$binary" ] && [ ! -L "$binary" ] \
    && [ -x "$binary" ] && [ ! -e "$output" ] && [ ! -L "$output" ] || exit 64
for dependency in python3 timeout readlink; do
    command -v "$dependency" >/dev/null 2>&1 || exit 69
done
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd -P)
usage
umask 077
mkdir -m 0700 -- "$output"
# The shared runner checks namespace identity and drops privileges before this
# command. A failed test never retries through the explicit CI-only sudo path.
# shellcheck disable=SC2016 # Positional arguments expand only inside the isolated child shell.
timeout --signal=TERM --kill-after=5s 40s \
    "$repository_root/scripts/run-isolated-test.sh" --command /bin/sh dns_cache_builtin_root \
        VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS loopback -eu -c '
        fixture=$1; binary=$2; output=$3; scripts=$4
        server_pid=
        stop_server() {
            if [ -n "$server_pid" ]; then
                kill -TERM "$server_pid" 2>/dev/null || true
                wait "$server_pid" || true
                server_pid=
            fi
        }
        trap stop_server EXIT
        trap "exit 130" INT
        trap "exit 143" TERM
        [ "$(readlink /proc/self/ns/net)" != "$VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS" ]
        python3 -B "$scripts/dns-cache-fixture.py" serve "$fixture" \
            127.0.0.1:1053 "$output/replay.json" "$output/replay-ready.json" \
            --max-seconds 30 >"$output/replay.stdout" 2>"$output/replay.stderr" &
        server_pid=$!
        count=0
        while [ ! -s "$output/replay-ready.json" ] && [ "$count" -lt 100 ]; do
            kill -0 "$server_pid" 2>/dev/null || exit 1
            sleep 0.02
            count=$((count + 1))
        done
        [ -s "$output/replay-ready.json" ]
        "$binary" 127.0.0.1:1053 iana.org >"$output/core.jsonl" 2>"$output/core.stderr"
        kill -TERM "$server_pid"
        wait "$server_pid"
        server_pid=
        python3 -B "$scripts/dns-cache-fixture.py" validate-core "$fixture" "$output"
    ' dns-cache-proof "$fixture" "$binary" "$output" "$script_directory" \
    >"$output/namespace.stdout" 2>"$output/namespace.stderr"
printf '%s\n' 'PASS: bounded real root-chain collector/local-cache preflight only; C05 peer/route acceptance remains pending.'
