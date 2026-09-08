#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Compile only our diagnostic against a previously source-built, recorded SDK.
# No downloads, installs, real interfaces, host routes, or host firewall changes.
set -eu
umask 077
export LC_ALL=C

if [ "$#" -lt 1 ] || [ "$#" -gt 6 ] || [ "$#" -eq 3 ]; then
    printf '%s\n' 'Usage: sh run-warm-failover-probe.sh ABSOLUTE_SDK_ROOT [0|1 [DELAY0_MS DELAY1_MS [PUMP_MS [burst|lowrate]]]]' >&2
    exit 2
fi
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
common=$(git -C "$repository" rev-parse --git-common-dir)
common=$(CDPATH='' cd -- "$common" && pwd -P)
sdk=$(CDPATH='' cd -- "$1" && pwd -P)
case $sdk in "$common"/*) ;; *) printf '%s\n' 'SDK must be inside this repository common Git directory' >&2; exit 2 ;; esac
blocked=${2:-1}
case $blocked in 0|1) ;; *) exit 2 ;; esac
delay0=${3:-0}; delay1=${4:-0}; pump_ms=${5:-1}; mode=${6:-burst}
for delay in "$delay0" "$delay1"; do
    case $delay in ''|*[!0-9]*) exit 2 ;; esac
    [ "${#delay}" -le 2 ] && [ "$delay" -le 50 ] || exit 2
done
case $pump_ms in 1|2|3|4|5|6|7|8|9|10) ;; *) exit 2 ;; esac
case $mode in burst|lowrate) ;; *) exit 2 ;; esac
probe_timeout=140s
if [ "$delay0" -gt 0 ] || [ "$delay1" -gt 0 ]; then probe_timeout=310s; fi
for command_name in cc git jq sha256sum mktemp timeout unshare ip; do
    command -v "$command_name" >/dev/null 2>&1 || exit 2
done
manifest=$sdk/probe-sdk.json
[ -f "$manifest" ] && [ ! -L "$manifest" ] || exit 2
lock=$repository/third_party/upstream.lock.json
lock_hash=$(sha256sum "$lock" | awk '{ print $1 }')
boringssl_commit=$(jq -er '.components[] | select(.name=="boringssl") | .commit' "$lock")
jq -e --arg lock "$lock_hash" --arg commit "$boringssl_commit" '
  .schema_version==1 and .upstream_lock_sha256==$lock and
  .boringssl_commit==$commit and .boringssl_reused==true and
  (.files|keys)==["mqvpn/liblwip_core.a","mqvpn/libmqvpn.a",
    "source/mqvpn/include/libmqvpn.h","xquic/libxquic-static.a"] and
  (.boringssl_files|keys)==["boringssl/libcrypto.a","boringssl/libssl.a",
    "source/boringssl/include/openssl/rand.h","source/boringssl/include/openssl/sha.h"] and
  all(.files[],.boringssl_files[]; test("^[0-9a-f]{64}$"))
' "$manifest" >/dev/null
boringssl=$(jq -er '.boringssl_root' "$manifest")
boringssl=$(CDPATH='' cd -- "$boringssl" && pwd -P)
case $boringssl in "$common"/*) ;; *) exit 2 ;; esac
verify_file() {
    actual_file=$1; expected_hash=$2
    [ -f "$actual_file" ] && [ ! -L "$actual_file" ] || return 1
    actual_hash=$(sha256sum "$actual_file" | awk '{ print $1 }')
    [ "$actual_hash" = "$expected_hash" ]
}
for relative in mqvpn/libmqvpn.a mqvpn/liblwip_core.a xquic/libxquic-static.a source/mqvpn/include/libmqvpn.h; do
    verify_file "$sdk/$relative" "$(jq -er --arg p "$relative" '.files[$p]' "$manifest")"
done
for relative in boringssl/libssl.a boringssl/libcrypto.a source/boringssl/include/openssl/sha.h source/boringssl/include/openssl/rand.h; do
    verify_file "$boringssl/$relative" "$(jq -er --arg p "$relative" '.boringssl_files[$p]' "$manifest")"
done

work=$(mktemp -d "$sdk/probe.XXXXXX")
case $work in "$sdk"/probe.??????) ;; *) exit 2 ;; esac
printf '%s\n' \
    'Plan: compile one source-built diagnostic into the SDK-owned temporary directory;' \
    'create a disposable user/network namespace, bring up only its private loopback;' \
    'use four ephemeral UDP sockets, warm one real two-path session with 4+8+4 MiB;' \
    'discard one path in userspace without closing its FD; close sockets and retire the namespace.' \
    'This is not WireGuard, HTTP/3, host-network, or alpha acceptance evidence.'
printf 'Mode: %s; synthetic one-way delay: %s/%s ms; pump interval: %s ms.\n' "$mode" "$delay0" "$delay1" "$pump_ms"
printf '%s\n' 'Burst transfers another 32 MiB; lowrate instead tests 44-byte uplink datagrams at two per second for 30 s.' \
    'Optional userspace delay is a synthetic diagnostic, not the VM TBF topology or a production scheduler change.'
printf 'Diagnostic artifacts: %s\n' "$work"
cc -std=c11 -O1 -g -Wall -Wextra -Werror \
    -I "$sdk/source/mqvpn/include" -I "$boringssl/source/boringssl/include" \
    "$repository/native/volparossa-mpquic/tests/warm_failover_probe.c" \
    "$sdk/mqvpn/libmqvpn.a" "$sdk/mqvpn/liblwip_core.a" "$sdk/xquic/libxquic-static.a" \
    "$boringssl/boringssl/libssl.a" "$boringssl/boringssl/libcrypto.a" \
    -lm -lstdc++ -ldl -lpthread -o "$work/warm_failover_probe"
sha256sum "$repository/native/volparossa-mpquic/tests/warm_failover_probe.c" \
    "$work/warm_failover_probe" "$manifest" >"$work/source-and-artifact.sha256"
probe_pid=
# shellcheck disable=SC2317 # Invoked by the EXIT trap, including signal exits.
cleanup() {
    if [ -n "$probe_pid" ]; then
        kill -TERM "$probe_pid" 2>/dev/null || true
        wait "$probe_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=3s "$probe_timeout" \
    unshare -Urn sh -c 'ip link set lo up && exec "$@"' sh \
    "$work/warm_failover_probe" "$sdk/source/mqvpn/tests/certs/test.crt" \
    "$sdk/source/mqvpn/tests/certs/test.key" "$blocked" "$delay0" "$delay1" "$pump_ms" "$mode" \
    >"$work/probe.stdout" 2>"$work/probe.stderr" &
probe_pid=$!
status=0
wait "$probe_pid" || status=$?
probe_pid=
# Upstream startup logs may share stdout; the probe emits one bounded JSON line per phase.
sed -n '/^{/p' "$work/probe.stdout" >"$work/probe.ndjson"
cat "$work/probe.ndjson"
cat "$work/probe.stderr" >&2
exit "$status"
