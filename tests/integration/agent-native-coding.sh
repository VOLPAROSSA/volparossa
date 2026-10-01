#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Actual source-built native Codex and private core Qwen; disposable guest only.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
umask 077
mode=preview
approval=no
revision=
plan() {
    printf '%s\n' \
        'VOLPAROSSA native Codex/core coding trial plan:' \
        '  execute only as vpci in the disposable Debian 13 KVM guest with at least 6GiB available RAM;' \
        '  install official guest build dependencies and build the exact source CLI with two jobs;' \
        '  verify staged exact Code sources and the source-built Codex runtime, notices and full native prompt;' \
        '  explicitly fetch SHA256-pinned Node24.19 and Qwen3-0.6B assets inside this disposable guest only;' \
        '  start private-serve in a private network namespace with MemoryMax5GiB, swap disabled and a 2700s lifetime;' \
        '  retain unchanged 4GiB worker RSS, 4.5GiB admission and 600s per-request limits;' \
        '  run the actual app-server with owner-approved synthetic read, model-chosen edit and actual unit tests;' \
        '  require four real cleanup-confirmed responses, changed file and independent passing tests;' \
        '  export closed evidence only; never prompts, model text, tool output, credentials or private source;' \
        '  stop the exact service, join owned processes and remove newly created fixture/model/output directories;' \
        '  verify guest routes, DNS and firewall remain unchanged.' \
        'No development-host model/install, OpenAI credentials/fallback, training or general coding-quality claim.'
}
while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
        --expected-commit) [ "$#" -ge 2 ] || exit 64; revision=$2; shift ;;
        *) exit 64 ;;
    esac
    shift
done
if [ "$mode" = preview ]; then
    [ "$approval" = no ] && [ -z "$revision" ] || exit 64
    plan
    printf '%s\n' 'PREVIEW ONLY: no files, model, installation or network changes.'
    exit 0
fi
[ "$approval" = yes ] || exit 64
case $revision in ''|*[!0-9a-f]*) exit 64 ;; esac
[ "${#revision}" -eq 40 ] || exit 64
[ "$(id -un)" = vpci ] && [ "$(id -u)" -ne 0 ] || exit 77
[ "$(hostname)" = volparossa-alpha ] && [ "$(systemd-detect-virt)" = kvm ] || exit 77
# shellcheck source=/dev/null
[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13 ] || exit 77
[ "$(pwd -P)" = /home/vpci/source ] || exit 77
[ ! -e /home/vpci/alpha-output ] && [ ! -L /home/vpci/alpha-output ] || exit 77
mkdir -m 0700 /home/vpci/alpha-output
output=/home/vpci/alpha-output
fixture=tests/integration/agent-native-coding.py
phase=guest-packages
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ ! -f "$output/agent-native-coding-smoke.json" ]; then
        python3 -B "$fixture" failure "$output" "$revision" "$phase"
    fi
    printf '%s\n' "$result" >"$output/guest-exit-status"
    find "$output" -type d -exec chmod 0700 {} +
    find "$output" -type f -exec chmod 0600 {} +
    tar -C "$output" -czf /home/vpci/alpha-output.tar.gz .
    exit "$result"
}
trap finalize EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
plan
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    build-essential ca-certificates cargo cmake git iproute2 nftables pkg-config \
    python3 python3-venv rustc bubblewrap util-linux libssl3t64
phase=cli-build
printf '%s\n' "$phase" >"$output/current-phase"
CARGO_TARGET_DIR=/home/vpci/target CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
    cargo build --locked -p volparossa --bin volparossa >/home/vpci/cargo-build.log 2>&1 || {
        tail -c 131072 /home/vpci/cargo-build.log >&2
        exit 1
    }
phase=native-coding
printf '%s\n' "$phase" >"$output/current-phase"
python3 -B "$fixture" execute "$output" "$revision" --yes \
    >"$output/runner.stdout" 2>"$output/runner.stderr"
python3 -B "$fixture" report "$output/agent-native-coding-smoke.json" "$revision"
