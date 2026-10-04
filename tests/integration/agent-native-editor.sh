#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Actual native editor UI/core trial; nothing executes on the development host.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
umask 077
mode=preview
approval=no
revision=
plan() {
    printf '%s\n' \
        'VOLPAROSSA native editor/core trial plan:' \
        '  require vpci in the disposable Debian 13 KVM guest and at least 7GiB available RAM;' \
        '  install official guest build/editor libraries and build the exact core CLI;' \
        '  verify all staged exact Code, source-built Codex, full prompt, notices and installed-editor files;' \
        '  explicitly fetch pinned Node24.19 and Qwen3-0.6B assets inside this guest only;' \
        '  start private core with 5GiB/no swap, two threads, 600s requests and a 2700s lifetime;' \
        '  start a separate 2GiB/no-swap headless editor/driver cgroup with a 2550s lifetime;' \
        '  isolate editor network/PID/IPC and mount only public runtimes, private fixture and exact core socket;' \
        '  use real keyboard/mouse input, explicit consent and one-shot approvals for actual read/edit/test;' \
        '  independently verify changed bytes and passing tests, then close the editor with Ctrl-Q;' \
        '  join both owned units, remove fixture/model/profile data and verify unchanged guest network state;' \
        '  export only closed evidence, never model text, prompts, commands or private source.' \
        'No host display/IPC, no --no-sandbox, no model/tool substitutes or general coding-quality claim.'
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
    printf '%s\n' 'PREVIEW ONLY: no files, model, editor, installation or network changes.'
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
fixture=tests/integration/agent-native-editor.py
phase=guest-packages
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ ! -f "$output/agent-native-editor-smoke.json" ]; then
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
    python3 python3-venv rustc bubblewrap util-linux libssl3t64 \
    libgtk-3-0t64 libnss3 libnspr4 libatk-bridge2.0-0t64 libasound2t64 \
    libgbm1 libxkbcommon0 libcups2t64 libxdamage1 libxrandr2 fonts-dejavu-core
phase=cli-build
printf '%s\n' "$phase" >"$output/current-phase"
CARGO_TARGET_DIR=/home/vpci/target CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
    cargo build --locked -p volparossa --bin volparossa >/home/vpci/cargo-build.log 2>&1 || {
        tail -c 131072 /home/vpci/cargo-build.log >&2
        exit 1
    }
phase=native-editor
printf '%s\n' "$phase" >"$output/current-phase"
python3 -B "$fixture" execute "$output" "$revision" --yes \
    >"$output/runner.stdout" 2>"$output/runner.stderr"
python3 -B "$fixture" report "$output/agent-native-editor-smoke.json" "$revision"
