#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Genuine Qwen tool/result component proof, explicitly confined to a disposable guest.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
umask 077
mode=preview
approval=no
revision=
plan() {
    printf '%s\n' \
        'VOLPAROSSA private Qwen conversation plan:' \
        '  execute only as vpci in the disposable Debian 13 KVM guest, with at least 6GiB available RAM;' \
        '  install official guest build dependencies and build the exact source CLI with two jobs;' \
        '  explicitly stage SHA256-pinned Code Node clients, Node24.19 and Qwen3-0.6B CPU assets;' \
        '  run private-serve as vpci in a private network namespace with MemoryMax5GiB and swap disabled;' \
        '  retain the unchanged 4GiB worker RSS and 4.5GiB admission limits; do not force cache reclamation;' \
        '  submit two genuine model turns: one tool proposal and one correlated tool-result continuation;' \
        '  let only the fixture authorize the exact read of synthetic fixture.js, never model commands;' \
        '  observe actual worker namespaces, exact read-only inputs, cleanup and bounded cgroup usage;' \
        '  export only closed proof and host-state snapshots, never source prompts or raw model answers;' \
        '  stop the exact transient service, join child groups, remove only the newly owned fixture root;' \
        '  compare guest routes, DNS and firewall before and after.' \
        'No host model/install, cloud fallback, training, public sharing or full Codex/edit/test/quality claim.'
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
fixture=tests/integration/agent-private-conversation.py
phase=guest-packages
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ ! -f "$output/agent-private-conversation-smoke.json" ]; then
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
    python3 python3-venv rustc bubblewrap util-linux
phase=cli-build
printf '%s\n' "$phase" >"$output/current-phase"
CARGO_TARGET_DIR=/home/vpci/target CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
    cargo build --locked -p volparossa --bin volparossa >/home/vpci/cargo-build.log 2>&1 || {
        tail -c 131072 /home/vpci/cargo-build.log >&2
        exit 1
    }
phase=private-conversation
printf '%s\n' "$phase" >"$output/current-phase"
python3 -B "$fixture" execute "$output" "$revision" --yes \
    >"$output/runner.stdout" 2>"$output/runner.stderr"
python3 -B "$fixture" report "$output/agent-private-conversation-smoke.json" "$revision"
