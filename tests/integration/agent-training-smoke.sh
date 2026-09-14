#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Independent CPU training proof, only in the pinned disposable Debian VM.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C
umask 077
mode=preview
approval=no
revision=
scenario=agent-training
plan() {
    printf '%s\n' \
        'VOLPAROSSA isolated public model-training plan:' \
        '  require the disposable Debian 13 KVM guest and unprivileged vpci account;' \
        '  install official guest build tools, python3-venv and bubblewrap; build only the CLI;' \
        '  explicitly provision 38 pinned CPU wheels and eight original model assets in a new 3GiB-budget root;' \
        '  train SmolLM2-135M-Instruct LoRA on source-bound public project Q/A for eight real updates;' \
        '  observe the actual worker namespace/mount isolation without opening host keys;' \
        '  check held-out evaluation, unchanged base, changed adapter, reload and artifact hashes;' \
        '  reap processes, remove only the new guest model/job roots, compare routes/DNS/firewall.' \
        'No development-host install/training, native MPQUIC build, distributed-training or better-answer claim.'
    if [ "$scenario" = agent-owner-priority ]; then
        printf '%s\n' \
            'Owner-priority variant: explicitly enable spare-capacity handling for this actual model job;' \
            '  create bounded CPU contenders only inside this guest, observe validated paused/resumed ACKs;' \
            '  measure the exact paused worker CPU ticks and unchanged model step, then real resumed work;' \
            '  preserve the original 600s deadline and reap all exact owned contenders/model processes;' \
            '  this does not prove all owner activity, battery/thermal policy or owner cancellation.'
    fi
}
while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
        --expected-commit) [ "$#" -ge 2 ] || exit 64; revision=$2; shift ;;
        --scenario) [ "$#" -ge 2 ] || exit 64; scenario=$2; shift
            case $scenario in agent-training|agent-owner-priority) ;; *) exit 64 ;; esac ;;
        *) exit 64 ;;
    esac
    shift
done
if [ "$mode" = preview ]; then
    [ "$approval" = no ] && [ -z "$revision" ] || exit 64
    plan
    printf '%s\n' 'PREVIEW ONLY: no install, model download, training, file or network changes.'
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
[ ! -e /home/vpci/alpha-output ] || exit 77
mkdir -m 0700 /home/vpci/alpha-output
output=/home/vpci/alpha-output
fixture=tests/integration/$scenario-smoke.py
phase=guest-packages
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ ! -f "$output/$scenario-smoke.json" ]; then
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
    build-essential ca-certificates cargo cmake git iproute2 jq nftables pkg-config \
    python3 python3-venv rustc bubblewrap util-linux
phase=cli-build
printf '%s\n' "$phase" >"$output/current-phase"
CARGO_TARGET_DIR=/home/vpci/target cargo build --locked -p volparossa --bin volparossa \
    >/home/vpci/cargo-build.log 2>&1 || {
        tail -c 131072 /home/vpci/cargo-build.log >&2
        exit 1
    }
phase=training
printf '%s\n' "$phase" >"$output/current-phase"
python3 -B "$fixture" execute "$output" "$revision" \
    >"$output/runner.stdout" 2>"$output/runner.stderr"
