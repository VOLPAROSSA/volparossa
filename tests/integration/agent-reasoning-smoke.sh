#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit provisioning and exactly one isolated public 1.7B reasoning worker.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C
umask 077
mode=preview
approval=no
revision=
plan() {
    printf '%s\n' \
        'VOLPAROSSA agent-reasoning plan:' \
        '  run only as vpci inside the disposable Debian 13 KVM guest, 4vCPU/8192MiB;' \
        '  install official guest build tools and bubblewrap, then build only the CLI;' \
        '  explicitly provision pinned CPU SmolLM2-1.7B within a 5GiB provisioning budget;' \
        '  run one BF16 inference worker, two threads, unchanged 600s worker deadline;' \
        '  preserve the original 444-byte public routing source and factual question;' \
        '  retain actual raw answer/report, pinned dtype, RSS, sampled CPU and namespaces;' \
        '  keep semantic review pending independently: EOS is not correctness;' \
        '  remove the two new owned guest roots and compare routes/DNS/firewall.' \
        'No host model/install, peer execution, private input, network publication or full-alpha claim.'
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
    printf '%s\n' 'PREVIEW ONLY: no installation, model, file or network changes.'
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
fixture=tests/integration/agent-reasoning-smoke.py
phase=guest-packages
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ ! -f "$output/agent-reasoning-smoke.json" ]; then
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
phase=reasoning
printf '%s\n' "$phase" >"$output/current-phase"
python3 -B "$fixture" execute "$output" "$revision" \
    >"$output/runner.stdout" 2>"$output/runner.stderr"
