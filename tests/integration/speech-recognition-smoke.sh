#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Debian KVM guest entry point. Installs guest-only package tools, builds Core and
# provisions one pinned CPU model. All recordings are created by the guest fixture.
set -eu
[ "$#" = 1 ] && [ "${#1}" = 40 ] || exit 64
case $1 in *[!0-9a-f]*) exit 64 ;; esac
[ "$(id -un)" = vpci ] && [ "$(hostname)" = volparossa-alpha ] &&
    [ "$(systemd-detect-virt --vm)" = kvm ] && [ "$(pwd -P)" = /home/vpci/source ] || exit 77
umask 077
output=/home/vpci/alpha-output
mkdir "$output"
root=$(mktemp -d /home/vpci/speech-XXXXXXXX)
finish() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$root"
    printf '%s\n' "$status" > "$output/guest-exit-status"
    tar -C "$output" -czf /home/vpci/alpha-output.tar.gz .
    exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
phase() { printf '%s\n' "$1" > "$output/current-phase"; }
phase packages
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    build-essential ca-certificates cmake git pkg-config protobuf-compiler python3-venv bubblewrap util-linux espeak-ng=1.52.0+dfsg-5
phase cli
CARGO_TARGET_DIR=/home/vpci/target cargo build --locked -p volparossa --bin volparossa
phase worker-lifetime
CARGO_TARGET_DIR=/home/vpci/target cargo test --locked -p volparossa --bin volparossa \
    compute::supervise::lifetime::tests::stat_opened_before_reap_reports_only_the_original_lifetime_gone \
    -- --exact > "$root/lifetime-test.log"
grep -F 'test result: ok. 1 passed;' "$root/lifetime-test.log"
phase provision
python3 -B workers/volparossa-ml/provision.py --execute --yes --disposable-guest --root "$root/runtime" \
    --model-profile whisper-small-v1 --budget-bytes 3221225472
phase recognition
python3 -B tests/integration/speech-recognition-smoke.py "$root" "$output" "$1"
phase complete
