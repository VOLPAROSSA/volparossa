#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit guest provisioning; private Unix IPC, cancellation and one EOS inference.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
umask 077
mode=preview
approval=no
revision=
browser=no
code=no
plan() {
    printf '%s\n' \
        'VOLPAROSSA local-private Q/A plan:' \
        '  run only as vpci inside the disposable Debian 13 KVM guest;' \
        '  install official guest build tools and bubblewrap, then build the CLI;' \
        '  explicitly provision the pinned CPU SmolLM2-360M profile within the existing 3GiB budget;' \
        '  create one mode-0600 synthetic private question/context and a mode-0700 work-parent;' \
        '  require public inference to reject that exact private input before acquiring the runtime;' \
        '  start same-owner private-serve on a new mode-0600 Unix socket, with fixed roots and limits;' \
        '  observe real cancel/disconnect cleanup and global busy rejection before one EOS task;' \
        '  execute that one private task via bounded Unix IPC, with two threads and the original 600s deadline;' \
        '  use a read-only root observer for exact input/model mounts and network-denied namespaces;' \
        '  require real owner ACKs and an EOS answer containing the generated synthetic identifier;' \
        '  verify ephemeral input/report removal at the declared result boundary and unchanged original input;' \
        '  stop the exact service, require socket removal and no private prompts in its diagnostics;' \
        '  export only scenario-allowlisted synthetic proof, never raw private input/report;' \
        '  reap owned processes, remove only the two new guest fixture roots and compare routes/DNS/firewall.' \
        'No host installation/model, public cache, publication, training, peer execution or full-B04 claim.'
    if [ "$browser" = yes ]; then
        printf '%s\n' \
            '  browser variant: download only the exact source-manifest files and SHA256-pinned ESR package inside the guest;' \
            '  extract/stage in a fresh owned guest directory; no system Firefox installation;' \
            '  before model provisioning, require the same isolated empty-profile about:blank startup;' \
            '  retain only that separate startup log (at most 16KiB) with fixed process/listener facts;' \
            '  replace only the final Python Submit with the real ESR sidebar using actual private-serve;' \
            '  observe cleanup at decoded-result-before-panel-render and again after browser completion;' \
            '  export no raw answer, browser profile or private-session log; remove the entire owned browser root;' \
            '  this is not a Firefox 157 source build or native provider-selector proof.'
    elif [ "$code" = yes ]; then
        printf '%s\n' \
            '  code variant: stage exact source-hashed d5802a0 PrivateCompute and pinned Node24.19 within the guest;' \
            '  use the same single 360M model provision with tiny synthetic code; no second model download;' \
            '  execute the Node Unix client in a network-denied namespace and observe cleanup after completion;' \
            '  export closed proof only, not source prompts/raw answer; no Codex, editor or tool-calling claim.'
    else
        printf '%s\n' '  v2 private-task retains its original first-result-frame-byte cleanup check and authorized synthetic answer.'
    fi
}
while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
        --browser) browser=yes ;;
        --code) code=yes ;;
        --expected-commit) [ "$#" -ge 2 ] || exit 64; revision=$2; shift ;;
        *) exit 64 ;;
    esac
    shift
done
[ "$browser:$code" != yes:yes ] || exit 64
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
fixture=tests/integration/agent-private-task-smoke.py
report_name=agent-private-task
execute_action=execute
failure_action=failure
if [ "$browser" = yes ]; then
    report_name=agent-private-browser
    execute_action=execute-browser
    failure_action=failure-browser
fi
if [ "$code" = yes ]; then
    report_name=agent-private-code
    execute_action=execute-code
    failure_action=failure-code
fi
phase=guest-packages
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ ! -f "$output/$report_name-smoke.json" ]; then
        python3 -B "$fixture" "$failure_action" "$output" "$revision" "$phase"
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
if [ "$browser" = yes ]; then
    # Runtime Depends from the exact Debian ESR package; no Firefox is installed on the host
    # or into the guest system. The manifest-bound package is separately verified/extracted.
    phase=guest-browser-dependencies
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        libasound2t64 libatk1.0-0t64 libc6 libcairo-gobject2 libcairo2 libdbus-1-3 \
        libevent-2.1-7t64 libffi8 libfontconfig1 libfreetype6 libgcc-s1 libgdk-pixbuf-2.0-0 \
        libglib2.0-0t64 libgtk-3-0t64 libnspr4 libpango-1.0-0 libstdc++6 libvpx9 libx11-6 \
        libx11-xcb1 libxcb-shm0 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
        libxrandr2 zlib1g fontconfig procps debianutils
fi
phase=cli-build
printf '%s\n' "$phase" >"$output/current-phase"
CARGO_TARGET_DIR=/home/vpci/target cargo build --locked -p volparossa --bin volparossa \
    >/home/vpci/cargo-build.log 2>&1 || {
        tail -c 131072 /home/vpci/cargo-build.log >&2
        exit 1
    }
phase=private-service
printf '%s\n' "$phase" >"$output/current-phase"
python3 -B "$fixture" "$execute_action" "$output" "$revision" \
    >"$output/runner.stdout" 2>"$output/runner.stderr"
