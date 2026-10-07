#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Guest entrypoint for the existing pinned-image 4-vCPU/4-GiB/16-GiB KVM driver.
# This script is not a host installer and never starts a VM itself.
set -eu
export LC_ALL=C
umask 077
revision=${1:-}
stage=${2:-trial}
case $revision in ''|*[!0-9a-f]*) exit 64 ;; esac
[ "${#revision}" -eq 40 ] || exit 64
case $stage in trial|build) ;; *) exit 64 ;; esac
[ "$(id -un)" = vpci ]
[ "$(hostname)" = volparossa-alpha ]
[ "$(systemd-detect-virt)" = kvm ]
# shellcheck source=/dev/null
[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13 ]
[ "$(pwd -P)" = /home/vpci/source ]

tools=/home/vpci/transaction-abci-tools
comet_revision=0880b4d378f347ab16e54ec677ff50d803f37d62
go_version=go1.27.1
go_archive_sha256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
go_license_sha256=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad

if [ "$stage" = build ]; then
    # This stage is called only in a bounded transient guest service. No compiler
    # auto-upgrade, global Go installation, prebuilt Comet or unpinned engine.
    [ ! -e "$tools" ]
    mkdir -m 0755 "$tools"
    mkdir -m 0755 "$tools/bin"
    curl --fail --location --max-redirs 3 --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 120 --max-filesize 70553950 \
        --output "$tools/go.tar.gz" "https://go.dev/dl/$go_version.linux-amd64.tar.gz"
    [ "$(stat -c %s "$tools/go.tar.gz")" -eq 70553950 ]
    printf '%s  %s\n' "$go_archive_sha256" "$tools/go.tar.gz" | sha256sum --check --strict -
    tar --extract --gzip --file "$tools/go.tar.gz" --directory "$tools" --no-same-owner
    printf '%s  %s\n' "$go_license_sha256" "$tools/go/LICENSE" | sha256sum --check --strict -
    cmp "$tools/go/LICENSE" third_party/licenses/go1.27.1-BSD-3-Clause.txt
    [ "$("$tools/go/bin/go" version)" = 'go version go1.27.1 linux/amd64' ]
    # Retain the entire compiler distribution, including LICENSE and PATENTS,
    # in this disposable guest until the VM is destroyed.
    git init --quiet "$tools/comet-source"
    git -C "$tools/comet-source" -c transfer.fsckObjects=true fetch --quiet --depth 1 \
        https://github.com/cometbft/cometbft.git "$comet_revision"
    git -C "$tools/comet-source" checkout --quiet --detach FETCH_HEAD
    [ "$(git -C "$tools/comet-source" rev-parse HEAD)" = "$comet_revision" ]
    (
        cd "$tools/comet-source"
        sha256sum go.mod go.sum >"$tools/module-before.sha256"
        env GOTOOLCHAIN=local GOENV=off GOFLAGS= GOWORK=off GOMAXPROCS=2 CGO_ENABLED=0 \
            GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
            GOPRIVATE= GONOSUMDB= GONOPROXY= \
            GOCACHE="$tools/go-cache" GOMODCACHE="$tools/go-modules" \
            "$tools/go/bin/go" build -mod=readonly -p=2 -trimpath -buildvcs=false \
            -o "$tools/bin/cometbft" ./cmd/cometbft
        sha256sum --check --strict "$tools/module-before.sha256"
        git diff --exit-code -- go.mod go.sum
    )
    CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/home/vpci/target \
        cargo build --locked -p volparossa-transaction-abci --bin volparossa-transaction-abci
    install -m 0755 /home/vpci/target/debug/volparossa-transaction-abci "$tools/bin/volparossa-transaction-abci"
    chmod 0755 "$tools/bin/cometbft"
    python3 -B - "$revision" "$tools" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

revision, root = sys.argv[1], Path(sys.argv[2])
def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
value = {
    'schema': 1,
    'source_commit': revision,
    'comet_source': subprocess.check_output(['git', '-C', str(root / 'comet-source'), 'rev-parse', 'HEAD'], text=True).strip(),
    'compiler': 'go1.27.1',
    'compiler_archive_sha256': digest(root / 'go.tar.gz'),
    'compiler_license_sha256': digest(root / 'go/LICENSE'),
    'go_mod_sha256': digest(root / 'comet-source/go.mod'),
    'go_sum_sha256': digest(root / 'comet-source/go.sum'),
    'comet_sha256': digest(root / 'bin/cometbft'),
    'adapter_sha256': digest(root / 'bin/volparossa-transaction-abci'),
    'source_built_engine': True,
    'compiler_auto_upgrade': False,
}
with (root / 'build-receipt.json').open('x') as output:
    os.chmod(output.name, 0o600)
    json.dump(value, output, sort_keys=True)
    output.write('\n')
PY
    exit 0
fi

printf '%s\n' \
    'Disposable guest only: install build dependencies from signed Debian repositories;' \
    'verify the exact official Go compiler archive/license; source-build exact pinned Comet;' \
    'build the locked Rust adapter; use at most the existing 4 CPU / 4 GiB / 16 GiB VM;' \
    'create five isolated network namespaces, four validators and four private TEST stores;' \
    'test real signed conflicting spends, commit, 3/1 and 2/2 partitions, rejoin and crash/replay;' \
    'remove all owned network objects/processes/keys, compare original guest network state;' \
    'no real financial service, Byzantine equivocation or development-host changes.'
[ ! -e /home/vpci/alpha-output ]
mkdir -m 0700 /home/vpci/alpha-output
output=/home/vpci/alpha-output
phase=packages
build_unit=volparossa-transaction-build
trial_unit=volparossa-transaction-trial
finalize() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    sudo -n systemctl stop "$build_unit.service" "$trial_unit.service" >/dev/null 2>&1
    printf '%s\n' "$result" >"$output/guest-exit-status"
    printf '%s\n' "$phase" >"$output/guest-phase"
    if [ -f "$tools/build-receipt.json" ]; then
        cp "$tools/build-receipt.json" "$output/transaction-abci-build.json"
    fi
    sudo -n chown -R vpci:vpci "$output"
    find "$output" -type d -exec chmod 0700 {} +
    find "$output" -type f -exec chmod 0600 {} +
    tar -C "$output" -czf /home/vpci/alpha-output.tar.gz .
    exit "$result"
}
trap finalize EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

timeout --kill-after=10s 240s sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
timeout --kill-after=10s 240s sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    build-essential ca-certificates cargo curl git iproute2 nftables pkg-config protobuf-compiler python3 rustc util-linux
phase=source-build
# Combined build phase remains bounded even if one dependency fetch hangs. These
# are guest services, not persistent host services. The VM's overall 2400s cap
# remains unchanged; timeout is a failure, never a reason to enlarge resources.
sudo -n systemd-run --quiet --wait --pipe --collect --unit "$build_unit" \
    --uid vpci --gid vpci --working-directory /home/vpci/source \
    --property MemoryMax=3G --property MemorySwapMax=0 --property CPUQuota=200% \
    --property TasksMax=512 --property RuntimeMaxSec=1300 --property TimeoutStopSec=10 \
    --property KillMode=control-group \
    /bin/sh /home/vpci/source/tests/integration/transaction-abci-vm-guest.sh "$revision" build
phase=real-consensus-trial
# Keep logs in the private guest journal, not in exported evidence. Only closed
# receipts are exported; no private keys, signed command payloads or raw stores.
sudo -n systemd-run --quiet --wait --collect --unit "$trial_unit" \
    --working-directory /home/vpci/source \
    --property MemoryMax=2G --property MemorySwapMax=0 --property CPUQuota=200% \
    --property TasksMax=256 --property RuntimeMaxSec=600 --property TimeoutStopSec=20 \
    --property KillMode=control-group \
    /usr/bin/python3 -B /home/vpci/source/tests/integration/transaction-abci-smoke.py \
    --execute --yes --expected-commit "$revision" \
    --comet "$tools/bin/cometbft" --adapter "$tools/bin/volparossa-transaction-abci" \
    --build-receipt "$tools/build-receipt.json" --output "$output"
phase=complete
