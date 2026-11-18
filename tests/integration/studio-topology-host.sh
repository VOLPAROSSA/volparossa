#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Called only by Quality's opt-in joined Studio/production-helper job.
set -euo pipefail
umask 077
test "$GITHUB_ACTIONS" = true && test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_EVENT_NAME" = workflow_dispatch && test "$GITHUB_WORKFLOW" = Quality
test "$STUDIO_PROOF_MODE" = signed-site-topology
test "$STUDIO_CORE_REVISION" = "$GITHUB_SHA" && test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test "$(git -C "$GITHUB_WORKSPACE/studio" rev-parse HEAD)" = "$STUDIO_REVISION"
test "$(git -C "$GITHUB_WORKSPACE/silex" rev-parse HEAD)" = 672efed69dda04c0a1e968859239e042f00d9538
test "$(pwd -P)" = "$GITHUB_WORKSPACE/core" && test "$RUNNER_TEMP" = "$(realpath "$RUNNER_TEMP")"
test "$(id -u)" -gt 0 && test "$(stat -c '%u' -- "$RUNNER_TEMP")" = "$(id -u)"
stage="$RUNNER_TEMP/studio-topology-handoff"
output="$RUNNER_TEMP/studio-topology-result"
case "${1:-}" in
prepare)
    test ! -e "$output" && test ! -L "$output"
    mkdir -m 0700 "$output"
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        build-essential cmake git libevent-dev pkg-config qemu-system-x86 qemu-utils cloud-image-utils openssh-client curl jq util-linux
    test -c /dev/kvm && test "$(stat -Lc '%u' /dev/kvm)" = 0
    kvm_gid=$(stat -Lc '%g' /dev/kvm)
    [[ "$kvm_gid" =~ ^[1-9][0-9]*$ ]] && test "$(getent group "$kvm_gid" | cut -d: -f1)" = kvm
    qemu-system-x86_64 -accel help | grep -Fx kvm

    native/volparossa-mpquic/scripts/fetch-upstream.sh --yes
    VMP_BUILD_JOBS=2 VMP_RUN_TESTS=no native/volparossa-mpquic/scripts/build-upstream.sh
    runtime="$(pwd -P)/native/volparossa-mpquic/build/volparossa-mpquic"
    test -x "$runtime" && test "$("$runtime" --api-version)" = 7
    test "$(stat -Lc '%s' "$runtime")" -le 67108864

    manifest=tests/helper/debian13-amd64-image-v1.json
    printf '%s  %s\n' c535c54e44f724aa05278fe2bfa7bf607ecd285b83f35e136f16b99d1b99392a "$manifest" | sha256sum --check --strict -
    image="$RUNNER_TEMP/$(jq -er .filename "$manifest")"
    test ! -e "$image" && test ! -L "$image"
    curl --fail --show-error --silent --location --connect-timeout 30 --max-time 1200 --max-filesize 2147483648 \
        --max-redirs 3 --proto '=https' --proto-redir '=https' --output "$image" "$(jq -er .url "$manifest")"
    printf '%s  %s\n' "$(jq -er .sha512 "$manifest")" "$image" | sha512sum --check --strict -
    ;;
consume)
    receipt="$RUNNER_TEMP/studio-export-receipt.json"
    sha=$(jq -er --arg core "$STUDIO_CORE_REVISION" --arg studio "$STUDIO_REVISION" \
        'select(.status == "passed" and .stage == "complete" and .proof_mode == "signed-site-topology"
            and .STUDIO_CORE_REVISION == $core and .STUDIO_REVISION == $studio and .temporary_outputs_removed == true)
         | .topology_handoff.evidence_sha256 | select(test("^[0-9a-f]{64}$"))' "$receipt")
    projection="$RUNNER_TEMP/studio-topology-public-input.json"
    test ! -e "$projection" && test ! -L "$projection"
    python3 -B tests/integration/studio-topology-input.py "$stage" "$sha" "$GITHUB_SHA" \
        "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$STUDIO_REVISION" >"$projection"
    sudo -n -- /usr/bin/setpriv --reuid "$(id -u)" --regid "$(stat -Lc '%g' /dev/kvm)" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs --reset-env -- \
        "$(pwd -P)/tests/integration/run-alpha-topology-vm.sh" --execute --yes --scenario content-repair \
        --image "$RUNNER_TEMP/$(jq -er .filename tests/helper/debian13-amd64-image-v1.json)" \
        --mpquic "$(pwd -P)/native/volparossa-mpquic/build/volparossa-mpquic" --output "$output" \
        --expected-commit "$GITHUB_SHA" --studio-handoff "$stage" --studio-evidence-sha256 "$sha"
    report="$output/content-repair-smoke.json"
    jq -e --arg rev "$GITHUB_SHA" '.source_revision == $rev and .qemu_started and .qemu_joined and .private_guest_state_removed' \
        "$output/studio-vm-cleanup.json" >/dev/null
    python3 -B tests/integration/content-repair-smoke.py report "$report" "$GITHUB_SHA"
    jq -e --slurpfile producer "$projection" '.repair.offline_site.input == $producer[0]' "$report" >/dev/null
    for phase in before after; do
        test "$(sha256sum "$output/host-state-$phase.json" | cut -d' ' -f1)" = \
            "$(jq -er --arg k "${phase}_sha256" '.host_state[$k]' "$report")"
    done
    ;;
cleanup)
    if [ -e "$stage" ] || [ -L "$stage" ]; then
        test -d "$stage" && test ! -L "$stage" && test "$(stat -c '%u:%a' "$stage")" = "$(id -u):700"
        for file in site.vps manifest.bin evidence.json; do
            if [ -e "$stage/$file" ] || [ -L "$stage/$file" ]; then
                test -f "$stage/$file" && test ! -L "$stage/$file" && test "$(stat -c '%u' "$stage/$file")" = "$(id -u)"
                rm -- "$stage/$file"
            fi
        done
        rmdir -- "$stage"
    fi
    ;;
*) exit 64 ;;
esac
