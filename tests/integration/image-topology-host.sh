#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
umask 077

test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_EVENT_NAME" = workflow_dispatch
test "$GITHUB_REPOSITORY" = VOLPAROSSA/volparossa
test "$CORE_CHECKOUT" = "$GITHUB_WORKSPACE/core"
test "$IMAGE_CHECKOUT" = "$GITHUB_WORKSPACE/image"
test "$RUNNER_TEMP" = "$(realpath -e -- "$RUNNER_TEMP")"
owner=$(id -u)
test "$owner" -gt 0
test "$(stat -c %u -- "$RUNNER_TEMP")" = "$owner"
cd -- "$CORE_CHECKOUT"
test "$(pwd -P)" = "$CORE_CHECKOUT"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
test "$(git -C "$IMAGE_CHECKOUT" rev-parse HEAD)" = "$IMAGE_REVISION"
adapter=tests/integration/image-topology-input.py
result="$RUNNER_TEMP/image-topology-result"
receipt="$RUNNER_TEMP/image-topology-receipt.json"

case "${1:-}" in
prepare)
    test "$#" -eq 1
    python3 -B "$adapter" check-source "$IMAGE_CHECKOUT"
    source tests/integration/application-topology-prepare.sh
    prepare_application_topology
    ;;
transport)
    test "$#" -eq 3
    input=$2
    output=$3
    for directory in "$input" "$output"; do
        [[ "$directory" == "$RUNNER_TEMP/"* ]]
        test "$directory" = "$(realpath -e -- "$directory")"
        test -d "$directory"
        test "$(stat -c '%u:%a' -- "$directory")" = "$owner:700"
    done
    test "$input" != "$output"
    test -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)"
    test ! -e "$receipt"
    test ! -L "$receipt"
    python3 -B "$adapter" verify "$input" >/dev/null
    mkdir -m 0700 -- "$result"
    runtime="$CORE_CHECKOUT/native/volparossa-mpquic/build/volparossa-mpquic"
    base="$RUNNER_TEMP/$(jq -er .filename tests/helper/debian13-amd64-image-v1.json)"
    # Only the unprivileged VM driver receives access to KVM. The owner key stays with Image.
    sudo -n -- /usr/bin/setpriv --reuid "$owner" --regid "$(stat -Lc %g /dev/kvm)" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs --reset-env -- \
        "$CORE_CHECKOUT/tests/integration/run-alpha-topology-vm.sh" --execute --yes --scenario image-snapshot \
        --image "$base" --mpquic "$runtime" --output "$result" --expected-commit "$GITHUB_SHA" \
        --image-handoff "$input" --image-return "$output" --image-revision 0da0c35e9372a828553f376c3eb404a6081e0bb8
    pending=$(mktemp -- "$RUNNER_TEMP/.image-transport-receipt-XXXXXXXX")
    trap 'rm -f -- "$pending"' EXIT
    python3 -B "$adapter" host-receipt "$input" "$output" "$result" "$GITHUB_SHA" \
        "$IMAGE_REVISION" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" >"$pending"
    ln -- "$pending" "$receipt"
    ;;
*) exit 64 ;;
esac
