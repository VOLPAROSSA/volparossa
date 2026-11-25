#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Hosted Core Quality or the protected Studio native-site workflow.
set -euo pipefail
umask 077
test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_EVENT_NAME" = workflow_dispatch
test "$STUDIO_PROOF_MODE" = signed-site-topology
test "$(pwd -P)" = "$GITHUB_WORKSPACE/core"
test "$(git rev-parse HEAD)" = "$STUDIO_CORE_REVISION"
test "$(git -C "$GITHUB_WORKSPACE/studio" rev-parse HEAD)" = "$STUDIO_REVISION"
test "$(git -C "$GITHUB_WORKSPACE/silex" rev-parse HEAD)" = 672efed69dda04c0a1e968859239e042f00d9538
python3 -B tests/integration/studio-topology-input.py check-workflow
test "$RUNNER_TEMP" = "$(realpath "$RUNNER_TEMP")"
test "$(id -u)" -gt 0
test "$(stat -c '%u' -- "$RUNNER_TEMP")" = "$(id -u)"
stage="$RUNNER_TEMP/studio-topology-handoff"
output="$RUNNER_TEMP/studio-topology-result"
case "${1:-}" in
prepare)
    test ! -e "$output"
    test ! -L "$output"
    mkdir -m 0700 "$output"
    source tests/integration/application-topology-prepare.sh
    prepare_application_topology
    ;;
consume)
    receipt="$RUNNER_TEMP/studio-export-receipt.json"
    sha=$(jq -er --arg core "$STUDIO_CORE_REVISION" --arg studio "$STUDIO_REVISION" \
        'select(.status == "passed" and .stage == "complete" and .proof_mode == "signed-site-topology"
            and .STUDIO_CORE_REVISION == $core and .STUDIO_REVISION == $studio and .temporary_outputs_removed == true)
         | .topology_handoff.evidence_sha256 | select(test("^[0-9a-f]{64}$"))' "$receipt")
    if [ "$GITHUB_REPOSITORY" = VOLPAROSSA/volparossa-studio ]; then
        jq -e '.native_export as $native | .signed_site_recovery.bindings as $signed
          | $native.operation == "native_file_hosting_export" and $native.native_reopened == true
          and $native.asset_count == 5 and $native.original_assets_equal == true
          and $native.signing_input == "native_file_hosting" and $native.owner_review_bound_before_signing == true
          and $native.owner_terminal_approved_original_manifest == true
          and ($native.reviewed_bundle_sha256 | test("^[0-9a-f]{64}$"))
          and $native.reviewed_bundle_sha256 == $signed.bundle_sha256' "$receipt" >/dev/null
    fi
    projection="$RUNNER_TEMP/studio-topology-public-input.json"
    test ! -e "$projection"
    test ! -L "$projection"
    python3 -B tests/integration/studio-topology-input.py "$stage" "$sha" "$STUDIO_CORE_REVISION" \
        "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$STUDIO_REVISION" >"$projection"
    sudo -n -- /usr/bin/setpriv --reuid "$(id -u)" --regid "$(stat -Lc '%g' /dev/kvm)" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs --reset-env -- \
        "$(pwd -P)/tests/integration/run-alpha-topology-vm.sh" --execute --yes --scenario content-repair \
        --image "$RUNNER_TEMP/$(jq -er .filename tests/helper/debian13-amd64-image-v1.json)" \
        --mpquic "$(pwd -P)/native/volparossa-mpquic/build/volparossa-mpquic" --output "$output" \
        --expected-commit "$STUDIO_CORE_REVISION" --studio-handoff "$stage" --studio-evidence-sha256 "$sha"
    report="$output/content-repair-smoke.json"
    jq -e --arg rev "$STUDIO_CORE_REVISION" '.source_revision == $rev and .qemu_started and .qemu_joined and .private_guest_state_removed' \
        "$output/studio-vm-cleanup.json" >/dev/null
    python3 -B tests/integration/content-repair-smoke.py report-studio "$report" "$STUDIO_CORE_REVISION"
    if [ "$GITHUB_REPOSITORY" = VOLPAROSSA/volparossa-studio ]; then
        jq -e '.repair.offline_site.viewer | .recipient_browser_reopen.profile_removed == true
          and .recipient_browser_reopen == .recipient_browser' "$report" >/dev/null
    fi
    jq -e --slurpfile producer "$projection" '.repair.offline_site.input == $producer[0]' "$report" >/dev/null
    for phase in before after; do
        test "$(sha256sum "$output/host-state-$phase.json" | cut -d' ' -f1)" = \
            "$(jq -er --arg k "${phase}_sha256" '.host_state[$k]' "$report")"
    done
    ;;
cleanup)
    if [ -e "$stage" ] || [ -L "$stage" ]; then
        test -d "$stage"
        test ! -L "$stage"
        test "$(stat -c '%u:%a' "$stage")" = "$(id -u):700"
        for file in site.vps manifest.bin evidence.json; do
            if [ -e "$stage/$file" ] || [ -L "$stage/$file" ]; then
                test -f "$stage/$file"
                test ! -L "$stage/$file"
                test "$(stat -c '%u' "$stage/$file")" = "$(id -u)"
                rm -- "$stage/$file"
            fi
        done
        rmdir -- "$stage"
    fi
    ;;
*) exit 64 ;;
esac
