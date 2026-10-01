#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicit disposable KVM topology.
# shellcheck disable=SC2154,SC2034

image_snapshot_run() {
    # Keep GnuPG's private Unix socket below sockaddr_un's path limit. This is
    # inside the exact disposable WORK tree, never an external /tmp shortcut.
    storage_owner_directory=$WORK/i
    storage_fixture_driver=image-snapshot-smoke.py
    [ "$IMAGE_SOURCE" = /opt/volparossa-image ] || fail IMAGE_SOURCE_INVALID
    [ "$IMAGE_NODE" = /opt/volparossa-node/bin/node ] || fail IMAGE_NODE_INVALID
    [ "$IMAGE_REVISION" = e177afebabd99ac0773de2a73d60275346a5de52 ] || fail IMAGE_REVISION_INVALID
    if [ ! -f "$IMAGE_SOURCE/provision.json" ] || [ -L "$IMAGE_SOURCE/provision.json" ]; then
        fail IMAGE_PROVISION_MISSING
    fi
    install -o root -g root -m 0600 "$IMAGE_SOURCE/provision.json" "$WORK/image-snapshot-provision.json"
    private_storage_fragments_run
}

image_snapshot_finalize_report() {
    image_status=$1
    optional_json_evidence "$WORK/image-snapshot-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$image_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-image-snapshot",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,image:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"Pinned Image GPG-encrypted synthetic quiesced snapshot through actual Node storage CLI and three protected providers; A offline, two decrypted/hash-verified B/C restores, all-copy deletion and cleanup. No running Immich server, PostgreSQL recovery, mobile sync or serverless availability proof."}' \
        >"$WORK/image-snapshot-smoke.json" || return 1
    image_exports=$(python3 -B "$source_directory/tests/integration/image-snapshot-smoke.py" export-names) || return 1
    for image_name in $image_exports; do
        image_artifact=$WORK/$image_name
        if [ -f "$image_artifact" ] && [ ! -L "$image_artifact" ]; then
            [ "$(wc -c <"$image_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$image_artifact" "$output_directory/$image_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/image-snapshot-smoke.py" report \
        "$WORK/image-snapshot-smoke.json" "$expected_commit"
}
