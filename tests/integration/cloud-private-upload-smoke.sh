#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicit disposable KVM topology.
# shellcheck disable=SC2154,SC2034

cloud_private_upload_run() {
    # Keep GnuPG's private Unix socket below sockaddr_un's path limit. This is
    # inside the exact disposable WORK tree, never an external /tmp shortcut.
    # WORK is root-owned 0755: the worker cannot rmdir a direct child there.
    # A short private parent lets the same owner remove its complete i tree.
    storage_owner_parent=$WORK/u
    storage_owner_directory=$storage_owner_parent/i
    storage_fixture_driver=cloud-private-upload-smoke.py
    storage_restore_flows=28
    storage_phase_timeout_seconds=2400
    if [ -e "$storage_owner_parent" ] || [ -L "$storage_owner_parent" ]; then
        fail CLOUD_OWNER_PARENT_NOT_NEW
    fi
    longest_cloud_socket=$storage_owner_directory/o/object-0123456789abcdef0123456789abcdef/g-xxxxxxxx/S.gpg-agent
    [ "${#longest_cloud_socket}" -lt 104 ] || fail CLOUD_SOCKET_PATH_TOO_LONG
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_owner_parent"
    [ "$CLOUD_SOURCE" = /opt/volparossa-cloud ] || fail CLOUD_SOURCE_INVALID
    [ "$CLOUD_NODE" = /opt/volparossa-node/bin/node ] || fail CLOUD_NODE_INVALID
    [ "$CLOUD_REVISION" = 311f6070dc8950a75133567a9eff724e975593b6 ] || fail CLOUD_REVISION_INVALID
    if [ ! -f "$CLOUD_SOURCE/provision.json" ] || [ -L "$CLOUD_SOURCE/provision.json" ]; then
        fail CLOUD_PROVISION_MISSING
    fi
    install -o root -g root -m 0600 "$CLOUD_SOURCE/provision.json" "$WORK/cloud-private-upload-provision.json"
    private_storage_fragments_run
    # The worker has proved private cleanup; root removes only the empty parent.
    rmdir "$storage_owner_parent" || fail CLOUD_OWNER_PARENT_CLEANUP_FAILED
}

cloud_private_upload_finalize_report() {
    cloud_status=$1
    optional_json_evidence "$WORK/cloud-private-upload-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$cloud_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-cloud-private-upload",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,cloud:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"Pinned Cloud original Files/Uppy upload through real owner encryption and protected fragments. Authenticated synthetic DAV baseline source stopped; both local ciphertexts removed; service stopped and restarted; provider A offline; two baseline restores and two original UI downloads. Exact retained physical charges, all-copy retirement and joined private service/browser cleanup. No full OpenCloud accounts, sharing, writable synchronization or general server-independent availability proof."}' \
        >"$WORK/cloud-private-upload-smoke.json" || return 1
    cloud_exports=$(python3 -B "$source_directory/tests/integration/cloud-private-upload-smoke.py" export-names) || return 1
    for cloud_name in $cloud_exports; do
        cloud_artifact=$WORK/$cloud_name
        if [ -f "$cloud_artifact" ] && [ ! -L "$cloud_artifact" ]; then
            [ "$(wc -c <"$cloud_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$cloud_artifact" "$output_directory/$cloud_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/cloud-private-upload-smoke.py" report \
        "$WORK/cloud-private-upload-smoke.json" "$expected_commit"
}
