#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicit disposable KVM topology; no host operation.
# shellcheck disable=SC2154,SC2034

private_storage_maintenance_run() {
    storage_fixture_driver=private-storage-maintenance-smoke.py
    # Preserve all core exchange/turn deadlines. The fixture includes real daemon
    # ticks, quiet-link cooldown and bounded attempts against stopped provider A.
    storage_phase_timeout_seconds=2400
    ip -n "$CLIENT" -j -d link show cr0 | jq -e 'length == 1 and .[0].linkinfo.info_kind == "veth"
        and (.[0].flags | index("UP")) != null' >/dev/null || fail MAINTENANCE_GUEST_LINK_MISSING
    private_storage_fragments_run
}

private_storage_maintenance_finalize_report() {
    maintenance_status=$1
    optional_json_evidence "$WORK/private-storage-maintenance-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$maintenance_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-storage-maintenance",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,maintenance:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"Explicit owner enrollment and actual core idle turns on guest cr0, protected provider renewal/repair, retained cursor after owner EOF, independent foreground revocation, A-offline conservative accounting, two B/C reconstructions and all-copy deletion. Synthetic opaque data; no encryption, device-diversity, reciprocal credit, contribution resizing or full-alpha proof."}' \
        >"$WORK/private-storage-maintenance-smoke.json" || return 1
    maintenance_exports=$(python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" export-names) || return 1
    for maintenance_name in $maintenance_exports; do
        maintenance_artifact=$WORK/$maintenance_name
        if [ -f "$maintenance_artifact" ] && [ ! -L "$maintenance_artifact" ]; then
            [ "$(wc -c <"$maintenance_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$maintenance_artifact" "$output_directory/$maintenance_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" report \
        "$WORK/private-storage-maintenance-smoke.json" "$expected_commit"
}
