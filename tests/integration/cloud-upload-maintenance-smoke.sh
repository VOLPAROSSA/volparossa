#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additional explicit profile only; never replaces the original consumer run.
# shellcheck disable=SC2154,SC2034

private_cloud_upload_private() {
    STORAGE_PROOF_BASELINE_MS=${provider_baseline_ms:-0} \
      STORAGE_PROOF_ROUTE_POLICY=${upload_route_policy:-} \
      STORAGE_PROOF_UNDERLAY_SHA256=${upload_underlay_sha:-} \
      timeout --signal=TERM --kill-after=30s 2400s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/cloud-upload-maintenance-smoke.py" "$@" --profile-version 6 --network-version 2
}

# The mandatory consumer run has already installed the signed 3x3 control
# underlay. Observe that same immutable matrix; never recreate its removed ac*
# links or overwrite the preceding consumer receipts.
private_cloud_upload_readback() {
    case $1 in before|after) upload_readback_stage=$1 ;; *) return 1 ;; esac
    case $upload_phase in upload|exercise|finish) ;; *) return 1 ;; esac
    storage_consumer_control_snapshot after || return 1
    upload_readback=$WORK/cloud-upload-$upload_phase-control-$upload_readback_stage.json
    [ ! -e "$upload_readback" ] && [ ! -L "$upload_readback" ] || return 1
    jq -cSj '.' "$WORK/consumer-control-after.private" >"$upload_readback" || return 1
    chmod 0600 "$upload_readback" || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" readback "$WORK" "$upload_readback"
}

private_cloud_upload_start_captures() {
    case $upload_phase in upload|exercise|finish) ;; *) return 1 ;; esac
    [ "${cloud_upload_maintenance:-no}" = yes ] && [ "${private_storage_maintenance:-no}" = yes ] \
        && [ -z "$PROVIDER_CONTROL_PID" ] \
        && [ -z "$CONSUMER_CONTROL_0_PID$CONSUMER_CONTROL_1_PID$CONSUMER_CONTROL_2_PID" ] || return 1
    for upload_capture_b in 0 1 2; do
        content_provider_node "relay$upload_capture_b" || return 1
        upload_capture_ns=$provider_ns; upload_capture_ips=$provider_ip
        for upload_capture_provider in relay3 relay4 relay5; do
            content_provider_node "$upload_capture_provider" || return 1
            upload_capture_ips=$upload_capture_ips,$provider_ip
        done
        upload_capture_prefix=cloud-upload-$upload_phase-control-relay$upload_capture_b
        ip netns exec "$upload_capture_ns" python3 "$WORK/bin/privacy-observer.py" \
            content-control "$WORK/$upload_capture_prefix.json" "$WORK/$upload_capture_prefix.ready" \
            --content-providers "--consumer-control=relay$upload_capture_b" \
            "--content-control=$upload_capture_ips" "cc${upload_capture_b}0" "cc${upload_capture_b}1" "cc${upload_capture_b}2" \
            >"$WORK/$upload_capture_prefix.log" 2>&1 &
        upload_capture_pid=$!
        case $upload_capture_b in
            0) CONSUMER_CONTROL_0_PID=$upload_capture_pid ;;
            1) CONSUMER_CONTROL_1_PID=$upload_capture_pid ;;
            2) CONSUMER_CONTROL_2_PID=$upload_capture_pid ;;
        esac
        # Register before readiness: the existing EXIT trap owns all three PIDs.
        wait_observer "$upload_capture_pid" "$WORK/$upload_capture_prefix.ready" || return 1
    done
}

private_cloud_upload_phase_start() {
    storage_phase=cloud-upload-$upload_phase
    private_cloud_upload_readback before || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" layout "$WORK" \
        >"$WORK/private-storage-fragments-$storage_phase-layout.json" || return 1
    upload_route_policy=$(jq -c '.route_policy' "$WORK/private-storage-fragments-$storage_phase-layout.json") || return 1
    upload_underlay_sha=$(jq -er '.control_underlay_sha256' "$WORK/private-storage-fragments-$storage_phase-layout.json") || return 1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || return 1
    start_privacy_observers "private-storage-fragments-$storage_phase-privacy" || return 1
    private_cloud_upload_start_captures
}

private_cloud_upload_phase_finish() {
    benchmark_capture_paths "private-storage-fragments-$storage_phase-live" mptcp || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" route-check "$WORK" \
        "$WORK/private-storage-fragments-$storage_phase-live-selection.json" \
        "$storage_user/flow-$storage_phase.json" || return 1
    private_cloud_upload_readback after || return 1
    upload_network_status=0
    stop_privacy_observers || upload_network_status=1
    storage_consumer_stop_captures || upload_network_status=1
    [ "$upload_network_status" -eq 0 ] || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" gates "$WORK" \
        "$storage_user/flow-$storage_phase.json" "$provider_baseline_ms" "$1" \
        >"$WORK/private-storage-fragments-$storage_phase-gates.json"
}

private_cloud_upload_phase() {
    case $1 in upload|exercise|finish) ;; *) fail CLOUD_UPLOAD_PHASE_INVALID ;; esac
    upload_phase=$1
    upload_minimum=$(private_cloud_upload_private flow-minimum "$upload_phase" "$upload_user") \
        || fail CLOUD_UPLOAD_FLOW_MINIMUM_INVALID
    case $upload_minimum in ''|*[!0-9]*) fail CLOUD_UPLOAD_FLOW_MINIMUM_INVALID ;; esac
    PHASE=cloud-upload-$upload_phase
    private_cloud_upload_phase_start || fail CLOUD_UPLOAD_NETWORK_START_FAILED
    private_cloud_upload_private "$upload_phase" "$upload_user" \
        "$WORK/runtime-exit/control/agent.sock" "$storage_user" \
        >"$WORK/cloud-upload-$upload_phase.json" || fail CLOUD_UPLOAD_APPLICATION_FAILED
    private_cloud_upload_phase_finish "$upload_minimum" || fail CLOUD_UPLOAD_NETWORK_FINISH_FAILED
}

private_cloud_upload_cleanup() {
    [ "${upload_private_cleanup_complete:-no}" != yes ] || return 0
    [ -n "${upload_user:-}" ] || return 0
    private_cloud_upload_private cleanup "$upload_user" \
        >"$WORK/cloud-upload-private-cleanup.json" || return 1
    rmdir "$WORK/u" || return 1
    upload_private_cleanup_complete=yes
}

private_cloud_upload_run() {
    if [ "${private_storage_maintenance:-no}" != yes ] || [ "${cloud_upload_maintenance:-no}" != yes ]; then
        fail CLOUD_UPLOAD_PROFILE_INVALID
    fi
    [ "${consumer_private_cleanup_complete:-no}" = yes ] || fail CLOUD_UPLOAD_PRIOR_CONSUMER_NOT_JOINED
    # Validate the unchanged mandatory prior profile first. The final joined
    # evidence builder additionally reconstructs it from all original raw files.
    python3 -B "$source_directory/tests/integration/storage-consumer-maintenance-evidence.py" \
        check "$WORK/storage-consumer-evidence.json" || fail CLOUD_UPLOAD_PRIOR_CONSUMER_INVALID
    jq -e '.schema_version == 10' "$WORK/storage-consumer-evidence.json" >/dev/null \
        || fail CLOUD_UPLOAD_PRIOR_CONSUMER_PROFILE_INVALID
    jq -e 'length == 3 and all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})' \
        "$WORK/private-storage-fragments-consumer_deleted_usage.json" >/dev/null \
        || fail CLOUD_UPLOAD_INITIAL_STORE_NOT_EMPTY
    if [ -e "$WORK/u" ] || [ -L "$WORK/u" ]; then fail CLOUD_UPLOAD_OWNER_PARENT_NOT_NEW; fi
    upload_user=$WORK/u/a
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/u" "$upload_user"
    upload_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $upload_client_pid in ''|0|*[!0-9]*) fail CLOUD_UPLOAD_CLIENT_PID_INVALID ;; esac
    nsenter --target "$upload_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CLOUD_UPLOAD_POSITIVE_ISOLATION_FAILED
    for upload_private in "$upload_user" "$WORK/state-relay4/private-store" \
        "$WORK/state-relay5/private-store" "$WORK/state-relay3/private-store"; do
        if nsenter --target "$upload_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$upload_private"; then fail CLOUD_UPLOAD_LOCAL_SHORTCUT; fi
    done
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" \
        '{user_uid:$user,agent_uid:$agent,agent_mount_positive_control:true,
        client_cannot_read_new_owner_root:true,client_cannot_read_any_provider_store:true}' \
        >"$WORK/cloud-upload-isolation.json"
    if [ ! -f /opt/volparossa-cloud-upload-proof/provision.json ] \
        || [ -L /opt/volparossa-cloud-upload-proof/provision.json ]; then
        fail CLOUD_UPLOAD_PROVISION_MISSING
    fi
    install -o root -g root -m 0600 /opt/volparossa-cloud-upload-proof/provision.json \
        "$WORK/cloud-upload-provision.json"

    private_storage_fragments_reopen relay4 relay5 relay3
    PHASE=cloud-upload-prepare
    private_cloud_upload_private prepare "$upload_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-relay4/control/agent.sock" \
        "$WORK/runtime-relay5/control/agent.sock" "$WORK/runtime-relay3/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/cloud-upload-prepare.json" || fail CLOUD_UPLOAD_PREPARE_FAILED
    private_cloud_upload_phase upload
    private_storage_fragments_usage cloud_upload_uploaded_usage

    # The joined upload receipt measures completed early A migrations. Only
    # remaining original A copies count as new repair after this withdrawal.
    private_storage_fragments_reopen relay5 relay3
    content_custody_cli relay4 content status | jq -e '.serving == false' >/dev/null \
        || fail CLOUD_UPLOAD_SOURCE_STILL_SERVING
    for upload_node in relay5 relay3; do
        content_custody_cli "$upload_node" content status | jq -e '.serving == true' >/dev/null \
            || fail CLOUD_UPLOAD_SURVIVOR_NOT_SERVING
    done
    private_cloud_upload_phase exercise
    private_storage_fragments_usage cloud_upload_restored_usage

    private_storage_fragments_reopen relay4 relay5 relay3
    private_cloud_upload_phase finish
    private_storage_fragments_usage cloud_upload_deleted_usage
    jq -e 'length == 3 and all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})' \
        "$WORK/private-storage-fragments-cloud_upload_deleted_usage.json" >/dev/null \
        || fail CLOUD_UPLOAD_PROVIDER_CLEANUP_INCOMPLETE
    jq -n '{first_provider_stopped_after_measured_upload_baseline:true,
        first_provider_stopped_before_new_repair_and_reads:true,first_store_retained:true,
        other_two_providers_serving:true,same_three_stores_reopened:true,
        all_usage_snapshots_with_services_stopped:true,all_three_store_inodes_preserved:true}' \
        >"$WORK/cloud-upload-withdrawal.json"
    private_cloud_upload_cleanup || fail CLOUD_UPLOAD_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" \
        evidence-v8 "$WORK" "$WORK/cloud-upload-evidence.json" || fail CLOUD_UPLOAD_EVIDENCE_INVALID
}

private_cloud_upload_finalize_report() {
    upload_final_status=$1
    python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" finalize-report-v8 \
        "$WORK" "$expected_commit" "$RUN_ID" "$PHASE" "$upload_final_status" "$CLEANUP_COMPLETE" \
        "$REMAINING_OWNED_OBJECTS" "$OBSERVED_BLOCKER" "$WORK/cloud-upload-maintenance-smoke.json" || return 1
    upload_exports=$(python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" export-names-v8) || return 1
    for upload_name in $upload_exports; do
        upload_artifact=$WORK/$upload_name
        if [ -f "$upload_artifact" ] && [ ! -L "$upload_artifact" ]; then
            upload_export_limit=1048576
            upload_export_size=$(wc -c <"$upload_artifact") || return 1
            if [ "$upload_name" = cloud-upload-evidence.json ] \
                && [ "$upload_export_size" -le 2097152 ] \
                && jq -e '(.schema_version == 3 or .schema_version == 4 or .schema_version == 5 or .schema_version == 6 or .schema_version == 7 or .schema_version == 8) and .kind == "cloud-upload-maintenance-evidence"' "$upload_artifact" >/dev/null; then
                upload_export_limit=2097152
            fi
            [ "$upload_export_size" -le "$upload_export_limit" ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$upload_artifact" "$output_directory/$upload_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/cloud-upload-maintenance-evidence.py" check-report-v8 \
        "$WORK/cloud-upload-maintenance-smoke.json" "$expected_commit"
}
