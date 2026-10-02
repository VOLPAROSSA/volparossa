#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the approved disposable KVM topology. No host operation.
# shellcheck disable=SC2154,SC2034

private_storage_fragments_private() {
    # One phase may perform two restores, each trying stopped A twice. This
    # fixture-only bound does not widen core exchange deadlines or leases.
    timeout --signal=TERM --kill-after=5s "${storage_phase_timeout_seconds:-1500}s" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/${storage_fixture_driver:-private-storage-fragments-smoke.py}" "$@"
}

private_storage_fragments_cleanup() {
    [ -f "$WORK/bin/private-storage-fragments-smoke.py" ] || return 0
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    private_storage_fragments_private cleanup "${storage_owner_directory:-$WORK/client-fixtures/private-storage-user}" \
        >"$WORK/private-storage-fragments-private_cleanup.json"
}

private_storage_fragments_phase_start() {
    storage_phase=$1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail FRAGMENTS_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers "private-storage-fragments-$storage_phase-privacy" || fail FRAGMENTS_CAPTURE_UNAVAILABLE
    content_provider_adaptive_start_control_observer "content-provider-adaptive-private-storage-fragments-$storage_phase-control" \
        || fail FRAGMENTS_CONTROL_CAPTURE_UNAVAILABLE
}

private_storage_fragments_phase_finish() {
    storage_expected_flows=$1
    benchmark_capture_paths "private-storage-fragments-$storage_phase-live" mptcp || fail FRAGMENTS_ROUTE_UNAVAILABLE
    jq -e --arg context "$storage_context" '.route_context_id == $context' \
        "$WORK/private-storage-fragments-$storage_phase-live-selection.json" >/dev/null || fail FRAGMENTS_ROUTE_CHANGED
    stop_privacy_observers || fail FRAGMENTS_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail FRAGMENTS_CONTROL_CAPTURE_INCOMPLETE
    storage_poll=0
    while [ "$storage_poll" -lt 50 ]; do
        # The shared diagnostic snapshot requests only the newest 400 records.
        # This phase performs 56 exchanges plus their other lifecycle events:
        # count the complete existing 1000-record ring, never a cropped tail.
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-exit/control/agent.sock" \
            logs --limit 1000 >"$WORK/private-storage-fragments-exit-log-window.txt" \
            || fail FRAGMENTS_EXIT_LOG_UNAVAILABLE
        python3 -B "$WORK/bin/private-storage-fragments-smoke.py" flow-gates \
            "$WORK/private-storage-fragments-exit-log-window.txt" "$provider_baseline_ms" \
            >"$WORK/private-storage-fragments-$storage_phase-gates.json" || fail FRAGMENTS_EXIT_LOG_INVALID
        jq -e '.exit_log_window_covers_baseline == true' \
            "$WORK/private-storage-fragments-$storage_phase-gates.json" >/dev/null \
            || fail FRAGMENTS_EXIT_LOG_WINDOW_TRUNCATED
        storage_flows=$(jq -er '.exit_mptcp_tls_completed' \
            "$WORK/private-storage-fragments-$storage_phase-gates.json") || fail FRAGMENTS_EXIT_LOG_INVALID
        [ "$storage_flows" -lt "$storage_expected_flows" ] || break
        sleep 0.1
        storage_poll=$((storage_poll + 1))
    done
    [ "$storage_flows" -ge "$storage_expected_flows" ] || fail FRAGMENTS_PROTECTED_FLOW_INCOMPLETE
}

private_storage_fragments_usage() {
    storage_usage_label=$1
    # The real store owns an exclusive lock. Inspect only after its service has
    # stopped; no direct SQLite reads or fabricated counters while it is live.
    for storage_node in relay4 relay5 relay3; do
        private_storage_fragments_stop "$storage_node"
        private_storage_replicas_usage "$storage_node" | jq -e '{reserved_bytes,committed_bytes,leases}' \
            >"$WORK/private-storage-fragments-usage-$storage_node.json" || fail FRAGMENTS_USAGE_FAILED
    done
    jq -s '.' "$WORK/private-storage-fragments-usage-relay4.json" \
        "$WORK/private-storage-fragments-usage-relay5.json" "$WORK/private-storage-fragments-usage-relay3.json" \
        >"$WORK/private-storage-fragments-$storage_usage_label.json" || fail FRAGMENTS_USAGE_FAILED
}

private_storage_fragments_reopen() {
    for storage_reopen_node in "$@"; do
        private_storage_replicas_serve "$storage_reopen_node" yes || fail FRAGMENTS_REOPEN_FAILED
        case $storage_reopen_node in
            relay4) storage_expected_inode=$storage_store_a ;;
            relay5) storage_expected_inode=$storage_store_b ;;
            relay3) storage_expected_inode=$storage_store_c ;;
            *) fail FRAGMENTS_REOPEN_NODE_INVALID ;;
        esac
        [ "$storage_expected_inode" = "$(stat -Lc '%d:%i' "$WORK/state-$storage_reopen_node/private-store")" ] \
            || fail FRAGMENTS_OWNED_STORE_REPLACED
    done
}

private_storage_fragments_stop() {
    storage_stop_node=$1
    content_custody_cli "$storage_stop_node" content stop >/dev/null || fail FRAGMENTS_STOP_FAILED
    content_custody_cli "$storage_stop_node" content status | jq -e '.serving == false' >/dev/null \
        || fail FRAGMENTS_PROVIDER_STILL_SERVING
}

private_storage_fragments_setup() {
    PHASE=private-storage-fragments-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail FRAGMENTS_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail FRAGMENTS_CONTROL_GROUP_INVALID
    storage_user=${storage_owner_directory:-$WORK/client-fixtures/private-storage-user}
    if [ -e "$storage_user" ] || [ -L "$storage_user" ]; then fail FRAGMENTS_USER_NOT_NEW; fi
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_user"
    benchmark_select_route private-storage-fragments mptcp || fail FRAGMENTS_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/private-storage-fragments-selection.json" || fail FRAGMENTS_ROUTE_INVALID
    storage_context=$(jq -er '.route_context_id' "$WORK/private-storage-fragments-selection.json")
    provider_control_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || fail FRAGMENTS_CONTROL_UNAVAILABLE
    jq -e --arg peer "$provider_control_peer" '[.relay0,.relay1,.relay2] | index($peer) != null' \
        "$WORK/a01-expected-peers.json" >/dev/null || fail FRAGMENTS_CONTROL_NOT_ROUTE_DISTINCT
    # Reuse the custody topology's existing restricted QUIC-only control links.
    # No new application endpoint, Internet egress or direct Client/provider path.
    content_provider_adaptive_control_underlay "$provider_control_peer" || fail FRAGMENTS_CONTROL_UNDERLAY_FAILED
    storage_key_a=$(private_storage_replicas_key relay4) || fail FRAGMENTS_PROVIDER_KEY_FAILED
    storage_key_b=$(private_storage_replicas_key relay5) || fail FRAGMENTS_PROVIDER_KEY_FAILED
    storage_key_c=$(private_storage_replicas_key relay3) || fail FRAGMENTS_PROVIDER_KEY_FAILED
    if [ "$storage_key_a" = "$storage_key_b" ] || [ "$storage_key_a" = "$storage_key_c" ] \
        || [ "$storage_key_b" = "$storage_key_c" ]; then fail FRAGMENTS_PROVIDER_KEYS_EQUAL; fi
    storage_namespaces=
    for storage_node in relay4 relay5 relay3; do
        private_storage_replicas_serve "$storage_node" no || fail FRAGMENTS_SERVE_FAILED
        storage_key=$(private_storage_replicas_key "$storage_node") || fail FRAGMENTS_PROVIDER_KEY_FAILED
        storage_peer=$(jq -er --arg node "$storage_node" '.[$node]' "$WORK/a01-expected-peers.json")
        python3 -B - "$source_directory/tests/integration/content-custody-smoke.py" "$storage_peer" "$storage_key" <<'PY' \
            || fail FRAGMENTS_PROVIDER_IDENTITY_MISMATCH
import runpy, sys
assert runpy.run_path(sys.argv[1])["peer_key"](sys.argv[2]) == sys.argv[3]
PY
        content_provider_node "$storage_node" || fail FRAGMENTS_NAMESPACE_INVALID
        storage_namespace=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail FRAGMENTS_NAMESPACE_INVALID
        case " $storage_namespaces " in *" $storage_namespace "*) fail FRAGMENTS_NAMESPACES_EQUAL ;; esac
        storage_namespaces="$storage_namespaces $storage_namespace"
    done
    storage_store_a=$(stat -Lc '%d:%i' "$WORK/state-relay4/private-store") || fail FRAGMENTS_STORE_IDENTITY_FAILED
    storage_store_b=$(stat -Lc '%d:%i' "$WORK/state-relay5/private-store") || fail FRAGMENTS_STORE_IDENTITY_FAILED
    storage_store_c=$(stat -Lc '%d:%i' "$WORK/state-relay3/private-store") || fail FRAGMENTS_STORE_IDENTITY_FAILED
    private_storage_fragments_private prepare "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-relay4/control/agent.sock" \
        "$WORK/runtime-relay5/control/agent.sock" "$WORK/runtime-relay3/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-fragments-prepare.json" || fail FRAGMENTS_OWNER_PREPARE_FAILED
    storage_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $storage_client_pid in ''|0|*[!0-9]*) fail FRAGMENTS_CLIENT_PID_INVALID ;; esac
    nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail FRAGMENTS_POSITIVE_ISOLATION_FAILED
    for storage_private in "$storage_user" "$WORK/state-relay4/private-store" \
        "$WORK/state-relay5/private-store" "$WORK/state-relay3/private-store"; do
        if nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$storage_private"; then fail FRAGMENTS_LOCAL_SHORTCUT; fi
    done
    jq -n --arg control "$provider_control_peer" --arg context "$storage_context" \
        '{provider_nodes:["relay4","relay5","relay3"],control_relay_peer_id:$control,route_context_id:$context}' \
        >"$WORK/private-storage-fragments-layout.json"
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$group,
        agent_cannot_read_user_state:true,client_cannot_read_any_provider_store:true,agent_mount_positive_control:true,
        all_provider_keys_match_independent_fixture_peers:true,three_provider_namespaces_distinct:true}' \
        >"$WORK/private-storage-fragments-isolation.json"
}

private_storage_fragments_run() {
    private_storage_fragments_setup
    PHASE=private-storage-fragments-upload
    private_storage_fragments_phase_start upload
    private_storage_fragments_private upload "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-fragments-upload.json" || fail FRAGMENTS_UPLOAD_FAILED
    private_storage_fragments_phase_finish 56
    private_storage_fragments_usage uploaded_usage

    PHASE=private-storage-fragments-withdrawal
    # A remains stopped with its original store intact; only B/C serve restores.
    private_storage_fragments_reopen relay5 relay3
    content_custody_cli relay4 content status | jq -e '.serving == false' >/dev/null \
        || fail FRAGMENTS_FIRST_PROVIDER_STILL_SERVING
    for storage_node in relay5 relay3; do
        content_custody_cli "$storage_node" content status | jq -e '.serving == true' >/dev/null \
            || fail FRAGMENTS_SURVIVOR_NOT_SERVING
    done
    PHASE=private-storage-fragments-restore
    private_storage_fragments_phase_start restore
    private_storage_fragments_private restore "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-fragments-restore.json" || fail FRAGMENTS_SURVIVOR_RESTORE_FAILED
    private_storage_fragments_phase_finish "${storage_restore_flows:-16}"
    private_storage_fragments_usage restored_usage
    private_storage_fragments_reopen relay4 relay5 relay3
    jq -n '{first_provider_stopped_before_restore:true,first_store_retained:true,other_two_providers_serving:true,
        same_three_stores_reopened:true,all_usage_snapshots_with_services_stopped:true,
        all_three_store_inodes_preserved:true,agent_restart_claimed:false}' >"$WORK/private-storage-fragments-withdrawal.json"

    PHASE=private-storage-fragments-finish
    private_storage_fragments_phase_start finish
    private_storage_fragments_private finish "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-fragments-finish.json" || fail FRAGMENTS_FINISH_FAILED
    private_storage_fragments_phase_finish 16
    private_storage_fragments_usage deleted_usage
    benchmark_disconnect_route private-storage-fragments || fail FRAGMENTS_ROUTE_CLEANUP_FAILED
    private_storage_fragments_cleanup || fail FRAGMENTS_PRIVATE_CLEANUP_FAILED
    if [ "${cloud_private_upload:-no}" = yes ]; then
        python3 -B "$source_directory/tests/integration/cloud-private-upload-smoke.py" evidence "$WORK" \
            "$WORK/cloud-private-upload-evidence.json" >/dev/null || fail CLOUD_PRIVATE_UPLOAD_EVIDENCE_INVALID
    elif [ "${cloud_private_file:-no}" = yes ]; then
        python3 -B "$source_directory/tests/integration/cloud-private-file-smoke.py" evidence "$WORK" \
            "$WORK/cloud-private-file-evidence.json" >/dev/null || fail CLOUD_PRIVATE_FILE_EVIDENCE_INVALID
    elif [ "${image_snapshot:-no}" = yes ]; then
        python3 -B "$source_directory/tests/integration/image-snapshot-smoke.py" evidence "$WORK" \
            "$WORK/image-snapshot-evidence.json" >/dev/null || fail IMAGE_SNAPSHOT_EVIDENCE_INVALID
    else
        python3 -B "$source_directory/tests/integration/private-storage-fragments-smoke.py" evidence "$WORK" \
            "$WORK/private-storage-fragments-evidence.json" >/dev/null || fail FRAGMENTS_EVIDENCE_INVALID
    fi
    OBSERVED_BLOCKER=NONE
    if [ "${cloud_private_upload:-no}" = yes ]; then PHASE=cloud-private-upload-complete
    elif [ "${cloud_private_file:-no}" = yes ]; then PHASE=cloud-private-file-complete
    elif [ "${image_snapshot:-no}" = yes ]; then PHASE=image-snapshot-complete
    else PHASE=private-storage-fragments-complete; fi
}

private_storage_fragments_finalize_report() {
    storage_status=$1
    optional_json_evidence "$WORK/private-storage-fragments-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-storage-fragments",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,storage:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"four signed ciphertext fragments with two copies across three actual providers; stopped first provider, two full reconstructions, exact non-consuming subset accounting and all-copy deletion; no automatic placement, repair, reciprocal quota, encryption or Signal proof"}' \
        >"$WORK/private-storage-fragments-smoke.json" || return 1
    storage_exports=$(python3 -B "$source_directory/tests/integration/private-storage-fragments-smoke.py" export-names) || return 1
    for storage_name in $storage_exports; do
        storage_artifact=$WORK/$storage_name
        if [ -f "$storage_artifact" ] && [ ! -L "$storage_artifact" ]; then
            [ "$(wc -c <"$storage_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$storage_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/private-storage-fragments-smoke.py" report \
        "$WORK/private-storage-fragments-smoke.json" "$expected_commit"
}
