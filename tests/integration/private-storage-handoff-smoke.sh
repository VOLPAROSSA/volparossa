#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the approved disposable KVM topology. No host operation.
# shellcheck disable=SC2154,SC2034

private_storage_handoff_private() {
    # Replace performs at most eleven sequential 120s exchanges, including failed
    # deletion of stopped A. The fixture-only outer bound does not widen core TTLs.
    timeout --signal=TERM --kill-after=5s 1500s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-handoff-smoke.py" "$@"
}

private_storage_handoff_cleanup() {
    [ -f "$WORK/bin/private-storage-handoff-smoke.py" ] || return 0
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    private_storage_handoff_private cleanup "$WORK/client-fixtures/private-storage-user" \
        >"$WORK/private-storage-handoff-private_cleanup.json"
}

private_storage_handoff_phase_start() {
    storage_phase=$1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail HANDOFF_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers "private-storage-handoff-$storage_phase-privacy" || fail HANDOFF_CAPTURE_UNAVAILABLE
    content_provider_adaptive_start_control_observer "content-provider-adaptive-private-storage-handoff-$storage_phase-control" \
        || fail HANDOFF_CONTROL_CAPTURE_UNAVAILABLE
}

private_storage_handoff_phase_finish() {
    storage_expected_flows=$1
    benchmark_capture_paths "private-storage-handoff-$storage_phase-live" mptcp || fail HANDOFF_ROUTE_UNAVAILABLE
    jq -e --arg context "$storage_context" '.route_context_id == $context' \
        "$WORK/private-storage-handoff-$storage_phase-live-selection.json" >/dev/null || fail HANDOFF_ROUTE_CHANGED
    stop_privacy_observers || fail HANDOFF_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail HANDOFF_CONTROL_CAPTURE_INCOMPLETE
    storage_poll=0
    while [ "$storage_poll" -lt 50 ]; do
        capture_product_logs
        storage_flows=$(content_provider_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        [ "$storage_flows" -lt "$storage_expected_flows" ] || break
        sleep 0.1
        storage_poll=$((storage_poll + 1))
    done
    jq -n --argjson baseline "$provider_baseline_ms" --argjson count "$storage_flows" \
        '{event_baseline_unix_ms:$baseline,exit_mptcp_tls_completed:$count}' \
        >"$WORK/private-storage-handoff-$storage_phase-gates.json"
    [ "$storage_flows" -ge "$storage_expected_flows" ] || fail HANDOFF_PROTECTED_FLOW_INCOMPLETE
}

private_storage_handoff_usage() {
    storage_usage_label=$1
    # The real store owns an exclusive lock. Inspect only after its service has
    # stopped; no direct SQLite reads or fabricated counters while it is live.
    for storage_node in relay4 relay5 relay3; do
        private_storage_handoff_stop "$storage_node"
        private_storage_replicas_usage "$storage_node" | jq -e '{reserved_bytes,committed_bytes,leases}' \
            >"$WORK/private-storage-handoff-usage-$storage_node.json" || fail HANDOFF_USAGE_FAILED
    done
    jq -s '.' "$WORK/private-storage-handoff-usage-relay4.json" \
        "$WORK/private-storage-handoff-usage-relay5.json" "$WORK/private-storage-handoff-usage-relay3.json" \
        >"$WORK/private-storage-handoff-$storage_usage_label.json" || fail HANDOFF_USAGE_FAILED
}

private_storage_handoff_reopen() {
    for storage_reopen_node in "$@"; do
        private_storage_replicas_serve "$storage_reopen_node" yes || fail HANDOFF_REOPEN_FAILED
        case $storage_reopen_node in
            relay4) storage_expected_inode=$storage_store_a ;;
            relay5) storage_expected_inode=$storage_store_b ;;
            relay3) storage_expected_inode=$storage_store_c ;;
            *) fail HANDOFF_REOPEN_NODE_INVALID ;;
        esac
        [ "$storage_expected_inode" = "$(stat -Lc '%d:%i' "$WORK/state-$storage_reopen_node/private-store")" ] \
            || fail HANDOFF_OWNED_STORE_REPLACED
    done
}

private_storage_handoff_stop() {
    storage_stop_node=$1
    content_custody_cli "$storage_stop_node" content stop >/dev/null || fail HANDOFF_STOP_FAILED
    content_custody_cli "$storage_stop_node" content status | jq -e '.serving == false' >/dev/null \
        || fail HANDOFF_PROVIDER_STILL_SERVING
}

private_storage_handoff_run() {
    PHASE=private-storage-handoff-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail HANDOFF_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail HANDOFF_CONTROL_GROUP_INVALID
    storage_user=$WORK/client-fixtures/private-storage-user
    if [ -e "$storage_user" ] || [ -L "$storage_user" ]; then fail HANDOFF_USER_NOT_NEW; fi
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_user"
    benchmark_select_route private-storage-handoff mptcp || fail HANDOFF_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/private-storage-handoff-selection.json" || fail HANDOFF_ROUTE_INVALID
    storage_context=$(jq -er '.route_context_id' "$WORK/private-storage-handoff-selection.json")
    provider_control_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || fail HANDOFF_CONTROL_UNAVAILABLE
    jq -e --arg peer "$provider_control_peer" '[.relay0,.relay1,.relay2] | index($peer) != null' \
        "$WORK/a01-expected-peers.json" >/dev/null || fail HANDOFF_CONTROL_NOT_ROUTE_DISTINCT
    # Reuse the custody topology's existing restricted QUIC-only control links.
    # No new application endpoint, Internet egress or direct Client/provider path.
    content_provider_adaptive_control_underlay "$provider_control_peer" || fail HANDOFF_CONTROL_UNDERLAY_FAILED
    storage_key_a=$(private_storage_replicas_key relay4) || fail HANDOFF_PROVIDER_KEY_FAILED
    storage_key_b=$(private_storage_replicas_key relay5) || fail HANDOFF_PROVIDER_KEY_FAILED
    storage_key_c=$(private_storage_replicas_key relay3) || fail HANDOFF_PROVIDER_KEY_FAILED
    if [ "$storage_key_a" = "$storage_key_b" ] || [ "$storage_key_a" = "$storage_key_c" ] \
        || [ "$storage_key_b" = "$storage_key_c" ]; then fail HANDOFF_PROVIDER_KEYS_EQUAL; fi
    storage_namespaces=
    for storage_node in relay4 relay5 relay3; do
        private_storage_replicas_serve "$storage_node" no || fail HANDOFF_SERVE_FAILED
        storage_key=$(private_storage_replicas_key "$storage_node") || fail HANDOFF_PROVIDER_KEY_FAILED
        storage_peer=$(jq -er --arg node "$storage_node" '.[$node]' "$WORK/a01-expected-peers.json")
        python3 -B - "$source_directory/tests/integration/content-custody-smoke.py" "$storage_peer" "$storage_key" <<'PY' \
            || fail HANDOFF_PROVIDER_IDENTITY_MISMATCH
import runpy, sys
assert runpy.run_path(sys.argv[1])["peer_key"](sys.argv[2]) == sys.argv[3]
PY
        content_provider_node "$storage_node" || fail HANDOFF_NAMESPACE_INVALID
        storage_namespace=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail HANDOFF_NAMESPACE_INVALID
        case " $storage_namespaces " in *" $storage_namespace "*) fail HANDOFF_NAMESPACES_EQUAL ;; esac
        storage_namespaces="$storage_namespaces $storage_namespace"
    done
    storage_store_a=$(stat -Lc '%d:%i' "$WORK/state-relay4/private-store") || fail HANDOFF_STORE_IDENTITY_FAILED
    storage_store_b=$(stat -Lc '%d:%i' "$WORK/state-relay5/private-store") || fail HANDOFF_STORE_IDENTITY_FAILED
    storage_store_c=$(stat -Lc '%d:%i' "$WORK/state-relay3/private-store") || fail HANDOFF_STORE_IDENTITY_FAILED
    private_storage_handoff_private prepare "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-relay4/control/agent.sock" \
        "$WORK/runtime-relay5/control/agent.sock" "$WORK/runtime-relay3/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-handoff-prepare.json" || fail HANDOFF_OWNER_PREPARE_FAILED
    storage_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $storage_client_pid in ''|0|*[!0-9]*) fail HANDOFF_CLIENT_PID_INVALID ;; esac
    nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail HANDOFF_POSITIVE_ISOLATION_FAILED
    for storage_private in "$storage_user" "$WORK/state-relay4/private-store" \
        "$WORK/state-relay5/private-store" "$WORK/state-relay3/private-store"; do
        if nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$storage_private"; then fail HANDOFF_LOCAL_SHORTCUT; fi
    done
    jq -n --arg control "$provider_control_peer" --arg context "$storage_context" \
        '{provider_nodes:["relay4","relay5","relay3"],control_relay_peer_id:$control,route_context_id:$context}' \
        >"$WORK/private-storage-handoff-layout.json"
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$group,
        agent_cannot_read_user_state:true,client_cannot_read_any_provider_store:true,agent_mount_positive_control:true,
        all_provider_keys_match_independent_fixture_peers:true,three_provider_namespaces_distinct:true}' \
        >"$WORK/private-storage-handoff-isolation.json"

    PHASE=private-storage-handoff-upload
    private_storage_handoff_phase_start upload
    private_storage_handoff_private upload "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" \
        >"$WORK/private-storage-handoff-upload.json" || fail HANDOFF_INITIAL_UPLOAD_FAILED
    private_storage_handoff_phase_finish 18

    PHASE=private-storage-handoff-pending
    private_storage_handoff_stop relay4
    storage_archive_bytes=$(jq -er '.ciphertext_bytes' "$WORK/private-storage-handoff-prepare.json")
    private_storage_replicas_usage relay4 | jq -e --argjson bytes "$storage_archive_bytes" \
        '.reserved_bytes == 0 and .committed_bytes == $bytes and .leases == 1' \
        >/dev/null || fail HANDOFF_ORIGINAL_STORE_NOT_RETAINED
    private_storage_handoff_phase_start pending
    private_storage_handoff_private pending "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-handoff-pending.json" || fail HANDOFF_EXPECTED_PENDING_STATE_MISSING
    private_storage_handoff_phase_finish 10
    private_storage_handoff_usage pending_usage

    PHASE=private-storage-handoff-retry
    private_storage_handoff_reopen relay4 relay5 relay3
    private_storage_handoff_phase_start complete
    private_storage_handoff_private complete "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-handoff-complete.json" || fail HANDOFF_RETRY_FAILED
    private_storage_handoff_phase_finish 7
    private_storage_handoff_usage complete_usage
    private_storage_handoff_reopen relay5 relay3

    PHASE=private-storage-handoff-restore-b
    private_storage_handoff_phase_start restore_b
    private_storage_handoff_private restore_b "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-handoff-restore_b.json" || fail HANDOFF_UNCHANGED_SURVIVOR_RESTORE_FAILED
    private_storage_handoff_phase_finish 4

    PHASE=private-storage-handoff-restore-c
    private_storage_handoff_stop relay5
    private_storage_handoff_phase_start restore_c
    private_storage_handoff_private restore_c "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-handoff-restore_c.json" || fail HANDOFF_REPLACEMENT_RESTORE_FAILED
    private_storage_handoff_phase_finish 4
    private_storage_handoff_reopen relay5
    jq -n '{first_provider_stopped_before_replace:true,first_store_retained:true,same_first_store_reopened:true,
        first_provider_stopped_after_confirmed_delete:true,second_provider_stopped_before_replacement_restore:true,
        same_second_store_reopened:true,all_usage_snapshots_with_services_stopped:true,
        all_three_store_inodes_preserved:true,agent_restart_claimed:false}' >"$WORK/private-storage-handoff-withdrawal.json"

    PHASE=private-storage-handoff-finish
    private_storage_handoff_phase_start finish
    private_storage_handoff_private finish "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-handoff-finish.json" || fail HANDOFF_FINISH_FAILED
    private_storage_handoff_phase_finish 4
    private_storage_handoff_stop relay5
    private_storage_handoff_stop relay3
    private_storage_handoff_usage deleted_usage
    benchmark_disconnect_route private-storage-handoff || fail HANDOFF_ROUTE_CLEANUP_FAILED
    private_storage_handoff_cleanup || fail HANDOFF_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/private-storage-handoff-smoke.py" evidence "$WORK" \
        "$WORK/private-storage-handoff-evidence.json" >/dev/null || fail HANDOFF_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=private-storage-handoff-complete
}

private_storage_handoff_finalize_report() {
    storage_status=$1
    optional_json_evidence "$WORK/private-storage-handoff-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-storage-handoff",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,storage:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"owner-driven A/B to B/C replacement; real survivor restore, replacement full readback, uncertain three-copy charge until exact source deletion; no automatic resizing, repair, Signal or independent hardware proof"}' \
        >"$WORK/private-storage-handoff-smoke.json" || return 1
    storage_exports=$(python3 -B "$source_directory/tests/integration/private-storage-handoff-smoke.py" export-names) || return 1
    for storage_name in $storage_exports; do
        storage_artifact=$WORK/$storage_name
        if [ -f "$storage_artifact" ] && [ ! -L "$storage_artifact" ]; then
            [ "$(wc -c <"$storage_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$storage_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/private-storage-handoff-smoke.py" report \
        "$WORK/private-storage-handoff-smoke.json" "$expected_commit"
}
