#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the approved disposable KVM topology, never on the development host.
# shellcheck disable=SC2154,SC2034

private_storage_replicas_private() {
    # At most two 420s CLI restores per phase; each core exchange still has its 120s limit.
    # This bound is replica-fixture-only, not a longer network or application deadline.
    timeout --signal=TERM --kill-after=5s 900s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-replicas-smoke.py" "$@"
}

private_storage_replicas_cleanup() {
    [ -f "$WORK/bin/private-storage-replicas-smoke.py" ] || return 0
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    private_storage_replicas_private cleanup "$WORK/client-fixtures/private-storage-user" \
        >"$WORK/private-storage-replicas-private_cleanup.json"
}

private_storage_replicas_serve() {
    storage_serve_node=$1
    content_custody_endpoint "$storage_serve_node" || return 1
    if [ "$2" = yes ]; then set -- --reuse-store
    else set -- --capacity-bytes 1048576 --min-free-bytes 268435456; fi
    content_custody_cli "$storage_serve_node" storage peer serve \
        --bind "$custody_address:18080" --advertised-hostname "$custody_hostname" \
        --store "$WORK/state-$storage_serve_node/private-store" "$@" >/dev/null
}

private_storage_replicas_usage() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" storage local status --store "$WORK/state-$1/private-store"
}

private_storage_replicas_key() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" content recipient-key \
        --identity "$WORK/state-$1/identity.key" --passphrase-file "$WORK/credential-$1/identity-passphrase" \
        | jq -er '.identity_public_key_hex | select(test("^[0-9a-f]{64}$"))'
}

private_storage_replicas_phase_start() {
    storage_phase=$1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail REPLICAS_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers "private-storage-replicas-$storage_phase-privacy" || fail REPLICAS_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer "content-provider-private-storage-replicas-$storage_phase-control" \
        || fail REPLICAS_CONTROL_CAPTURE_UNAVAILABLE
}

private_storage_replicas_phase_finish() {
    storage_expected_flows=$1
    benchmark_capture_paths "private-storage-replicas-$storage_phase-live" mptcp || fail REPLICAS_ROUTE_UNAVAILABLE
    jq -e --arg context "$storage_context" '.route_context_id == $context' \
        "$WORK/private-storage-replicas-$storage_phase-live-selection.json" >/dev/null || fail REPLICAS_ROUTE_CHANGED
    stop_privacy_observers || fail REPLICAS_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail REPLICAS_CONTROL_CAPTURE_INCOMPLETE
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
        >"$WORK/private-storage-replicas-$storage_phase-gates.json"
    [ "$storage_flows" -ge "$storage_expected_flows" ] || fail REPLICAS_PROTECTED_FLOW_INCOMPLETE
}

private_storage_replicas_run() {
    PHASE=private-storage-replicas-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail REPLICAS_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail REPLICAS_CONTROL_GROUP_INVALID
    storage_user=$WORK/client-fixtures/private-storage-user
    [ ! -e "$storage_user" ] && [ ! -L "$storage_user" ] || fail REPLICAS_USER_NOT_NEW
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_user"
    benchmark_select_route private-storage-replicas mptcp || fail REPLICAS_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/private-storage-replicas-selection.json" || fail REPLICAS_ROUTE_INVALID
    storage_context=$(jq -er '.route_context_id' "$WORK/private-storage-replicas-selection.json")
    provider_control_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || fail REPLICAS_CONTROL_UNAVAILABLE
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '. as $p | ["relay4","relay5","relay3"]
        | map(select($p[.] != $control)) | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") \
        || fail REPLICAS_PROVIDER_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    content_provider_control_underlay
    storage_key_a=$(private_storage_replicas_key "$provider_node_a") || fail REPLICAS_PROVIDER_KEY_FAILED
    storage_key_b=$(private_storage_replicas_key "$provider_node_b") || fail REPLICAS_PROVIDER_KEY_FAILED
    [ "$storage_key_a" != "$storage_key_b" ] || fail REPLICAS_PROVIDER_KEY_EQUAL
    for storage_node in "$provider_node_a" "$provider_node_b"; do
        private_storage_replicas_serve "$storage_node" no || fail REPLICAS_SERVE_FAILED
        storage_key=$(private_storage_replicas_key "$storage_node") || fail REPLICAS_PROVIDER_KEY_FAILED
        storage_peer=$(jq -er --arg node "$storage_node" '.[$node]' "$WORK/a01-expected-peers.json")
        python3 -B - "$source_directory/tests/integration/content-custody-smoke.py" "$storage_peer" "$storage_key" <<'PY' \
            || fail REPLICAS_PROVIDER_IDENTITY_MISMATCH
import runpy, sys
assert runpy.run_path(sys.argv[1])["peer_key"](sys.argv[2]) == sys.argv[3]
PY
    done
    content_provider_node "$provider_node_a" || fail REPLICAS_NAMESPACE_INVALID
    storage_net_a=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail REPLICAS_NAMESPACE_INVALID
    content_provider_node "$provider_node_b" || fail REPLICAS_NAMESPACE_INVALID
    storage_net_b=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail REPLICAS_NAMESPACE_INVALID
    [ "$storage_net_a" != "$storage_net_b" ] || fail REPLICAS_NAMESPACES_EQUAL
    private_storage_replicas_private prepare "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-$provider_node_a/control/agent.sock" \
        "$WORK/runtime-$provider_node_b/control/agent.sock" "$storage_key_a" "$storage_key_b" \
        >"$WORK/private-storage-replicas-prepare.json" || fail REPLICAS_OWNER_PREPARE_FAILED
    storage_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $storage_client_pid in ''|0|*[!0-9]*) fail REPLICAS_CLIENT_PID_INVALID ;; esac
    nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail REPLICAS_POSITIVE_ISOLATION_FAILED
    for storage_private in "$storage_user" "$WORK/state-$provider_node_a/private-store" "$WORK/state-$provider_node_b/private-store"; do
        if nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$storage_private"; then fail REPLICAS_LOCAL_SHORTCUT; fi
    done
    jq -n --argjson nodes "$provider_nodes" --arg control "$provider_control_peer" --arg context "$storage_context" \
        '{provider_nodes:$nodes,control_relay_peer_id:$control,route_context_id:$context}' >"$WORK/private-storage-replicas-layout.json"
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$group,
        agent_cannot_read_user_state:true,client_cannot_read_either_provider_store:true,agent_mount_positive_control:true,
        both_provider_keys_match_independent_fixture_peers:true,provider_namespaces_distinct:true}' >"$WORK/private-storage-replicas-isolation.json"

    PHASE=private-storage-replicas-upload
    private_storage_replicas_phase_start upload
    private_storage_replicas_private upload "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" \
        >"$WORK/private-storage-replicas-upload.json" || fail REPLICAS_UPLOAD_FAILED
    private_storage_replicas_phase_finish 18

    PHASE=private-storage-replicas-withdrawal
    storage_store_identity=$(stat -Lc '%d:%i' "$WORK/state-$provider_node_a/private-store") || fail REPLICAS_STORE_IDENTITY_FAILED
    content_custody_cli "$provider_node_a" content stop >/dev/null || fail REPLICAS_FIRST_STOP_FAILED
    content_custody_cli "$provider_node_a" content status | jq -e '.serving == false' >/dev/null || fail REPLICAS_FIRST_STILL_SERVING
    content_custody_cli "$provider_node_b" content status | jq -e '.serving == true' >/dev/null || fail REPLICAS_SURVIVOR_NOT_SERVING
    private_storage_replicas_usage "$provider_node_a" | jq -e '{first_provider_service_stopped:true,serving:false,
        retained_committed_bytes:.committed_bytes,retained_reserved_bytes:.reserved_bytes,retained_leases:.leases,
        second_provider_serving:true,agent_restart_claimed:false}' >"$WORK/private-storage-replicas-withdrawal-before.json" \
        || fail REPLICAS_RETAINED_STORE_UNAVAILABLE
    PHASE=private-storage-replicas-failover
    private_storage_replicas_phase_start failover
    private_storage_replicas_private failover "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" \
        >"$WORK/private-storage-replicas-failover.json" || fail REPLICAS_FAILOVER_FAILED
    private_storage_replicas_phase_finish 4

    PHASE=private-storage-replicas-reopen
    private_storage_replicas_serve "$provider_node_a" yes || fail REPLICAS_REOPEN_FAILED
    [ "$storage_store_identity" = "$(stat -Lc '%d:%i' "$WORK/state-$provider_node_a/private-store")" ] || fail REPLICAS_STORE_REPLACED
    jq '. + {same_owned_store_reopened:true}' "$WORK/private-storage-replicas-withdrawal-before.json" \
        >"$WORK/private-storage-replicas-withdrawal.json" || fail REPLICAS_WITHDRAWAL_EVIDENCE_FAILED
    PHASE=private-storage-replicas-finish
    private_storage_replicas_phase_start finish
    private_storage_replicas_private finish "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" \
        >"$WORK/private-storage-replicas-finish.json" || fail REPLICAS_FINISH_FAILED
    private_storage_replicas_phase_finish 6
    for storage_node in "$provider_node_a" "$provider_node_b"; do
        content_custody_cli "$storage_node" content stop >/dev/null || fail REPLICAS_FINAL_STOP_FAILED
        private_storage_replicas_usage "$storage_node" | jq -e '{reserved_bytes,committed_bytes,leases}' \
            >"$WORK/private-storage-replicas-usage-$storage_node.json" || fail REPLICAS_FINAL_USAGE_FAILED
    done
    jq -s '.' "$WORK/private-storage-replicas-usage-$provider_node_a.json" "$WORK/private-storage-replicas-usage-$provider_node_b.json" \
        >"$WORK/private-storage-replicas-deleted_usage.json"
    benchmark_disconnect_route private-storage-replicas || fail REPLICAS_ROUTE_CLEANUP_FAILED
    private_storage_replicas_cleanup || fail REPLICAS_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/private-storage-replicas-smoke.py" evidence "$WORK" \
        "$WORK/private-storage-replicas-evidence.json" >/dev/null || fail REPLICAS_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=private-storage-replicas-complete
}

private_storage_replicas_finalize_report() {
    storage_status=$1
    # Only bounded sanitized evidence crosses the guest boundary, never grants, keys or journals.
    optional_json_evidence "$WORK/private-storage-replicas-evidence.json" >"$WORK/replicas-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/replicas-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/replicas-report-evidence.part" \
        --slurpfile host "$WORK/replicas-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-storage-replicas",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,storage:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"two explicitly pinned stores over protected routes; actual first service unavailable, source removed, verified survivor restores and selected-copy deletion; synthetic opaque bytes, not independent hardware or reciprocal contribution"}' \
        >"$WORK/private-storage-replicas-smoke.json" || return 1
    for storage_name in smoke evidence prepare upload failover finish withdrawal deleted_usage private_cleanup isolation layout; do
        storage_artifact=$WORK/private-storage-replicas-$storage_name.json
        [ ! -f "$storage_artifact" ] || [ -L "$storage_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$(basename -- "$storage_artifact")"
    done
    python3 -B "$source_directory/tests/integration/private-storage-replicas-smoke.py" report \
        "$WORK/private-storage-replicas-smoke.json" "$expected_commit"
}
