#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the approved disposable topology; never a host-network test.
# shellcheck disable=SC2154,SC2034

private_storage_sequence_private() {
    sequence_owner_budget=900
    if [ "${private_storage_natural_expiry:-no}" = yes ] && [ "$1" = prepare ]; then
        sequence_owner_budget=$(python3 -B "$WORK/bin/private-storage-natural-expiry.py" remaining "$expiry_start") || return 1
        [ "$sequence_owner_budget" -gt 0 ] || return 1
    fi
    set -- timeout --signal=TERM --kill-after=5s "${sequence_owner_budget}s" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-deposit-sequence-smoke.py" "$@"
    "$@"
}

private_storage_sequence_cleanup() {
    [ -f "$WORK/bin/private-storage-deposit-sequence-smoke.py" ] || return 0
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    private_storage_sequence_private cleanup "$WORK/client-fixtures/private-storage-user" \
        >"$WORK/private-storage-deposit-sequence-private_cleanup.json"
}

private_storage_sequence_prepare() {
    PHASE=private-storage-deposit-sequence-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail SEQUENCE_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail SEQUENCE_CONTROL_GROUP_INVALID
    storage_user=$WORK/client-fixtures/private-storage-user
    [ ! -e "$storage_user" ] && [ ! -L "$storage_user" ] || fail SEQUENCE_USER_NOT_NEW
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_user"
    # One route selection only. Every CLI operation uses the production agent's
    # reusable route and helper-owned per-flow transport/retirement machinery.
    sequence_selection_status=0
    benchmark_select_route private-storage-deposit-sequence mptcp || sequence_selection_status=$?
    # Freeze only this first selector's outcome before fail invokes finalization.
    # Projection failure remains metadata, never changes selection or its result.
    python3 -B "$source_directory/tests/integration/private-storage-deposit-sequence-smoke.py" \
        capture-initial-route-selection "$WORK" >/dev/null 2>&1 || true
    [ "$sequence_selection_status" -eq 0 ] || fail SEQUENCE_ROUTE_UNAVAILABLE
    if [ "${private_storage_natural_expiry:-no}" = yes ]; then
        expiry_start=$(python3 -B "$WORK/bin/private-storage-natural-expiry.py" clock) || fail EXPIRY_CLOCK_FAILED
    fi
    benchmark_bind_slots "$WORK/private-storage-deposit-sequence-selection.json" || fail SEQUENCE_ROUTE_INVALID
    storage_context=$(jq -er '.route_context_id' "$WORK/private-storage-deposit-sequence-selection.json")
    provider_control_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || fail SEQUENCE_CONTROL_UNAVAILABLE
    jq -e --arg peer "$provider_control_peer" '[.relay0,.relay1,.relay2] | index($peer) != null' \
        "$WORK/a01-expected-peers.json" >/dev/null || fail SEQUENCE_CONTROL_NOT_ROUTE_DISTINCT
    if [ "${private_storage_natural_expiry:-no}" = yes ]; then
        private_storage_expiry_matrix_prepare || fail EXPIRY_MATRIX_FAILED
    else
        content_provider_adaptive_control_underlay "$provider_control_peer" || fail SEQUENCE_CONTROL_UNDERLAY_FAILED
    fi
    storage_key_a=$(private_storage_replicas_key relay4) || fail SEQUENCE_KEY_FAILED
    storage_key_b=$(private_storage_replicas_key relay5) || fail SEQUENCE_KEY_FAILED
    storage_key_c=$(private_storage_replicas_key relay3) || fail SEQUENCE_KEY_FAILED
    [ "$storage_key_a" != "$storage_key_b" ] && [ "$storage_key_a" != "$storage_key_c" ] \
        && [ "$storage_key_b" != "$storage_key_c" ] || fail SEQUENCE_KEYS_EQUAL
    storage_namespaces=
    for storage_node in relay4 relay5 relay3; do
        private_storage_replicas_serve "$storage_node" no || fail SEQUENCE_SERVE_FAILED
        storage_key=$(private_storage_replicas_key "$storage_node") || fail SEQUENCE_KEY_FAILED
        storage_peer=$(jq -er --arg node "$storage_node" '.[$node]' "$WORK/a01-expected-peers.json")
        python3 -B - "$source_directory/tests/integration/content-custody-smoke.py" "$storage_peer" "$storage_key" <<'PY' \
            || fail SEQUENCE_PROVIDER_IDENTITY_MISMATCH
import runpy, sys
assert runpy.run_path(sys.argv[1])["peer_key"](sys.argv[2]) == sys.argv[3]
PY
        content_provider_node "$storage_node" || fail SEQUENCE_NAMESPACE_INVALID
        storage_namespace=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail SEQUENCE_NAMESPACE_INVALID
        case " $storage_namespaces " in *" $storage_namespace "*) fail SEQUENCE_NAMESPACES_EQUAL ;; esac
        storage_namespaces="$storage_namespaces $storage_namespace"
    done
    storage_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $storage_client_pid in ''|0|*[!0-9]*) fail SEQUENCE_CLIENT_PID_INVALID ;; esac
    nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail SEQUENCE_POSITIVE_ISOLATION_FAILED
    for storage_private in "$storage_user" "$WORK/state-relay4/private-store" \
        "$WORK/state-relay5/private-store" "$WORK/state-relay3/private-store"; do
        if nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$storage_private"; then fail SEQUENCE_LOCAL_SHORTCUT; fi
    done
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$group,
        agent_cannot_read_user_state:true,client_cannot_read_any_provider_store:true,agent_mount_positive_control:true,
        all_provider_keys_match_independent_fixture_peers:true,three_provider_namespaces_distinct:true}' \
        >"$WORK/private-storage-deposit-sequence-isolation.json"
    jq -n --arg control "$provider_control_peer" --arg context "$storage_context" \
        --slurpfile selected "$WORK/private-storage-deposit-sequence-selection.json" \
        '{provider_nodes:["relay4","relay5","relay3"],control_relay_peer_id:$control,route_context_id:$context,
          route_scope:{exit_peer_id:$selected[0].exact_selected_exit,
            paths:[$selected[0].paths[] | {path_id,relay_peer_id}]}}' \
        >"$WORK/private-storage-deposit-sequence-layout.json"
    private_storage_sequence_private prepare "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-relay4/control/agent.sock" \
        "$WORK/runtime-relay5/control/agent.sock" "$WORK/runtime-relay3/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-deposit-sequence-prepare.json" || fail SEQUENCE_PREPARE_FAILED
}

private_storage_sequence_run() {
    private_storage_sequence_prepare
    PHASE=private-storage-deposit-sequence-run
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail SEQUENCE_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers private-storage-deposit-sequence-privacy || fail SEQUENCE_CAPTURE_UNAVAILABLE
    content_provider_adaptive_start_control_observer content-provider-adaptive-private-storage-deposit-sequence-control \
        || fail SEQUENCE_CONTROL_CAPTURE_UNAVAILABLE
    # Reuse the bounded overlapping-log observer. The owner command remains
    # unprivileged, finite and joined; no product deadline is changed.
    python3 -B "$WORK/bin/private-storage-fragments-smoke.py" observe-flows \
        "$binary_directory/volparossa" "$WORK/runtime-exit/control/agent.sock" \
        "$provider_baseline_ms" "$WORK/private-storage-deposit-sequence-gates.json" 40 -- \
        timeout --signal=TERM --kill-after=5s 900s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-deposit-sequence-smoke.py" run \
        "$storage_user" "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-deposit-sequence-sequence.json" || fail SEQUENCE_TRANSFER_FAILED
    benchmark_capture_paths private-storage-deposit-sequence-live mptcp || fail SEQUENCE_ROUTE_UNAVAILABLE
    stop_privacy_observers || fail SEQUENCE_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail SEQUENCE_CONTROL_CAPTURE_INCOMPLETE
    for storage_node in relay4 relay5 relay3; do
        content_custody_cli "$storage_node" content stop >/dev/null || fail SEQUENCE_STOP_FAILED
        content_custody_cli "$storage_node" content status | jq -e '.serving == false' >/dev/null \
            || fail SEQUENCE_PROVIDER_STILL_SERVING
        private_storage_replicas_usage "$storage_node" | jq -e '{reserved_bytes,committed_bytes,leases}' \
            >"$WORK/sequence-usage-$storage_node.private" || fail SEQUENCE_USAGE_FAILED
    done
    jq -s '.' "$WORK/sequence-usage-relay4.private" "$WORK/sequence-usage-relay5.private" \
        "$WORK/sequence-usage-relay3.private" >"$WORK/private-storage-deposit-sequence-deleted_usage.json"
    private_storage_sequence_cleanup || fail SEQUENCE_OWNER_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/private-storage-deposit-sequence-smoke.py" evidence "$WORK" \
        "$WORK/private-storage-deposit-sequence-evidence.json" >/dev/null || fail SEQUENCE_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=private-storage-deposit-sequence-complete
}

private_storage_sequence_finalize_report() {
    storage_status=$1
    optional_json_evidence "$WORK/private-storage-deposit-sequence-evidence.json" >"$WORK/sequence-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/sequence-host.part"
    python3 -B "$source_directory/tests/integration/private-storage-deposit-sequence-smoke.py" \
        initial-route-selection "$WORK" >"$WORK/sequence-initial-route.part" 2>/dev/null \
        || printf '%s\n' '{"schema_version":1,"status":"invalid","route":null}' >"$WORK/sequence-initial-route.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/sequence-evidence.part" \
        --slurpfile host "$WORK/sequence-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile initial_route "$WORK/sequence-initial-route.part" '
      {schema_version:1,report_kind:"volparossa-private-storage-deposit-sequence",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,storage:$evidence[0],initial_route_selection:$initial_route[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"core-only ten-deposit prefix on one fresh real protected route; not full consumer acceptance or proof of original failure cause"}' \
        >"$WORK/private-storage-deposit-sequence-smoke.json" || return 1
    storage_exports=$(python3 -B "$source_directory/tests/integration/private-storage-deposit-sequence-smoke.py" export-names) || return 1
    for storage_name in $storage_exports; do
        storage_artifact=$WORK/$storage_name
        if [ -f "$storage_artifact" ] && [ ! -L "$storage_artifact" ]; then
            [ "$(wc -c <"$storage_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$storage_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/private-storage-deposit-sequence-smoke.py" report \
        "$WORK/private-storage-deposit-sequence-smoke.json" "$expected_commit"
}
