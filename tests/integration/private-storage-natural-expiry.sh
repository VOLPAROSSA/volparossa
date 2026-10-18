#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced by the disposable topology only; no standalone host-network operator.
# shellcheck disable=SC2154,SC2034

private_storage_expiry_tool() {
    python3 -B "$source_directory/tests/integration/private-storage-natural-expiry.py" "$@"
}

private_storage_expiry_private() {
    expiry_remaining=$(private_storage_expiry_tool remaining "$expiry_start") || return 1
    [ "$expiry_remaining" -gt 0 ] || return 1
    timeout --signal=TERM --kill-after=5s "${expiry_remaining}s" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-natural-expiry.py" "$@"
}

private_storage_expiry_matrix_prepare() {
    [ "${private_storage_natural_expiry:-no}" = yes ] && [ "$private_storage_maintenance" = no ] \
        && [ "$private_storage_fragments" = no ] && [ -z "$PROVIDER_CONTROL_PID" ] || return 1
    # No historical adaptive links or archive are assumed or fabricated.
    storage_consumer_control_snapshot detached || return 1
    private_storage_expiry_tool matrix-check empty "$WORK/consumer-control-detached.private" || return 1
    storage_control_matrix_install || return 1
    storage_consumer_control_snapshot after || return 1
    private_storage_expiry_tool matrix-check installed "$WORK/consumer-control-after.private" || return 1
    jq -cn --slurpfile before "$WORK/consumer-control-detached.private" \
        --slurpfile after "$WORK/consumer-control-after.private" \
        '{version:1,created_from_empty:true,before:$before[0],after:$after[0]}' \
        >"$WORK/private-storage-natural-expiry-matrix.json"
}

private_storage_expiry_readback() {
    storage_consumer_control_snapshot after || return 1
    expiry_readback=$WORK/private-storage-natural-expiry-$expiry_phase-matrix-$1.json
    [ ! -e "$expiry_readback" ] && [ ! -L "$expiry_readback" ] || return 1
    jq -cSj '.' "$WORK/consumer-control-after.private" >"$expiry_readback" || return 1
    private_storage_expiry_tool matrix-check installed "$expiry_readback" \
        "$WORK/private-storage-natural-expiry-matrix.json"
}

private_storage_expiry_captures_start() {
    case $expiry_phase in prefix|suffix) ;; *) return 1 ;; esac
    [ -z "$PROVIDER_CONTROL_PID$CONSUMER_CONTROL_0_PID$CONSUMER_CONTROL_1_PID$CONSUMER_CONTROL_2_PID" ] || return 1
    private_storage_expiry_readback before || return 1
    start_privacy_observers "private-storage-natural-expiry-$expiry_phase-privacy" || return 1
    for expiry_broker in 0 1 2; do
        content_provider_node "relay$expiry_broker" || return 1
        expiry_namespace=$provider_ns; expiry_ips=$provider_ip
        for expiry_provider in relay3 relay4 relay5; do
            content_provider_node "$expiry_provider" || return 1
            expiry_ips=$expiry_ips,$provider_ip
        done
        expiry_capture=private-storage-natural-expiry-$expiry_phase-control-relay$expiry_broker
        ip netns exec "$expiry_namespace" python3 "$WORK/bin/privacy-observer.py" content-control \
            "$WORK/$expiry_capture.json" "$WORK/$expiry_capture.ready" --content-providers \
            "--consumer-control=relay$expiry_broker" "--content-control=$expiry_ips" \
            "cc${expiry_broker}0" "cc${expiry_broker}1" "cc${expiry_broker}2" \
            >"$WORK/$expiry_capture.log" 2>&1 &
        expiry_capture_pid=$!
        case $expiry_broker in
            0) CONSUMER_CONTROL_0_PID=$expiry_capture_pid ;;
            1) CONSUMER_CONTROL_1_PID=$expiry_capture_pid ;;
            2) CONSUMER_CONTROL_2_PID=$expiry_capture_pid ;;
        esac
        wait_observer "$expiry_capture_pid" "$WORK/$expiry_capture.ready" || return 1
    done
}

private_storage_expiry_captures_finish() {
    benchmark_capture_paths "private-storage-natural-expiry-$expiry_phase-live" mptcp || return 1
    private_storage_expiry_readback after || return 1
    expiry_capture_status=0
    stop_privacy_observers || expiry_capture_status=1
    storage_consumer_stop_captures || expiry_capture_status=1
    return "$expiry_capture_status"
}

private_storage_expiry_join() {
    if [ -n "${EXPIRY_COLLECTOR_PID:-}" ]; then
        kill -TERM "$EXPIRY_COLLECTOR_PID" 2>/dev/null || true
        expiry_join_status=0
        wait "$EXPIRY_COLLECTOR_PID" || expiry_join_status=1
        EXPIRY_COLLECTOR_PID=
        [ "$expiry_join_status" -eq 0 ] || return 1
        expiry_collector_joined=true
    fi
}

private_storage_expiry_cleanup() {
    if [ "${expiry_cleanup_done:-no}" = yes ]; then return "${expiry_cleanup_status:-1}"; fi
    expiry_abort_attempted=false
    expiry_remote_confirmed=false
    expiry_owner_confirmed=false
    expiry_cleanup_status=0
    if [ "${expiry_remote_cleanup:-no}" = yes ] || [ "${expiry_attempted:-0}" -eq 0 ]; then
        expiry_remote_confirmed=true
    elif [ -n "${expiry_start:-}" ] && [ -d "$WORK/client-fixtures/private-storage-user" ]; then
        expiry_abort_attempted=true
        if private_storage_expiry_private abort "$WORK/client-fixtures/private-storage-user" \
            "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
            "$storage_key_a" "$storage_key_b" "$storage_key_c" "$expiry_attempted" \
            >"$WORK/private-storage-natural-expiry-abort.json"; then
            expiry_remote_confirmed=true
        fi
    fi
    private_storage_expiry_join || expiry_cleanup_status=1
    # Existing owner cleanup validates the complete private tree before removal.
    # Closed failure/abort records are already retained; no raw private state is exported.
    if private_storage_sequence_cleanup; then expiry_owner_confirmed=true; fi
    jq -cn --argjson attempted "$expiry_abort_attempted" --argjson remote "$expiry_remote_confirmed" \
        --argjson joined "${expiry_collector_joined:-false}" --argjson owner "$expiry_owner_confirmed" \
        '{abort_attempted:$attempted,remote_cleanup_confirmed:$remote,collector_joined:$joined,owner_cleanup_confirmed:$owner}' \
        >"$WORK/private-storage-natural-expiry-cleanup.json" || expiry_cleanup_status=1
    [ "$expiry_remote_confirmed" = true ] && [ "$expiry_owner_confirmed" = true ] || expiry_cleanup_status=1
    expiry_cleanup_done=yes
    return "$expiry_cleanup_status"
}

private_storage_expiry_flow_drain() {
    expiry_drain=0
    while [ "$expiry_drain" -lt 50 ]; do
        kill -USR1 "$EXPIRY_COLLECTOR_PID" 2>/dev/null || return 1
        if private_storage_expiry_tool "$@" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
        expiry_drain=$((expiry_drain + 1))
    done
    return 1
}

private_storage_expiry_run() {
    expiry_attempted=0; expiry_collector_joined=false; expiry_remote_cleanup=no
    private_storage_sequence_prepare
    PHASE=private-storage-natural-expiry-prepare
    private_storage_expiry_tool observe "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        "$WORK/a01-expected-peers.json" >"$WORK/private-storage-natural-expiry-initial.json" || fail EXPIRY_INITIAL_ROUTE_FAILED
    private_storage_expiry_tool process-snapshot "$WORK" >"$WORK/expiry-process-initial.private" || fail EXPIRY_PROCESS_FAILED
    capture_product_logs
    expiry_baseline=$(client_log_baseline_ms) || fail EXPIRY_EVENT_BASELINE_FAILED
    python3 -B "$source_directory/tests/integration/private-storage-natural-expiry.py" collect \
        "$binary_directory/volparossa" "$WORK/runtime-exit/control/agent.sock" \
        "$expiry_baseline" "$WORK/private-storage-natural-expiry-initial.json" \
        "$WORK/private-storage-natural-expiry-flows.json" "$WORK/expiry-collector.ready" "$expiry_start" \
        >"$WORK/expiry-collector.private" 2>&1 &
    EXPIRY_COLLECTOR_PID=$!
    wait_observer "$EXPIRY_COLLECTOR_PID" "$WORK/expiry-collector.ready" || fail EXPIRY_COLLECTOR_UNAVAILABLE
    PHASE=private-storage-natural-expiry-prefix
    expiry_phase=prefix
    private_storage_expiry_captures_start || fail EXPIRY_PREFIX_CAPTURE_FAILED
    expiry_attempted=8
    private_storage_expiry_private prefix "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-natural-expiry-prefix.json" || fail EXPIRY_PREFIX_FAILED
    private_storage_expiry_flow_drain prefix-flows "$WORK/private-storage-natural-expiry-flows.json" \
        "$WORK/private-storage-natural-expiry-initial.json" || fail EXPIRY_PREFIX_FLOWS_FAILED
    private_storage_expiry_captures_finish || fail EXPIRY_PREFIX_CAPTURE_INCOMPLETE
    private_storage_expiry_tool observe "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        "$WORK/a01-expected-peers.json" >"$WORK/private-storage-natural-expiry-old.json" || fail EXPIRY_OLD_ROUTE_FAILED
    private_storage_expiry_tool same-route "$WORK/private-storage-natural-expiry-initial.json" \
        "$WORK/private-storage-natural-expiry-old.json" || fail EXPIRY_PREFIX_ROUTE_CHANGED
    private_storage_expiry_tool elapsed "$expiry_start" >"$WORK/private-storage-natural-expiry-prefix-clock.json"
    private_storage_expiry_tool process-snapshot "$WORK" >"$WORK/expiry-process-prefix.private" || fail EXPIRY_PROCESS_FAILED
    PHASE=private-storage-natural-expiry-wait
    # No serve/refresh/connect/disconnect/restart during this natural idle wait.
    private_storage_expiry_tool wait "$expiry_start" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/a01-expected-peers.json" \
        "$WORK/private-storage-natural-expiry-old.json" \
        >"$WORK/private-storage-natural-expiry-boundary.json" || fail EXPIRY_BOUNDARY_UNCONFIRMED
    PHASE=private-storage-natural-expiry-suffix
    expiry_phase=suffix
    private_storage_expiry_captures_start || fail EXPIRY_SUFFIX_CAPTURE_FAILED
    expiry_attempted=10
    private_storage_expiry_private suffix "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/private-storage-natural-expiry-suffix.json" || fail EXPIRY_SUFFIX_FAILED
    expiry_remote_cleanup=yes
    private_storage_expiry_tool observe "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        "$WORK/a01-expected-peers.json" >"$WORK/private-storage-natural-expiry-new.json" || fail EXPIRY_NEW_ROUTE_FAILED
    private_storage_expiry_flow_drain final-flows "$WORK/private-storage-natural-expiry-flows.json" \
        "$WORK/private-storage-natural-expiry-old.json" "$WORK/private-storage-natural-expiry-new.json" || fail EXPIRY_SUFFIX_FLOWS_FAILED
    private_storage_expiry_captures_finish || fail EXPIRY_SUFFIX_CAPTURE_INCOMPLETE
    private_storage_expiry_tool process-snapshot "$WORK" >"$WORK/expiry-process-final.private" || fail EXPIRY_PROCESS_FAILED
    private_storage_expiry_tool process-check "$WORK/expiry-process-initial.private" "$WORK/expiry-process-prefix.private" \
        "$WORK/expiry-process-final.private" >"$WORK/private-storage-natural-expiry-processes.json" || fail EXPIRY_PROCESS_CHANGED
    private_storage_expiry_join || fail EXPIRY_COLLECTOR_FAILED
    for storage_node in relay4 relay5 relay3; do
        content_custody_cli "$storage_node" content stop >/dev/null || fail EXPIRY_STOP_FAILED
        content_custody_cli "$storage_node" content status | jq -e '.serving == false' >/dev/null || fail EXPIRY_STILL_SERVING
        private_storage_replicas_usage "$storage_node" | jq -e '{reserved_bytes,committed_bytes,leases}' \
            >"$WORK/expiry-usage-$storage_node.private" || fail EXPIRY_USAGE_FAILED
    done
    jq -s '.' "$WORK/expiry-usage-relay4.private" "$WORK/expiry-usage-relay5.private" \
        "$WORK/expiry-usage-relay3.private" >"$WORK/private-storage-deposit-sequence-deleted_usage.json"
    private_storage_expiry_cleanup || fail EXPIRY_OWNER_CLEANUP_FAILED
    private_storage_expiry_tool evidence "$WORK" >"$WORK/private-storage-natural-expiry-evidence.json" || fail EXPIRY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=private-storage-natural-expiry-complete
}

private_storage_expiry_finalize_report() {
    expiry_status=$1
    optional_json_evidence "$WORK/private-storage-natural-expiry-evidence.json" >"$WORK/expiry-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/expiry-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$expiry_status" --slurpfile evidence "$WORK/expiry-evidence.part" --slurpfile host "$WORK/expiry-host.part" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-storage-natural-expiry",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,storage:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"core-only ordinary idle route expiry between eight and two copies; not in-flight expiry or original consumer acceptance"}' \
        >"$WORK/private-storage-natural-expiry-smoke.json" || return 1
    expiry_exports=$(private_storage_expiry_tool export-names) || return 1
    for expiry_name in $expiry_exports; do
        expiry_artifact=$WORK/$expiry_name
        if [ -f "$expiry_artifact" ] && [ ! -L "$expiry_artifact" ]; then
            [ "$(wc -c <"$expiry_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$expiry_artifact" "$output_directory/$expiry_name"
        fi
    done
    private_storage_expiry_tool report "$WORK/private-storage-natural-expiry-smoke.json" "$expected_commit"
}
