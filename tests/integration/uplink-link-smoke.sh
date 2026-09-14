#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only after the parent verifies its disposable KVM guest and exact owned namespaces.
# shellcheck disable=SC2154 # Exact namespace and process ownership belongs to the guarded parent.

uplink_link_extend_network() {
    # C stays entirely local. A is an actual but unmonitored alternative Exit. Only B's r2d
    # is explicitly monitored. B's data paths in this fixture use LAN, not its dummy WAN.
    link_nodes "$R0" r0d 10.241.34.1/30 "$DEST" dr0 10.241.34.2/30
    ip -n "$R0" route add 10.241.31.2/32 via 10.241.34.2 dev r0d src 10.241.34.1
    ip -n "$R2" route replace default via 10.241.35.2 dev r2d src 10.241.35.1
}

uplink_link_snapshot() {
    uplink_stage=$1
    local_link_node_snapshot "$uplink_stage"
    ip -n "$R2" -j address show dev r2d >"$WORK/uplink-egress-$uplink_stage-addresses.json"
    ip -n "$R2" -j route show table main >"$WORK/uplink-egress-$uplink_stage-routes.json"
    ip -n "$CLIENT" -j address show >"$WORK/uplink-client-$uplink_stage-addresses.json"
    ip -n "$CLIENT" -j route show table main >"$WORK/uplink-client-$uplink_stage-routes.json"
}

uplink_link_wait_advertisement() {
    uplink_ad_stage=$1
    uplink_ad_roles=$2
    uplink_ad_deadline=$(($(date +%s) + 60))
    while [ "$(date +%s)" -lt "$uplink_ad_deadline" ]; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
            peers >"$WORK/uplink-peers-$uplink_ad_stage.txt" || return 1
        # This CLI store contains verified signed advertisements, not configured peer roles.
        if awk -v peer="$R2_PEER" -v roles="roles=$uplink_ad_roles" \
            '$1 == peer && $2 == roles { found=1 } END { exit !found }' \
            "$WORK/uplink-peers-$uplink_ad_stage.txt"; then return 0; fi
        sleep 0.2
    done
    return 1
}

uplink_link_select() {
    uplink_select_phase=$1; uplink_select_node=$2
    uplink_select_relay=$3; uplink_select_exit=$4
    uplink_select_deadline=$(($(date +%s) + 180))
    uplink_select_attempt=0
    while [ "$uplink_select_attempt" -lt 16 ]; do
        uplink_select_left=$((uplink_select_deadline - $(date +%s)))
        [ "$uplink_select_left" -gt 0 ] || return 1
        (reciprocity_connect "$uplink_select_node" "$uplink_select_left") || return 1
        uplink_select_file="$WORK/uplink-$uplink_select_phase/draw-$uplink_select_node-$uplink_select_attempt.txt"
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$uplink_select_node/control/agent.sock" \
            paths >"$uplink_select_file" || return 1
        if awk -v relay="relay=$uplink_select_relay" -v target="exit=$uplink_select_exit" \
            '$1 ~ /^context=/ { rows++; if ($3 == relay && $4 == target &&
              ($5 == "state=2" || $5 == "state=3")) matched++ }
             END { exit !(rows == 1 && matched == 1) }' "$uplink_select_file"; then return 0; fi
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$uplink_select_node/control/agent.sock" \
            disconnect >"$WORK/uplink-$uplink_select_phase/disconnect-$uplink_select_node-$uplink_select_attempt.log" 2>&1 \
            || return 1
        uplink_select_attempt=$((uplink_select_attempt + 1))
    done
    return 1
}

uplink_link_start_phase() {
    uplink_phase=$1; uplink_second=$2
    uplink_phase_dir="$WORK/uplink-$uplink_phase"
    install -d -o root -g root -m 0755 "$uplink_phase_dir"
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$uplink_phase_dir/app"
    PHASE="uplink-$uplink_phase-selection"
    # Every draw is an ordinary Client Connect. Do not override production selection or IDs.
    (uplink_link_select "$uplink_phase" client "$R0_PEER" "$EXIT_PEER") &
    uplink_select_client_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $uplink_select_client_pid"
    case $uplink_second in relay0) uplink_target=$R2_PEER ;; relay2) uplink_target=$R0_PEER ;; esac
    (uplink_link_select "$uplink_phase" "$uplink_second" "$CLIENT_PEER" "$uplink_target") &
    uplink_select_second_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $uplink_select_second_pid"
    wait "$uplink_select_client_pid" || fail UPLINK_LOCAL_CONSUMPTION_ROUTE_UNAVAILABLE
    wait "$uplink_select_second_pid" || fail UPLINK_LOCAL_CONTRIBUTION_ROUTE_UNAVAILABLE
    RECIPROCITY_PIDS=
    PHASE="uplink-$uplink_phase-payload"
    ip netns exec "$DEST" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 -B "$WORK/bin/uplink-link-smoke.py" server "$uplink_phase_dir/app" "$RUN_ID" "$uplink_phase" \
        >"$uplink_phase_dir/server.log" 2>&1 &
    uplink_server_pid=$!
    RECIPROCITY_PIDS=$uplink_server_pid
    reciprocity_wait_file "$uplink_phase_dir/app/server.ready" "$uplink_server_pid" \
        || fail UPLINK_DESTINATION_NOT_READY
    uplink_capture_pids=
    for uplink_node in client relay0 relay2 exit; do
        uplink_ns=$(reciprocity_namespace "$uplink_node")
        ip netns exec "$uplink_ns" python3 -B "$WORK/bin/uplink-link-smoke.py" capture \
            "$uplink_phase_dir" "$RUN_ID" "$uplink_phase" "$uplink_node" \
            >"$uplink_phase_dir/capture-$uplink_node.log" 2>&1 &
        uplink_pid=$!
        uplink_capture_pids="$uplink_capture_pids $uplink_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $uplink_pid"
        reciprocity_wait_file "$uplink_phase_dir/local-link-capture-$uplink_node.ready" "$uplink_pid" \
            || fail UPLINK_CAPTURE_NOT_READY
    done
    uplink_app_pids=
    for uplink_node in client "$uplink_second"; do
        uplink_ns=$(reciprocity_namespace "$uplink_node")
        if [ "$uplink_phase" = initial ] && [ "$uplink_node" = relay0 ]; then
            set -- held-client "$uplink_phase_dir/app" "$RUN_ID" "$uplink_phase"
        else
            set -- client "$uplink_phase_dir/app" "$RUN_ID" "$uplink_phase" "$uplink_node"
        fi
        ip netns exec "$uplink_ns" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
            python3 -B "$WORK/bin/uplink-link-smoke.py" "$@" \
            >"$uplink_phase_dir/client-$uplink_node.log" 2>&1 &
        uplink_pid=$!
        uplink_app_pids="$uplink_app_pids $uplink_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $uplink_pid"
        printf '%s\n' "$uplink_pid" >"$uplink_phase_dir/pid-$uplink_node.txt"
    done
    printf 'go\n' >"$uplink_phase_dir/app/go"
    for uplink_node in client "$uplink_second"; do
        reciprocity_wait_file "$uplink_phase_dir/app/$uplink_node.active" \
            "$(cat "$uplink_phase_dir/pid-$uplink_node.txt")" || fail UPLINK_APPLICATION_ECHO_UNAVAILABLE
    done
    sleep 3
    for uplink_node in client "$uplink_second"; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$uplink_node/control/agent.sock" \
            paths >"$uplink_phase_dir/paths-$uplink_node.txt"
    done
    uplink_link_snapshot "$uplink_phase"
}

uplink_link_stop_phase() {
    printf 'stop\n' >"$uplink_phase_dir/app/stop"
    for uplink_pid in $uplink_app_pids; do wait "$uplink_pid" || fail UPLINK_APPLICATION_FAILED; done
    for uplink_pid in $uplink_capture_pids "$uplink_server_pid"; do
        kill -TERM "$uplink_pid" || fail UPLINK_OBSERVER_EARLY_EXIT
    done
    for uplink_pid in $uplink_capture_pids "$uplink_server_pid"; do
        wait "$uplink_pid" || fail UPLINK_OBSERVER_FAILED
    done
    RECIPROCITY_PIDS=
    for uplink_node in client relay0 relay2; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$uplink_node/control/agent.sock" \
            disconnect >"$uplink_phase_dir/disconnect-final-$uplink_node.log" 2>&1 \
            || fail UPLINK_CLIENT_CONTEXT_CLEANUP_FAILED
    done
}

uplink_link_run() {
    PHASE=uplink-discovery
    for uplink_fixture in reciprocity-smoke.py local-link-smoke.py uplink-link-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$uplink_fixture" "$WORK/bin/$uplink_fixture"
    done
    local_link_wait_neighbors || fail UPLINK_INITIAL_NEIGHBORS_UNAVAILABLE
    uplink_link_wait_advertisement initial 0b111 || fail UPLINK_INITIAL_EXIT_ADVERTISEMENT_UNAVAILABLE
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    uplink_link_start_phase initial relay0
    PHASE=uplink-loss
    uplink_loss_baseline=$(date +%s%3N)
    printf '%s\n' "$uplink_loss_baseline" >"$WORK/uplink-loss-baseline-ms.txt"
    sleep 0.01
    # Exact disposable guest objects only; no replacement device, no fallback default.
    ip -n "$R2" route del default via 10.241.35.2 dev r2d
    ip -n "$R2" link set dev r2d down
    uplink_loss_deadline=$(($(date +%s) + 30))
    while [ "$(date +%s)" -lt "$uplink_loss_deadline" ]; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay2/control/agent.sock" \
            logs --limit 400 >"$WORK/uplink-relay2-loss-logs.txt"
        awk -v baseline="$uplink_loss_baseline" '$1 > baseline && /event=INDEPENDENT_EGRESS_WITHDRAWN/ { print }' \
            "$WORK/uplink-relay2-loss-logs.txt" >"$WORK/uplink-withdraw-events.txt"
        [ ! -s "$WORK/uplink-withdraw-events.txt" ] || break
        sleep 0.2
    done
    [ -s "$WORK/uplink-withdraw-events.txt" ] || fail UPLINK_WITHDRAWAL_EVENT_UNAVAILABLE
    printf 'loss\n' >"$uplink_phase_dir/app/loss.go"
    reciprocity_wait_file "$uplink_phase_dir/app/loss.complete" \
        "$(cat "$uplink_phase_dir/pid-relay0.txt")" || fail UPLINK_OLD_APPLICATION_DID_NOT_STOP
    uplink_link_stop_phase
    uplink_link_wait_advertisement lost 0b011 || fail UPLINK_VERIFIED_EXIT_WITHDRAWAL_UNAVAILABLE
    # A new ordinary selection may fail before sending a grant. Never report that as a
    # server-side grant rejection; retain the actual result and assert only no ready B route.
    uplink_fresh_started=$(date +%s%3N)
    if timeout --kill-after=5 45 "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-relay0/control/agent.sock" connect --transport single-path-udp \
        >"$WORK/uplink-fresh-loss-connect.out" 2>"$WORK/uplink-fresh-loss-connect.err"; then
        printf '0\n' >"$WORK/uplink-fresh-loss-status.txt"
    else printf '%s\n' "$?" >"$WORK/uplink-fresh-loss-status.txt"; fi
    jq -cn --argjson started "$uplink_fresh_started" --argjson finished "$(date +%s%3N)" \
        --argjson status "$(cat "$WORK/uplink-fresh-loss-status.txt")" \
        '{node:"relay0",transport:"single-path-udp",started_ms:$started,finished_ms:$finished,exit_code:$status}' \
        >"$WORK/uplink-fresh-loss-attempt.json"
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay0/control/agent.sock" \
        paths >"$WORK/uplink-fresh-loss-paths.txt"
    if awk -v target="exit=$R2_PEER" '$1 ~ /^context=/ && $4 == target &&
        ($5 == "state=2" || $5 == "state=3") { found=1 } END { exit !found }' \
        "$WORK/uplink-fresh-loss-paths.txt"; then fail UPLINK_NEW_READY_ROUTE_TO_WITHDRAWN_EXIT; fi
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay0/control/agent.sock" \
        disconnect >"$WORK/uplink-fresh-loss-disconnect.log"
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay2/control/agent.sock" \
        logs --limit 400 >"$WORK/uplink-relay2-rejection-logs.txt"
    awk -v baseline="$uplink_loss_baseline" '$1 > baseline &&
        /event=(EXIT_FORWARD_EXIT_SCOPE_REJECTED|NATIVE_PROBE_PERMIT_EXIT_REJECTED|NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED)/ { print }' \
        "$WORK/uplink-relay2-rejection-logs.txt" >"$WORK/uplink-rejection-events.txt"
    uplink_link_start_phase lost relay2
    uplink_link_stop_phase
    PHASE=uplink-restoration
    ip -n "$R2" link set dev r2d up
    ip -n "$R2" route replace default via 10.241.35.2 dev r2d src 10.241.35.1
    uplink_link_wait_advertisement restored 0b111 || fail UPLINK_VERIFIED_EXIT_RESTORATION_UNAVAILABLE
    uplink_link_start_phase restored relay0
    uplink_link_stop_phase
    python3 -B "$WORK/bin/uplink-link-smoke.py" evidence "$WORK" "$RUN_ID" \
        || fail UPLINK_TRANSITION_EVIDENCE_INVALID
    PHASE=uplink-complete
    OBSERVED_BLOCKER=
}

uplink_link_finalize_report() {
    uplink_status=$1
    uplink_evidence='{"success":false,"flows":[],"nodes":[],"phases":[]}'
    [ ! -s "$WORK/uplink-link-evidence.json" ] || uplink_evidence=$(cat "$WORK/uplink-link-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$uplink_status" --argjson evidence "$uplink_evidence" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" \
        '$evidence + {schema_version:1,report_kind:"volparossa-uplink-transition-runtime",
          source_revision:$revision,run_id:$run_id,phase:$phase,
          success:($status == 0 and $evidence.success and $complete and $remaining == 0 and $host[0].unchanged),
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:{complete:$complete,remaining_owned_objects:$remaining},
          host_state:($host[0] | del(.acceptance_id))}' >"$WORK/uplink-link-smoke.json"
    for uplink_artifact in "$WORK"/uplink-*.json "$WORK"/uplink-*.txt "$WORK"/uplink-*.log \
        "$WORK"/uplink-*.out "$WORK"/uplink-*.err "$WORK"/local-link-node-*.json \
        "$WORK"/reciprocity-connect-*.out "$WORK"/reciprocity-connect-*.err; do
        if [ ! -f "$uplink_artifact" ] || [ -L "$uplink_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$uplink_artifact" "$output_directory/$(basename -- "$uplink_artifact")"
    done
    for uplink_saved_phase in initial lost restored; do
        for uplink_artifact in "$WORK/uplink-$uplink_saved_phase"/*.json "$WORK/uplink-$uplink_saved_phase"/*.txt \
            "$WORK/uplink-$uplink_saved_phase"/*.log "$WORK/uplink-$uplink_saved_phase/app"/*.json; do
            if [ ! -f "$uplink_artifact" ] || [ -L "$uplink_artifact" ]; then continue; fi
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$uplink_artifact" \
                "$output_directory/uplink-$uplink_saved_phase-$(basename -- "$uplink_artifact")"
        done
    done
    jq -e '.success == true' "$WORK/uplink-link-smoke.json" >/dev/null
}
