#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the guarded disposable KVM runner, never a host-network entrypoint.
# shellcheck disable=SC2154 # Paths, identities and ownership come from the guarded parent.

local_link_extend_network() {
    # Delete only exact objects in the already-created, disposable Client namespace.
    ip -n "$CLIENT" route del 42.158.0.1/32
    ip -n "$CLIENT" route del 45.161.2.1/32
    for local_link_interface in cr1 cr3 cr4 cr5 cb1 cb2 underlay; do
        ip -n "$CLIENT" link del "$local_link_interface"
    done
    # B provides its own Internet egress for A→C→B. C never receives an uplink.
    link_nodes "$R2" r2d 10.241.35.1/30 "$DEST" dr2 10.241.35.2/30
    ip -n "$R2" route add 10.241.31.2/32 via 10.241.35.2 dev r2d src 10.241.35.1
    ip -n "$R0" route add unreachable 45.161.2.1/32
    ip -n "$R2" route add unreachable 42.158.0.1/32
    ip -n "$CLIENT" -j address show >"$WORK/local-link-addresses-before.json"
    ip -n "$CLIENT" -j route show table main >"$WORK/local-link-routes-before.json"
    [ -z "$(ip -n "$CLIENT" route show table main default)" ] \
        || fail LOCAL_LINK_PHYSICAL_DEFAULT_PRESENT
    for local_link_forbidden in 46.162.3.1 10.241.31.2; do
        if ip -n "$CLIENT" route get "$local_link_forbidden" >/dev/null 2>&1; then
            fail LOCAL_LINK_DIRECT_EXIT_OR_INTERNET_ROUTE_PRESENT
        fi
    done
    if ip -n "$R0" route get 45.161.2.1 >/dev/null 2>&1; then
        fail LOCAL_LINK_CONTRIBUTOR_DIRECT_EXIT_ROUTE_PRESENT
    fi
}

local_link_node_snapshot() {
    local_link_stage=$1
    for local_link_node in client relay0 relay2 exit; do
        local_link_pid=$(systemctl show --property=MainPID --value \
            "volparossa-alpha-agent@$local_link_node.service")
        case $local_link_pid in ''|0|*[!0-9]*) fail LOCAL_LINK_AGENT_PID_INVALID ;; esac
        [ "$(readlink -f -- "/proc/$local_link_pid/exe")" = \
            "$binary_directory/volparossa-agent" ] || fail LOCAL_LINK_AGENT_EXECUTABLE_INVALID
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$local_link_node/control/agent.sock" role show \
            >"$WORK/local-link-roles-$local_link_node-$local_link_stage.txt"
        local_link_exit=true
        [ "$local_link_node" != client ] || local_link_exit=false
        for local_link_role in 'client: true' 'relay: true' "exit: $local_link_exit"; do
            grep -Fx "$local_link_role" \
                "$WORK/local-link-roles-$local_link_node-$local_link_stage.txt" >/dev/null \
                || fail LOCAL_LINK_CAPABILITY_ROLES_INVALID
        done
        jq -cn --arg node "$local_link_node" --argjson pid "$local_link_pid" \
            --argjson exit "$local_link_exit" \
            '{node:$node,agent_pid:$pid,roles:{client:true,relay:true,exit:$exit}}' \
            >"$WORK/local-link-node-$local_link_node-$local_link_stage.json"
    done
}

local_link_wait_neighbors() {
    local_link_deadline=$(($(date +%s) + 90))
    while [ "$(date +%s)" -lt "$local_link_deadline" ]; do
        local_link_ready=yes
        # Gate only the two consuming nodes' candidate views, not B/X's unused Client routes.
        for local_link_node in client relay0; do
            "$binary_directory/volparossa" \
                --control-socket "$WORK/runtime-$local_link_node/control/agent.sock" peers \
                >"$WORK/local-link-peers-$local_link_node.txt" || return 1
            case $local_link_node in
                client) local_link_neighbors="$R0_PEER:0b111 $R2_PEER:0b111 $EXIT_PEER:0b111" ;;
                relay0) local_link_neighbors="$CLIENT_PEER:0b011 $R2_PEER:0b111 $EXIT_PEER:0b111" ;;
            esac
            for local_link_neighbor in $local_link_neighbors; do
                awk -v peer="${local_link_neighbor%:*}" -v roles="roles=${local_link_neighbor#*:}" \
                    '$1 == peer && $2 == roles { found=1 } END { exit !found }' \
                    "$WORK/local-link-peers-$local_link_node.txt" || local_link_ready=no
            done
        done
        [ "$local_link_ready" != yes ] || return 0
        sleep 0.2
    done
    return 1
}

local_link_select_contribution() {
    # This square has two valid Relay assignments. Exercise the one where the offline node
    # actually forwards data, not merely control. Resample via ordinary Disconnect/Connect
    # before application traffic; retain every draw, and fail if the bounded sampler never
    # selects that path. No forced peer, fabricated capacity or changed selection policy.
    local_link_selection_deadline=$(($(date +%s) + 180))
    local_link_selection_attempt=0
    while [ "$local_link_selection_attempt" -lt 8 ]; do
        local_link_selection_file="$WORK/local-link-selection-$local_link_selection_attempt.txt"
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay0/control/agent.sock" \
            paths >"$local_link_selection_file" || return 1
        if awk -v relay="relay=$CLIENT_PEER" -v selected_exit="exit=$R2_PEER" \
            '$1 ~ /^context=/ { paths++; if ($3 == relay && $4 == selected_exit &&
                ($5 == "state=2" || $5 == "state=3")) matched++ }
             END { exit !(paths == 1 && matched == 1) }' "$local_link_selection_file"; then
            return 0
        fi
        local_link_selection_seconds=$((local_link_selection_deadline - $(date +%s)))
        [ "$local_link_selection_seconds" -gt 0 ] || return 1
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay0/control/agent.sock" \
            disconnect >"$WORK/local-link-reselection-$local_link_selection_attempt.log" 2>&1 || return 1
        (reciprocity_connect relay0 "$local_link_selection_seconds") || return 1
        local_link_selection_attempt=$((local_link_selection_attempt + 1))
    done
    return 1
}

local_link_run() {
    PHASE=local-link-discovery
    for local_link_fixture in reciprocity-smoke.py local-link-smoke.py; do
        install -o root -g root -m 0555 \
            "$source_directory/tests/integration/$local_link_fixture" "$WORK/bin/$local_link_fixture"
    done
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/local-link-app"
    local_link_node_snapshot before
    local_link_wait_neighbors || fail LOCAL_LINK_NEIGHBOR_DISCOVERY_UNAVAILABLE
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    ip netns exec "$DEST" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/local-link-smoke.py" server \
        "$WORK/local-link-app" "$RUN_ID" >"$WORK/local-link-server.log" 2>&1 &
    local_link_server_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $local_link_server_pid"
    reciprocity_wait_file "$WORK/local-link-app/server.ready" "$local_link_server_pid" \
        || fail LOCAL_LINK_DESTINATION_NOT_READY
    # The existing bounded connector chooses Exit and data Relay itself; the other adjacent
    # Relay carries the privacy control connection. No endpoint/Relay is forced by the fixture.
    local_link_connect_pids=
    for local_link_node in client relay0; do
        (reciprocity_connect "$local_link_node") &
        local_link_connect_pids="$local_link_connect_pids $!"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $!"
    done
    for local_link_pid in $local_link_connect_pids; do
        wait "$local_link_pid" || fail LOCAL_LINK_NATIVE_ROUTE_UNAVAILABLE
    done
    RECIPROCITY_PIDS=$local_link_server_pid
    local_link_select_contribution || fail LOCAL_LINK_DATA_CONTRIBUTOR_NOT_SELECTED
    PHASE=local-link-udp
    if [ "${wifi_link:-no}" = yes ]; then
        wifi_link_snapshot payload-before || fail WIFI_LINK_PAYLOAD_BASELINE_UNAVAILABLE
    fi
    local_link_capture_pids=
    for local_link_node in client relay0 relay2 exit; do
        local_link_ns=$(reciprocity_namespace "$local_link_node")
        ip netns exec "$local_link_ns" python3 "$WORK/bin/local-link-smoke.py" capture \
            "$WORK" "$RUN_ID" "$local_link_node" \
            >"$WORK/local-link-capture-$local_link_node.log" 2>&1 &
        local_link_pid=$!
        local_link_capture_pids="$local_link_capture_pids $local_link_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $local_link_pid"
        reciprocity_wait_file "$WORK/local-link-capture-$local_link_node.ready" "$local_link_pid" \
            || fail LOCAL_LINK_CAPTURE_NOT_READY
    done
    local_link_app_pids=
    for local_link_node in client relay0; do
        local_link_ns=$(reciprocity_namespace "$local_link_node")
        ip netns exec "$local_link_ns" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
            --no-new-privs -- python3 "$WORK/bin/local-link-smoke.py" client \
            "$WORK/local-link-app" "$RUN_ID" "$local_link_node" \
            >"$WORK/local-link-client-$local_link_node.log" 2>&1 &
        local_link_app_pid=$!
        local_link_app_pids="$local_link_app_pids $local_link_app_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $local_link_app_pid"
        printf '%s\n' "$local_link_app_pid" >"$WORK/local-link-pid-$local_link_node.txt"
    done
    printf 'go\n' >"$WORK/local-link-app/go"
    for local_link_node in client relay0; do
        reciprocity_wait_file "$WORK/local-link-app/$local_link_node.active" \
            "$(cat "$WORK/local-link-pid-$local_link_node.txt")" \
            || fail LOCAL_LINK_APPLICATION_ECHO_UNAVAILABLE
    done
    sleep 3
    for local_link_node in client relay0; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$local_link_node/control/agent.sock" \
            paths >"$WORK/local-link-paths-$local_link_node.txt"
    done
    local_link_node_snapshot after
    ip -n "$CLIENT" -j address show >"$WORK/local-link-addresses-after.json"
    ip -n "$CLIENT" -j route show table main >"$WORK/local-link-routes-after.json"
    printf 'stop\n' >"$WORK/local-link-app/stop"
    for local_link_pid in $local_link_app_pids; do
        wait "$local_link_pid" || fail LOCAL_LINK_APPLICATION_FAILED
    done
    for local_link_pid in $local_link_capture_pids "$local_link_server_pid"; do
        kill -TERM "$local_link_pid" || fail LOCAL_LINK_OBSERVER_EARLY_EXIT
    done
    for local_link_pid in $local_link_capture_pids "$local_link_server_pid"; do
        wait "$local_link_pid" || fail LOCAL_LINK_OBSERVER_FAILED
    done
    RECIPROCITY_PIDS=
    python3 "$WORK/bin/local-link-smoke.py" evidence "$WORK" "$RUN_ID" \
        || fail LOCAL_LINK_EVIDENCE_INVALID
    [ "${wifi_link:-no}" != yes ] || wifi_link_after_payload
    PHASE=local-link-complete
    OBSERVED_BLOCKER=
}

local_link_finalize_report() {
    local_link_status=$1
    local_link_evidence='{"success":false,"flows":[],"nodes":[]}'
    [ ! -s "$WORK/local-link-evidence.json" ] \
        || local_link_evidence=$(cat "$WORK/local-link-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$local_link_status" --argjson evidence "$local_link_evidence" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" \
        '$evidence + {schema_version:1,report_kind:"volparossa-local-link-runtime",
          source_revision:$revision,run_id:$run_id,phase:$phase,
          success:($status == 0 and $evidence.success and $complete and
            $remaining == 0 and $host[0].unchanged),
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:{complete:$complete,remaining_owned_objects:$remaining},
          host_state:($host[0] | del(.acceptance_id)),
          scope:"concurrent offline consumption and actual LAN relay contribution; not radio, capacity aggregation or A01-A15"}' \
        >"$WORK/local-link-smoke.json"
    for local_link_artifact in "$WORK"/local-link-*.json "$WORK"/local-link-*.txt \
        "$WORK"/local-link-*.log "$WORK"/reciprocity-connect-client.* "$WORK"/reciprocity-connect-relay0.* \
        "$WORK"/mpquic-*-client.log "$WORK"/mpquic-*-exit.log; do
        if [ ! -f "$local_link_artifact" ] || [ -L "$local_link_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$local_link_artifact" \
            "$output_directory/$(basename -- "$local_link_artifact")"
    done
    for local_link_artifact in "$WORK"/local-link-app/*.json; do
        if [ ! -f "$local_link_artifact" ] || [ -L "$local_link_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$local_link_artifact" \
            "$output_directory/local-link-app-$(basename -- "$local_link_artifact")"
    done
    jq -e '.success == true' "$WORK/local-link-smoke.json" >/dev/null
}
