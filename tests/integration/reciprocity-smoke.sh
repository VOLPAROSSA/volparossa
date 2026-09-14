#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the guarded disposable KVM topology, never a host network entrypoint.
# shellcheck disable=SC2154 # Runtime paths and ownership IDs come from the guarded parent.

reciprocity_namespace() {
    case $1 in
        client) printf '%s\n' "$CLIENT" ;;
        relay0) printf '%s\n' "$R0" ;;
        relay2) printf '%s\n' "$R2" ;;
        exit) printf '%s\n' "$EXIT_NODE" ;;
        *) return 1 ;;
    esac
}

reciprocity_extend_network() {
    # Every participant has its own disposable uplink. The original policy still permits only
    # 10.241.31.2:18081/UDP. Normal worker-UID applications must be transparently intercepted;
    # the observers reject their markers on any uplink except the selected remote Exit's.
    link_nodes "$CLIENT" cd 10.241.33.1/30 "$DEST" dc 10.241.33.2/30
    link_nodes "$R0" r0d 10.241.34.1/30 "$DEST" dr0 10.241.34.2/30
    link_nodes "$R2" r2d 10.241.35.1/30 "$DEST" dr2 10.241.35.2/30
    ip -n "$CLIENT" route del unreachable 10.241.31.2/32
    ip -n "$CLIENT" route add 10.241.31.2/32 via 10.241.33.2 dev cd src 10.241.33.1
    ip -n "$R0" route add 10.241.31.2/32 via 10.241.34.2 dev r0d src 10.241.34.1
    ip -n "$R2" route add 10.241.31.2/32 via 10.241.35.2 dev r2d src 10.241.35.1
    ip -n "$EXIT_NODE" route add unreachable 43.159.1.1/32
    ip -n "$R0" route add unreachable 45.161.2.1/32
    ip -n "$R2" route add unreachable 42.158.0.1/32
    for reciprocity_pair in "$CLIENT:46.162.3.1" "$EXIT_NODE:43.159.1.1" \
        "$R0:45.161.2.1" "$R2:42.158.0.1"; do
        if ip -n "${reciprocity_pair%:*}" route get "${reciprocity_pair#*:}" \
            >/dev/null 2>&1; then
            fail RECIPROCITY_DIRECT_EXIT_ROUTE_PRESENT
        fi
    done
}

reciprocity_stop_processes() {
    # The finite Python fixtures handle TERM, and KILL bounds cleanup even on fixture failure.
    for reciprocity_pid in $RECIPROCITY_PIDS; do
        kill -TERM "$reciprocity_pid" 2>/dev/null || true
    done
    reciprocity_stop_attempt=0
    while [ "$reciprocity_stop_attempt" -lt 50 ]; do
        reciprocity_alive=no
        for reciprocity_pid in $RECIPROCITY_PIDS; do
            kill -0 "$reciprocity_pid" 2>/dev/null && reciprocity_alive=yes
        done
        [ "$reciprocity_alive" = yes ] || break
        sleep 0.1
        reciprocity_stop_attempt=$((reciprocity_stop_attempt + 1))
    done
    for reciprocity_pid in $RECIPROCITY_PIDS; do
        kill -KILL "$reciprocity_pid" 2>/dev/null || true
        wait "$reciprocity_pid" 2>/dev/null || true
    done
    RECIPROCITY_PIDS=
}

reciprocity_agent_snapshot() {
    reciprocity_stage=$1
    for reciprocity_node in client relay0 relay2 exit; do
        reciprocity_pid=$(systemctl show --property=MainPID --value \
            "volparossa-alpha-agent@$reciprocity_node.service")
        case $reciprocity_pid in ''|0|*[!0-9]*) fail RECIPROCITY_AGENT_PID_INVALID ;; esac
        [ "$(readlink -f -- "/proc/$reciprocity_pid/exe")" = \
            "$binary_directory/volparossa-agent" ] || fail RECIPROCITY_AGENT_EXECUTABLE_INVALID
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$reciprocity_node/control/agent.sock" role show \
            >"$WORK/reciprocity-roles-$reciprocity_node-$reciprocity_stage.txt"
        for reciprocity_role in client relay exit; do
            grep -Fx "$reciprocity_role: true" \
                "$WORK/reciprocity-roles-$reciprocity_node-$reciprocity_stage.txt" >/dev/null \
                || fail RECIPROCITY_COMBINED_ROLE_NOT_ACTIVE
        done
        jq -cn --arg node "$reciprocity_node" --argjson pid "$reciprocity_pid" \
            '{node:$node,agent_pid:$pid,roles:{client:true,relay:true,exit:true}}' \
            >"$WORK/reciprocity-node-$reciprocity_node-$reciprocity_stage.json"
    done
}

reciprocity_wait_file() {
    reciprocity_wait_path=$1
    reciprocity_wait_pid=$2
    reciprocity_wait_attempt=0
    while [ "$reciprocity_wait_attempt" -lt 900 ]; do
        [ ! -s "$reciprocity_wait_path" ] || return 0
        kill -0 "$reciprocity_wait_pid" 2>/dev/null || return 1
        sleep 0.1
        reciprocity_wait_attempt=$((reciprocity_wait_attempt + 1))
    done
    return 1
}

reciprocity_connect() {
    # Subshell callers isolate loop variables. No forced Relay or Exit option is used.
    reciprocity_connect_node=$1
    reciprocity_connect_attempt=0
    reciprocity_connect_seconds=${2:-180}
    case $reciprocity_connect_seconds in ''|*[!0-9]*) return 1 ;; esac
    [ "$reciprocity_connect_seconds" -ge 1 ] && [ "$reciprocity_connect_seconds" -le 180 ] || return 1
    reciprocity_connect_deadline=$(($(date +%s) + reciprocity_connect_seconds))
    reciprocity_cli_pid=
    trap '[ -z "$reciprocity_cli_pid" ] || { kill -TERM "$reciprocity_cli_pid" 2>/dev/null || true; wait "$reciprocity_cli_pid" 2>/dev/null || true; }' EXIT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    trap 'exit 130' INT
    while [ "$reciprocity_connect_attempt" -lt 90 ] \
        && [ "$(date +%s)" -lt "$reciprocity_connect_deadline" ]; do
        reciprocity_cli_timeout=$((reciprocity_connect_deadline - $(date +%s)))
        [ "$reciprocity_cli_timeout" -le 75 ] || reciprocity_cli_timeout=75
        [ "$reciprocity_cli_timeout" -gt 0 ] || return 1
        timeout --kill-after=5 "$reciprocity_cli_timeout" "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$reciprocity_connect_node/control/agent.sock" \
            connect --transport single-path-udp \
            >"$WORK/reciprocity-connect-$reciprocity_connect_node.out" \
            2>"$WORK/reciprocity-connect-$reciprocity_connect_node.err" &
        reciprocity_cli_pid=$!
        if wait "$reciprocity_cli_pid"; then
            reciprocity_cli_pid=
            return 0
        fi
        reciprocity_cli_pid=
        grep -Eq '(PRESELECTION_UNAVAILABLE|NATIVE_.*_UNAVAILABLE|ROUTE_ADMISSION_UNAVAILABLE)' \
            "$WORK/reciprocity-connect-$reciprocity_connect_node.err" || return 1
        sleep 1
        reciprocity_connect_attempt=$((reciprocity_connect_attempt + 1))
    done
    return 1
}

reciprocity_wait_neighbors() {
    reciprocity_mesh_deadline=$(($(date +%s) + 90))
    while [ "$(date +%s)" -lt "$reciprocity_mesh_deadline" ]; do
        reciprocity_mesh_ready=yes
        for reciprocity_mesh_node in client relay0 relay2 exit; do
            "$binary_directory/volparossa" \
                --control-socket "$WORK/runtime-$reciprocity_mesh_node/control/agent.sock" peers \
                >"$WORK/reciprocity-peers-$reciprocity_mesh_node.txt" || return 1
            case $reciprocity_mesh_node in
                client|exit) reciprocity_neighbors="$R0_PEER $R2_PEER" ;;
                relay0|relay2) reciprocity_neighbors="$CLIENT_PEER $EXIT_PEER" ;;
            esac
            for reciprocity_neighbor in $reciprocity_neighbors; do
                awk -v peer="$reciprocity_neighbor" \
                    '$1 == peer && $2 == "roles=0b111" { found=1 } END { exit !found }' \
                    "$WORK/reciprocity-peers-$reciprocity_mesh_node.txt" \
                    || reciprocity_mesh_ready=no
            done
        done
        [ "$reciprocity_mesh_ready" != yes ] || return 0
        sleep 0.2
    done
    return 1
}

reciprocity_run() {
    PHASE=reciprocity-discovery
    install -o root -g root -m 0555 \
        "$source_directory/tests/integration/reciprocity-smoke.py" \
        "$WORK/bin/reciprocity-smoke.py"
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/reciprocity-app"
    reciprocity_agent_snapshot before
    reciprocity_wait_neighbors || fail RECIPROCITY_NEIGHBOR_DISCOVERY_UNAVAILABLE
    # Original alpha destination intentionally remains a separate fixture. Stop it before binding
    # the same exact allowed tuple; the reciprocal server understands four run-bound markers.
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    ip netns exec "$DEST" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/reciprocity-smoke.py" server \
        "$WORK/reciprocity-app" "$RUN_ID" >"$WORK/reciprocity-server.log" 2>&1 &
    reciprocity_server_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $reciprocity_server_pid"
    reciprocity_wait_file "$WORK/reciprocity-app/server.ready" "$reciprocity_server_pid" \
        || fail RECIPROCITY_DESTINATION_NOT_READY

    reciprocity_connect_pids=
    for reciprocity_node in client relay0 relay2 exit; do
        (reciprocity_connect "$reciprocity_node") &
        reciprocity_connect_pids="$reciprocity_connect_pids $!"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $!"
    done
    for reciprocity_pid in $reciprocity_connect_pids; do
        wait "$reciprocity_pid" || fail RECIPROCITY_NATIVE_ROUTE_UNAVAILABLE
    done
    RECIPROCITY_PIDS=$reciprocity_server_pid
    # All route/probe setup is complete before measuring application-window WireGuard packets.
    PHASE=reciprocity-concurrent-udp
    reciprocity_capture_pids=
    reciprocity_client_pids=
    for reciprocity_node in client relay0 relay2 exit; do
        reciprocity_ns=$(reciprocity_namespace "$reciprocity_node")
        ip netns exec "$reciprocity_ns" python3 "$WORK/bin/reciprocity-smoke.py" capture \
            "$WORK" "$RUN_ID" "$reciprocity_node" \
            >"$WORK/reciprocity-capture-$reciprocity_node.log" 2>&1 &
        reciprocity_capture_pid=$!
        reciprocity_capture_pids="$reciprocity_capture_pids $reciprocity_capture_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $reciprocity_capture_pid"
        reciprocity_wait_file "$WORK/reciprocity-capture-$reciprocity_node.ready" \
            "$reciprocity_capture_pid" || fail RECIPROCITY_CAPTURE_NOT_READY
        ip netns exec "$reciprocity_ns" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
            --no-new-privs -- python3 "$WORK/bin/reciprocity-smoke.py" client \
            "$WORK/reciprocity-app" "$RUN_ID" "$reciprocity_node" \
            >"$WORK/reciprocity-client-$reciprocity_node.log" 2>&1 &
        reciprocity_client_pid=$!
        reciprocity_client_pids="$reciprocity_client_pids $reciprocity_client_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $reciprocity_client_pid"
        printf '%s\n' "$reciprocity_client_pid" >"$WORK/reciprocity-pid-$reciprocity_node.txt"
    done
    printf 'go\n' >"$WORK/reciprocity-app/go"
    for reciprocity_node in client relay0 relay2 exit; do
        reciprocity_wait_file "$WORK/reciprocity-app/$reciprocity_node.active" \
            "$(cat "$WORK/reciprocity-pid-$reciprocity_node.txt")" \
            || fail RECIPROCITY_APPLICATION_ECHO_UNAVAILABLE
    done
    # The clients continue normal application datagrams throughout every role/path snapshot.
    sleep 3
    for reciprocity_node in client relay0 relay2 exit; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$reciprocity_node/control/agent.sock" paths \
            >"$WORK/reciprocity-paths-$reciprocity_node.txt"
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$reciprocity_node/control/agent.sock" sessions \
            >"$WORK/reciprocity-sessions-$reciprocity_node.txt"
    done
    reciprocity_agent_snapshot after
    printf 'stop\n' >"$WORK/reciprocity-app/stop"
    for reciprocity_pid in $reciprocity_client_pids; do
        wait "$reciprocity_pid" || fail RECIPROCITY_APPLICATION_FAILED
    done
    for reciprocity_pid in $reciprocity_capture_pids "$reciprocity_server_pid"; do
        kill -TERM "$reciprocity_pid" || fail RECIPROCITY_OBSERVER_EARLY_EXIT
    done
    for reciprocity_pid in $reciprocity_capture_pids "$reciprocity_server_pid"; do
        wait "$reciprocity_pid" || fail RECIPROCITY_OBSERVER_FAILED
    done
    RECIPROCITY_PIDS=
    python3 "$WORK/bin/reciprocity-smoke.py" evidence "$WORK" "$RUN_ID" \
        || fail RECIPROCITY_EVIDENCE_INVALID
    PHASE=reciprocity-complete
    OBSERVED_BLOCKER=
}

reciprocity_finalize_report() {
    reciprocity_status=$1
    reciprocity_evidence='{"success":false,"flows":[],"nodes":[],"reciprocal_witnesses":[]}'
    [ ! -s "$WORK/reciprocity-evidence.json" ] \
        || reciprocity_evidence=$(cat "$WORK/reciprocity-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$reciprocity_status" --argjson evidence "$reciprocity_evidence" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" \
        '$evidence + {schema_version:1,report_kind:"volparossa-reciprocal-node-runtime",
          source_revision:$revision,run_id:$run_id,phase:$phase,
          success:($status == 0 and $evidence.success and $complete and
            $remaining == 0 and $host[0].unchanged),
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:{complete:$complete,remaining_owned_objects:$remaining},
          host_state:($host[0] | del(.acceptance_id)),
          scope:"four concurrent genuine single-path UDP routes; not A01-A15"}' \
        >"$WORK/reciprocity-smoke.json"
    for reciprocity_artifact in "$WORK"/reciprocity-*.json "$WORK"/reciprocity-*.txt \
        "$WORK"/reciprocity-*.log "$WORK"/reciprocity-*.out "$WORK"/reciprocity-*.err \
        "$WORK"/mpquic-*-client.log "$WORK"/mpquic-*-exit.log; do
        [ -f "$reciprocity_artifact" ] && [ ! -L "$reciprocity_artifact" ] || continue
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$reciprocity_artifact" \
            "$output_directory/$(basename -- "$reciprocity_artifact")"
    done
    for reciprocity_artifact in "$WORK"/reciprocity-app/*.json; do
        [ -f "$reciprocity_artifact" ] && [ ! -L "$reciprocity_artifact" ] || continue
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$reciprocity_artifact" \
            "$output_directory/reciprocity-app-$(basename -- "$reciprocity_artifact")"
    done
    jq -e '.success == true' "$WORK/reciprocity-smoke.json" >/dev/null
}
