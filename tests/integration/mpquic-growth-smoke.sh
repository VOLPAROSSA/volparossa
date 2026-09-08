#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Only sourced by the guarded disposable KVM runner; never invokes a host-network command.
# shellcheck disable=SC2154,SC2034

mpquic_growth_cleanup() {
    [ "${growth_loss_owned:-false}" = true ] || return 0
    case ${growth_loss_interface:-} in r0x|r1x|r2x) ;; *) return 1 ;; esac
    [ -n "${growth_loss_ns:-}" ] || return 1
    ip netns exec "$growth_loss_ns" tc -j qdisc show dev "$growth_loss_interface" \
        >"$WORK/mpquic-growth-qdisc-cleanup.json" || return 1
    if jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
        "$WORK/mpquic-growth-qdisc-cleanup.json" >/dev/null; then
        growth_loss_owned=false
        return 0
    fi
    jq -e 'length == 1 and .[0].kind == "netem" and .[0].handle == "7a01:"' \
        "$WORK/mpquic-growth-qdisc-cleanup.json" >/dev/null || return 1
    ip netns exec "$growth_loss_ns" tc qdisc del dev "$growth_loss_interface" root handle 7a01: \
        || return 1
    growth_loss_owned=false
}

mpquic_growth_snapshot() {
    timeout --signal=TERM --kill-after=1s 5s "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/mpquic-growth-$1.txt" 2>"$WORK/mpquic-growth-$1.err" || return 1
    python3 -B "$source_directory/tests/integration/mpquic-growth-smoke.py" sample \
        "$WORK/mpquic-growth-$1.txt" "$WORK/mpquic-growth-selection.json" \
        "$WORK/mpquic-growth-$1.json"
}

mpquic_growth_select() {
    growth_deadline=$(($(date +%s) + 600))
    growth_draw=0
    growth_attempt=0
    while [ "$growth_draw" -lt 32 ] && [ "$growth_attempt" -lt 360 ]; do
        growth_remaining=$((growth_deadline - $(date +%s)))
        [ "$growth_remaining" -gt 0 ] || return 1
        if timeout --signal=TERM --kill-after=5s "${growth_remaining}s" "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" connect --transport multipath-quic \
            >"$WORK/mpquic-growth-connect.out" 2>"$WORK/mpquic-growth-connect.err"; then
            growth_poll=0
            while [ "$growth_poll" -lt 100 ] && [ "$(date +%s)" -lt "$growth_deadline" ]; do
                "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
                    >"$WORK/mpquic-growth-selection.txt" || return 1
                if python3 -B "$source_directory/tests/integration/mpquic-growth-smoke.py" select \
                    "$WORK/mpquic-growth-selection.txt" "$WORK/a01-expected-peers.json" \
                    "$WORK/mpquic-growth-selection.json" 2>"$WORK/mpquic-growth-selection.err"; then
                    return 0
                fi
                sleep 0.1
                growth_poll=$((growth_poll + 1))
            done
            benchmark_disconnect_route mpquic-growth-draw || return 1
            growth_draw=$((growth_draw + 1))
        else
            a01_transient_connect_unavailable "$WORK/mpquic-growth-connect.err" || return 1
        fi
        growth_attempt=$((growth_attempt + 1))
        sleep 1
    done
    return 1
}

mpquic_growth_wait_progress() {
    growth_progress_attempt=0
    while [ "$growth_progress_attempt" -lt 300 ]; do
        kill -0 "$HTTP3_CLIENT_PID" 2>/dev/null || return 1
        if mpquic_growth_snapshot "$2" \
            && python3 -B "$source_directory/tests/integration/mpquic-growth-smoke.py" progress \
                "$WORK/mpquic-growth-$1.json" "$WORK/mpquic-growth-$2.json" "$3" \
                2>"$WORK/mpquic-growth-progress.err"; then
            return 0
        fi
        sleep 0.1
        growth_progress_attempt=$((growth_progress_attempt + 1))
    done
    return 1
}

mpquic_growth_run() {
    PHASE=mpquic-growth-selection
    mpquic_growth_select || fail MPQUIC_GROWTH_ROUTE_UNAVAILABLE
    jq -n --arg run "$RUN_ID" '{run_id:$run}' >"$WORK/mpquic-growth-run.json"
    growth_loss_path=$(jq -er '[.paths[] | select(.state == 3)][0].path_id' "$WORK/mpquic-growth-selection.json")
    growth_loss_peer=$(jq -er --argjson id "$growth_loss_path" \
        '.paths[] | select(.path_id == $id) | .relay_peer_id' "$WORK/mpquic-growth-selection.json")
    growth_loss_node=$(jq -er --arg peer "$growth_loss_peer" \
        'to_entries[] | select(.value == $peer) | .key' "$WORK/a01-expected-peers.json")
    case $growth_loss_node in
        relay0) growth_loss_ns=$R0; growth_loss_interface=r0x ;;
        relay1) growth_loss_ns=$R1; growth_loss_interface=r1x ;;
        relay2) growth_loss_ns=$R2; growth_loss_interface=r2x ;;
        *) fail MPQUIC_GROWTH_LOSS_TARGET_INVALID ;;
    esac
    ip netns exec "$growth_loss_ns" tc -j -s qdisc show dev "$growth_loss_interface" \
        >"$WORK/mpquic-growth-qdisc-before.json" || fail MPQUIC_GROWTH_QDISC_UNAVAILABLE
    python3 -B "$source_directory/tests/integration/mpquic-growth-smoke.py" qdisc \
        "$WORK/mpquic-growth-qdisc-before.json" plain || fail MPQUIC_GROWTH_LINK_ALREADY_SHAPED
    jq -n --arg node "$growth_loss_node" --arg interface "$growth_loss_interface" \
        --argjson path "$growth_loss_path" \
        '{relay_node:$node,interface:$interface,path_id:$path,loss_percent:15}' \
        >"$WORK/mpquic-growth-injection.json"

    PHASE=mpquic-growth-http3-start
    timeout --signal=TERM --kill-after=5s 240s \
        ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
        --bounding-set=+net_bind_service --no-new-privs -- \
        "$WORK/bin/examples/http3-acceptance-fixture" server \
        47.163.4.2:443 "$WORK/destination/mpquic-growth-cert.der" \
        "$WORK/destination/mpquic-growth-server.ready" "$WORK/destination" "$RUN_ID" mpquic-growth \
        >"$WORK/mpquic-growth-server.log" 2>&1 &
    HTTP3_SERVER_PID=$!
    growth_attempt=0
    while [ "$growth_attempt" -lt 100 ]; do
        [ -s "$WORK/destination/mpquic-growth-server.ready" ] && break
        kill -0 "$HTTP3_SERVER_PID" 2>/dev/null || break
        sleep 0.1
        growth_attempt=$((growth_attempt + 1))
    done
    [ -s "$WORK/destination/mpquic-growth-server.ready" ] || fail MPQUIC_GROWTH_SERVER_UNAVAILABLE
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
        "$WORK/destination/mpquic-growth-cert.der" "$WORK/client-fixtures/mpquic-growth-cert.der"
    start_privacy_observers mpquic-growth-initial-privacy || fail MPQUIC_GROWTH_CAPTURE_UNAVAILABLE
    timeout --signal=TERM --kill-after=5s 200s \
        ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        "$WORK/bin/examples/http3-acceptance-fixture" client mpquic-growth \
        43.159.1.1:52008 47.163.4.2:443 "$WORK/client-fixtures/mpquic-growth-cert.der" \
        "$RUN_ID" "$WORK/client-fixtures/mpquic-growth-client.json" \
        >"$WORK/mpquic-growth-client.log" 2>"$WORK/mpquic-growth-client.err" &
    HTTP3_CLIENT_PID=$!
    mpquic_growth_wait_progress selection before-loss 2 || fail MPQUIC_GROWTH_INITIAL_PAYLOAD_MISSING

    PHASE=mpquic-growth-sustained-loss
    # The exact selected Relay->Exit egress drops genuine upload packets, never duplicates them.
    # No prior qdisc is replaced and no host or other namespace link is touched.
    growth_loss_owned=true
    ip netns exec "$growth_loss_ns" tc qdisc add dev "$growth_loss_interface" root handle 7a01: \
        netem loss random 15% || fail MPQUIC_GROWTH_LOSS_INSTALL_FAILED
    growth_attempt=0
    while [ "$growth_attempt" -lt 450 ]; do
        kill -0 "$HTTP3_CLIENT_PID" 2>/dev/null || fail MPQUIC_GROWTH_FLOW_ENDED_BEFORE_GROWTH
        if mpquic_growth_snapshot expanded \
            && jq -e '(.paths | length) == 3 and all(.paths[]; .state == 3)' \
                "$WORK/mpquic-growth-expanded.json" >/dev/null; then
            break
        fi
        sleep 0.1
        growth_attempt=$((growth_attempt + 1))
    done
    [ "$growth_attempt" -lt 450 ] || fail MPQUIC_GROWTH_THIRD_PATH_NOT_ACTIVE
    stop_privacy_observers || fail MPQUIC_GROWTH_INITIAL_CAPTURE_NOT_DRAINED
    start_privacy_observers mpquic-growth-expanded-privacy || fail MPQUIC_GROWTH_CAPTURE_UNAVAILABLE
    # Refresh the baseline after these capture sockets are live, excluding earlier counters.
    mpquic_growth_snapshot expanded || fail MPQUIC_GROWTH_EXPANDED_BASELINE_UNAVAILABLE
    mpquic_growth_wait_progress expanded expanded-progress 3 || fail MPQUIC_GROWTH_THIRD_PAYLOAD_MISSING
    stop_privacy_observers || fail MPQUIC_GROWTH_EXPANDED_CAPTURE_NOT_DRAINED
    ip netns exec "$growth_loss_ns" tc -j -s qdisc show dev "$growth_loss_interface" \
        >"$WORK/mpquic-growth-qdisc-during.json" || fail MPQUIC_GROWTH_QDISC_UNAVAILABLE
    mpquic_growth_cleanup || fail MPQUIC_GROWTH_LOSS_CLEANUP_FAILED
    ip netns exec "$growth_loss_ns" tc -j -s qdisc show dev "$growth_loss_interface" \
        >"$WORK/mpquic-growth-qdisc-after.json" || fail MPQUIC_GROWTH_QDISC_UNAVAILABLE
    mpquic_growth_snapshot after-restore || fail MPQUIC_GROWTH_RESTORED_PATHS_UNAVAILABLE

    PHASE=mpquic-growth-completion
    growth_client_status=0
    wait "$HTTP3_CLIENT_PID" || growth_client_status=$?
    HTTP3_CLIENT_PID=
    [ "$growth_client_status" -eq 0 ] || fail MPQUIC_GROWTH_HTTP3_FAILED
    growth_server_status=0
    wait "$HTTP3_SERVER_PID" || growth_server_status=$?
    HTTP3_SERVER_PID=
    [ "$growth_server_status" -eq 0 ] || fail MPQUIC_GROWTH_SERVER_COMPLETION_FAILED
    install -o root -g root -m 0600 "$WORK/client-fixtures/mpquic-growth-client.json" \
        "$WORK/mpquic-growth-client.json"
    install -o root -g root -m 0600 "$WORK/destination/server-mpquic-growth.json" \
        "$WORK/mpquic-growth-server.json"
    benchmark_disconnect_route mpquic-growth || fail MPQUIC_GROWTH_RETIREMENT_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/mpquic-growth-final-status.txt" || fail MPQUIC_GROWTH_RETIREMENT_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/mpquic-growth-final-paths.txt" || fail MPQUIC_GROWTH_RETIREMENT_FAILED
    jq -n '{client_exit_status:0,server_exit_status:0,route_disconnected:true,
        active_contexts:0,paths_empty:true,loss_removed:true}' >"$WORK/mpquic-growth-cleanup.json"
    python3 -B "$source_directory/tests/integration/mpquic-growth-smoke.py" evidence \
        "$WORK" "$WORK/mpquic-growth-evidence.json" || fail MPQUIC_GROWTH_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=mpquic-growth-complete
}
