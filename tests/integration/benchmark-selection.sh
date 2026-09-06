#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced by the disposable KVM runner, never changes production selection policy.
# shellcheck disable=SC2154

wait_disconnected() {
    idle_attempt=0
    while [ "$idle_attempt" -lt 300 ]; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" status \
            >"$WORK/status-client.txt" 2>/dev/null || true
        if grep -Fx 'connected: false' "$WORK/status-client.txt" >/dev/null \
            && grep -Fx 'active contexts: 0' "$WORK/status-client.txt" >/dev/null; then
            return 0
        fi
        sleep 0.1
        idle_attempt=$((idle_attempt + 1))
    done
    return 1
}

a01_transient_connect_unavailable() {
    grep -Eq '^Error: agent rejected request: (PRESELECTION_UNAVAILABLE|NATIVE_PERMIT_UNAVAILABLE|NATIVE_RELAY_READY_UNAVAILABLE|NATIVE_HELPER_COMMIT_UNAVAILABLE|NATIVE_PROBE_START_UNAVAILABLE|NATIVE_PROBE_PROOF_UNAVAILABLE|ROUTE_ADMISSION_UNAVAILABLE) \(Unavailable\)$' "$1"
}

benchmark_capture_paths() {
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/$1-paths.txt" || return 3
    python3 -B "$source_directory/tests/integration/benchmark-paths.py" \
        "$WORK/$1-paths.txt" "$WORK/$1-selection.json" \
        "$R0_PEER" "$R1_PEER" "$R2_PEER" "$EXIT_PEER" "$2"
}

benchmark_disconnect_route() {
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" disconnect \
        >"$WORK/$1-disconnect.out" 2>"$WORK/$1-disconnect.err" || return 1
    wait_disconnected
}

benchmark_select_route() {
    benchmark_label=$1
    benchmark_transport=$2
    benchmark_deadline=$(($(date +%s) + 600))
    benchmark_attempt=0
    benchmark_draw=0
    while [ "$benchmark_attempt" -lt 360 ] && [ "$benchmark_draw" -lt 32 ]; do
        benchmark_remaining=$((benchmark_deadline - $(date +%s)))
        [ "$benchmark_remaining" -gt 0 ] || return 1
        if timeout --signal=TERM --kill-after=5s "${benchmark_remaining}s" \
            "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" connect \
            --transport "$benchmark_transport" >"$WORK/$benchmark_label-connect.out" \
            2>"$WORK/$benchmark_label-connect.err"; then
            benchmark_poll=0
            while [ "$benchmark_poll" -lt 100 ]; do
                benchmark_snapshot_status=0
                benchmark_capture_paths "$benchmark_label" "$benchmark_transport" \
                    || benchmark_snapshot_status=$?
                [ "$benchmark_snapshot_status" -eq 1 ] || break
                sleep 0.1
                benchmark_poll=$((benchmark_poll + 1))
            done
            case $benchmark_snapshot_status in
                0|2)
                    jq -c --arg label "$benchmark_label" --argjson draw "$benchmark_draw" \
                        '. + {benchmark:$label,draw:$draw}' \
                        "$WORK/$benchmark_label-selection.json" \
                        >>"$WORK/benchmark-selection-draws.jsonl" || return 1
                    ;;
                *) return 1 ;;
            esac
            [ "$benchmark_snapshot_status" -ne 0 ] || return 0
            # A valid different pair is not a product failure. No application exists yet.
            benchmark_disconnect_route "$benchmark_label" || return 1
            benchmark_draw=$((benchmark_draw + 1))
        else
            a01_transient_connect_unavailable "$WORK/$benchmark_label-connect.err" || return 1
        fi
        benchmark_attempt=$((benchmark_attempt + 1))
        sleep 1
    done
    return 1
}
