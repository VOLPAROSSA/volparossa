#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced by the disposable KVM runner, never changes production selection policy.
# shellcheck disable=SC2154

wait_disconnected() {
    idle_attempt=0
    while [ "$idle_attempt" -lt 300 ]; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-${BENCHMARK_NODE:-client}/control/agent.sock" status \
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
    case "${scenario:-alpha}:$2" in
        mixed-link:multipath-quic) benchmark_pair_option=--lan-pair ;;
        *:multipath-quic|*:mptcp) benchmark_pair_option=--any-pair ;;
        *) benchmark_pair_option= ;;
    esac
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-${BENCHMARK_NODE:-client}/control/agent.sock" paths \
        >"$WORK/$1-paths.txt" || return 3
    python3 -B "$source_directory/tests/integration/benchmark-paths.py" \
        "$WORK/$1-paths.txt" "$WORK/$1-selection.json" \
        "$R0_PEER" "$R1_PEER" "$R2_PEER" "$EXIT_PEER" "$2" \
        ${benchmark_pair_option:+"$benchmark_pair_option"}
}

# shellcheck disable=SC2034 # Independent immutable native slots survive later MPTCP draws.
native_bind_slots() {
    benchmark_bind_slots "$1" || return 1
    NATIVE_SELECTION_FILE=$1
    NATIVE_CONTEXT=$(jq -er '.route_context_id' "$1") || return 1
    NATIVE_PEER1=$(jq -er '.benchmark_slots[0].relay_peer_id' "$1") || return 1
    NATIVE_PEER2=$(jq -er '.benchmark_slots[1].relay_peer_id' "$1") || return 1
    NATIVE_INDEX1=$BENCH_INDEX1; NATIVE_INDEX2=$BENCH_INDEX2
    NATIVE_NODE1=$BENCH_NODE1; NATIVE_NODE2=$BENCH_NODE2
    NATIVE_NS1=$BENCH_NS1; NATIVE_NS2=$BENCH_NS2
    NATIVE_CLIENT_IF1=$BENCH_CLIENT_IF1; NATIVE_CLIENT_IF2=$BENCH_CLIENT_IF2
    NATIVE_RELAY_IF1=$BENCH_RELAY_IF1; NATIVE_RELAY_IF2=$BENCH_RELAY_IF2
    NATIVE_EXIT_LEG1=$BENCH_EXIT_LEG1; NATIVE_EXIT_LEG2=$BENCH_EXIT_LEG2
    NATIVE_EXIT_IF1=$BENCH_EXIT_IF1; NATIVE_EXIT_IF2=$BENCH_EXIT_IF2
    NATIVE_PUBLIC1=$BENCH_PUBLIC1; NATIVE_PUBLIC2=$BENCH_PUBLIC2
    NATIVE_CLIENT_HOP1=$BENCH_CLIENT_HOP1; NATIVE_CLIENT_HOP2=$BENCH_CLIENT_HOP2
    NATIVE_EXIT_HOP1=$BENCH_EXIT_HOP1; NATIVE_EXIT_HOP2=$BENCH_EXIT_HOP2
}

# Select only from the three immutable disposable topology bindings. Never overwrite R0/R1/R2:
# those globals also own teardown, discovery contacts, and the later native benchmarks.
# shellcheck disable=SC2034 # BENCH_* is consumed by the sourcing KVM runner.
benchmark_bind_slots() {
    BENCH_INDEX1=$(jq -er '.benchmark_slots[0].relay_index' "$1") || return 1
    BENCH_INDEX2=$(jq -er '.benchmark_slots[1].relay_index' "$1") || return 1
    [ "$BENCH_INDEX1" != "$BENCH_INDEX2" ] || return 1
    for benchmark_slot in 1 2; do
        if [ "$benchmark_slot" = 1 ]; then benchmark_index=$BENCH_INDEX1
        else benchmark_index=$BENCH_INDEX2; fi
        case $benchmark_index in
            0) benchmark_ns=$R0; benchmark_public=42.158.0.1 ;;
            1) benchmark_ns=$R1; benchmark_public=44.160.1.1 ;;
            2) benchmark_ns=$R2; benchmark_public=45.161.2.1 ;;
            *) return 1 ;;
        esac
        if [ "$benchmark_slot" = 1 ]; then
            BENCH_NS1=$benchmark_ns; BENCH_PUBLIC1=$benchmark_public
            BENCH_NODE1=relay$benchmark_index; BENCH_CLIENT_IF1=cr$benchmark_index
            BENCH_RELAY_IF1=r${benchmark_index}c; BENCH_EXIT_LEG1=r${benchmark_index}x
            BENCH_EXIT_IF1=xr$benchmark_index
            BENCH_CLIENT_HOP1=10.241.$((10 + benchmark_index)).1
            BENCH_EXIT_HOP1=10.241.$((20 + benchmark_index)).2
        else
            BENCH_NS2=$benchmark_ns; BENCH_PUBLIC2=$benchmark_public
            BENCH_NODE2=relay$benchmark_index; BENCH_CLIENT_IF2=cr$benchmark_index
            BENCH_RELAY_IF2=r${benchmark_index}c; BENCH_EXIT_LEG2=r${benchmark_index}x
            BENCH_EXIT_IF2=xr$benchmark_index
            BENCH_CLIENT_HOP2=10.241.$((10 + benchmark_index)).1
            BENCH_EXIT_HOP2=10.241.$((20 + benchmark_index)).2
        fi
    done
}

benchmark_disconnect_route() {
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-${BENCHMARK_NODE:-client}/control/agent.sock" disconnect \
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
            --control-socket "$WORK/runtime-${BENCHMARK_NODE:-client}/control/agent.sock" connect \
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
