#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Measured Core and consumer phases on the same UDP-only control matrix. Caller owns the disposable namespaces and EXIT trap.
# shellcheck disable=SC2154,SC2034

storage_consumer_stop_captures() {
    consumer_capture_status=0
    for consumer_pid in "$CONSUMER_CONTROL_0_PID" "$CONSUMER_CONTROL_1_PID" "$CONSUMER_CONTROL_2_PID"; do
        [ -z "$consumer_pid" ] || kill -TERM "$consumer_pid" 2>/dev/null || true
    done
    for consumer_pid in "$CONSUMER_CONTROL_0_PID" "$CONSUMER_CONTROL_1_PID" "$CONSUMER_CONTROL_2_PID"; do
        if [ -n "$consumer_pid" ] && ! wait "$consumer_pid"; then consumer_capture_status=1; fi
    done
    CONSUMER_CONTROL_0_PID=; CONSUMER_CONTROL_1_PID=; CONSUMER_CONTROL_2_PID=
    return "$consumer_capture_status"
}

storage_consumer_start_captures() {
    case $1 in storage-consumer-publish|storage-consumer-exercise|storage-consumer-finish|private-storage-core-restore|private-storage-core-finish) ;; *) return 1 ;; esac
    [ "${private_storage_maintenance:-no}" = yes ] && [ -z "$PROVIDER_CONTROL_PID" ] \
        && [ -z "$CONSUMER_CONTROL_0_PID$CONSUMER_CONTROL_1_PID$CONSUMER_CONTROL_2_PID" ] || return 1
    for consumer_capture_b in 0 1 2; do
        content_provider_node "relay$consumer_capture_b" || return 1
        consumer_capture_ns=$provider_ns; consumer_capture_ips=$provider_ip
        for consumer_capture_provider in relay3 relay4 relay5; do
            content_provider_node "$consumer_capture_provider" || return 1
            consumer_capture_ips=$consumer_capture_ips,$provider_ip
        done
        consumer_capture_prefix=$1-control-relay$consumer_capture_b
        ip netns exec "$consumer_capture_ns" python3 "$WORK/bin/privacy-observer.py" \
            content-control "$WORK/$consumer_capture_prefix.json" "$WORK/$consumer_capture_prefix.ready" \
            --content-providers "--consumer-control=relay$consumer_capture_b" \
            "--content-control=$consumer_capture_ips" "cc${consumer_capture_b}0" "cc${consumer_capture_b}1" "cc${consumer_capture_b}2" \
            >"$WORK/$consumer_capture_prefix.log" 2>&1 &
        consumer_capture_pid=$!
        case $consumer_capture_b in
            0) CONSUMER_CONTROL_0_PID=$consumer_capture_pid ;;
            1) CONSUMER_CONTROL_1_PID=$consumer_capture_pid ;;
            2) CONSUMER_CONTROL_2_PID=$consumer_capture_pid ;;
        esac
        # Store each PID before readiness can fail; outer EXIT owns all children.
        wait_observer "$consumer_capture_pid" "$WORK/$consumer_capture_prefix.ready" || return 1
    done
}

storage_consumer_readback() {
    case $1 in before|after) consumer_readback_stage=$1 ;; *) return 1 ;; esac
    storage_consumer_control_snapshot after || return 1
    consumer_readback=$WORK/$consumer_control_prefix-control-$consumer_readback_stage.json
    [ ! -e "$consumer_readback" ] && [ ! -L "$consumer_readback" ] || return 1
    jq -cSj '.' "$WORK/consumer-control-after.private" >"$consumer_readback" || return 1
    chmod 0600 "$consumer_readback" || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" readback "$WORK" "$consumer_readback"
}

storage_consumer_phase_start() {
    case ${1:-consumer} in
        consumer)
            storage_phase=consumer-$consumer_phase
            consumer_control_prefix=storage-consumer-$consumer_phase ;;
        restore|finish)
            storage_phase=$1
            consumer_control_prefix=private-storage-core-$storage_phase ;;
        *) return 1 ;;
    esac
    storage_consumer_readback before || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" layout "$WORK" \
        >"$WORK/private-storage-fragments-$storage_phase-layout.json" || return 1
    consumer_route_policy=$(jq -c '.route_policy' "$WORK/private-storage-fragments-$storage_phase-layout.json") || return 1
    consumer_underlay_sha=$(jq -er '.control_underlay_sha256' "$WORK/private-storage-fragments-$storage_phase-layout.json") || return 1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || return 1
    start_privacy_observers "private-storage-fragments-$storage_phase-privacy" || return 1
    storage_consumer_start_captures "$consumer_control_prefix"
}

storage_core_control_receipt() {
    case $1 in restore|finish) ;; *) return 1 ;; esac
    core_capture=$WORK/private-storage-core-$1-control
    core_receipt=$WORK/content-provider-adaptive-private-storage-fragments-$1-control.json
    for core_broker in relay0 relay1 relay2; do
        [ -f "$core_capture-$core_broker.json" ] && [ ! -L "$core_capture-$core_broker.json" ] || return 1
    done
    jq -cS -n --slurpfile r0 "$core_capture-relay0.json" --slurpfile r1 "$core_capture-relay1.json" \
        --slurpfile r2 "$core_capture-relay2.json" \
        'if ([$r0,$r1,$r2] | all(length == 1)) then {relay0:$r0[0],relay1:$r1[0],relay2:$r2[0]} else error("incomplete control capture") end' \
        >"$core_receipt.part" && mv -- "$core_receipt.part" "$core_receipt"
}

storage_consumer_phase_finish() {
    benchmark_capture_paths "private-storage-fragments-$storage_phase-live" mptcp || return 1
    python3 -B "$WORK/bin/storage-consumer-network.py" route-check "$WORK" \
        "$WORK/private-storage-fragments-$storage_phase-live-selection.json" \
        "$storage_user/flow-$storage_phase.json" || return 1
    storage_consumer_readback after || return 1
    # Join every owned capture even when one fails. Outer trap retains safety
    # cleanup on earlier route/readback failure; none of that becomes success.
    consumer_network_status=0
    stop_privacy_observers || consumer_network_status=1
    storage_consumer_stop_captures || consumer_network_status=1
    [ "$consumer_network_status" -eq 0 ] || return 1
    case $storage_phase in
        restore|finish) storage_core_control_receipt "$storage_phase" || return 1 ;;
    esac
    python3 -B "$WORK/bin/storage-consumer-network.py" gates "$WORK" \
        "$storage_user/flow-$storage_phase.json" "$provider_baseline_ms" "$1" \
        >"$WORK/private-storage-fragments-$storage_phase-gates.json"
}
