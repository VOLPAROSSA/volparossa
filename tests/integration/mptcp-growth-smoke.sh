#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicitly approved disposable KVM runner.
# shellcheck disable=SC2154,SC2034

mptcp_growth_check() {
    python3 -B "$source_directory/tests/integration/mptcp-growth-smoke.py" "$@"
}

mptcp_growth_cleanup() {
    if [ "${mptcp_loss_owned:-false}" = true ]; then
        case ${mptcp_loss_interface:-} in xr0|xr1|xr2) ;; *) return 1 ;; esac
        ip netns exec "$EXIT_NODE" tc -j -s qdisc show dev "$mptcp_loss_interface" \
            >"$WORK/mptcp-growth-qdisc-cleanup.json" || return 1
        if jq -e 'length == 1 and .[0].kind == "netem" and .[0].handle == "7a01:"' \
            "$WORK/mptcp-growth-qdisc-cleanup.json" >/dev/null; then
            ip netns exec "$EXIT_NODE" tc qdisc del dev "$mptcp_loss_interface" root handle 7a01: || return 1
        else
            jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
                "$WORK/mptcp-growth-qdisc-cleanup.json" >/dev/null || return 1
        fi
        mptcp_loss_owned=false
    fi
    for mptcp_rate_node in ${mptcp_rate_owned:-}; do
        case $mptcp_rate_node in
            0) mptcp_rate_ns=$R0 ;; 1) mptcp_rate_ns=$R1 ;; 2) mptcp_rate_ns=$R2 ;; *) return 1 ;;
        esac
        ip netns exec "$mptcp_rate_ns" tc -j -s qdisc show dev "r${mptcp_rate_node}c" \
            >"$WORK/mptcp-growth-rate-$mptcp_rate_node-cleanup.json" || return 1
        if jq -e 'length == 1 and .[0].kind == "tbf" and .[0].handle == "7a02:"' \
            "$WORK/mptcp-growth-rate-$mptcp_rate_node-cleanup.json" >/dev/null; then
            ip netns exec "$mptcp_rate_ns" tc qdisc del dev "r${mptcp_rate_node}c" root handle 7a02: || return 1
        else
            jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
                "$WORK/mptcp-growth-rate-$mptcp_rate_node-cleanup.json" >/dev/null || return 1
        fi
        ip netns exec "$mptcp_rate_ns" tc -j qdisc show dev "r${mptcp_rate_node}c" \
            >"$WORK/mptcp-growth-rate-$mptcp_rate_node-after.json" || return 1
    done
    mptcp_rate_owned=
}

mptcp_growth_select() {
    mptcp_deadline=$(($(date +%s) + 600))
    mptcp_draw=0
    mptcp_attempt=0
    while [ "$mptcp_draw" -lt 32 ] && [ "$mptcp_attempt" -lt 360 ]; do
        mptcp_remaining=$((mptcp_deadline - $(date +%s)))
        [ "$mptcp_remaining" -gt 0 ] || return 1
        if timeout --signal=TERM --kill-after=5s "${mptcp_remaining}s" "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" connect --transport mptcp \
            >"$WORK/mptcp-growth-connect.out" 2>"$WORK/mptcp-growth-connect.err"; then
            "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
                >"$WORK/mptcp-growth-selection.txt" || return 1
            if mptcp_growth_check select "$WORK/mptcp-growth-selection.txt" "$WORK/a01-expected-peers.json" \
                "$WORK/mptcp-growth-selection.json" 2>"$WORK/mptcp-growth-selection.err"; then
                mptcp_context=$(jq -er '.route_context_id' "$WORK/mptcp-growth-selection.json") || return 1
                "$WORK/bin/examples/http3-acceptance-fixture" route-layout "$mptcp_context" \
                    >"$WORK/mptcp-growth-layout.json" || return 1
                if mptcp_growth_check owners "$WORK/mptcp-growth-layout.json" "$WORK/mptcp-growth-owners.json" \
                    2>"$WORK/mptcp-growth-owners.err" \
                    && jq -e 'all(.[]; ([.paths[].relay_node] | sort) == ["relay0","relay1","relay2"])' \
                        "$WORK/mptcp-growth-owners.json" >/dev/null; then
                    return 0
                fi
            fi
            benchmark_disconnect_route mptcp-growth-draw || return 1
            mptcp_draw=$((mptcp_draw + 1))
        else
            a01_transient_connect_unavailable "$WORK/mptcp-growth-connect.err" || return 1
        fi
        mptcp_attempt=$((mptcp_attempt + 1))
        sleep 1
    done
    return 1
}

mptcp_growth_sample() {
    mptcp_growth_check sample "$WORK/mptcp-growth-owners.json" "$WORK/mptcp-growth-layout.json" \
        "$WORK/mptcp-growth-$1.json" 2>"$WORK/mptcp-growth-sample.err"
}

mptcp_growth_progress() {
    mptcp_poll=0
    while [ "$mptcp_poll" -lt 300 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || return 1
        if mptcp_growth_sample "$2" \
            && mptcp_growth_check progress "$WORK/mptcp-growth-$1.json" "$WORK/mptcp-growth-$2.json" "$3" \
                2>"$WORK/mptcp-growth-progress.err"; then return 0; fi
        sleep 0.1
        mptcp_poll=$((mptcp_poll + 1))
    done
    return 1
}

mptcp_growth_run() {
    PHASE=mptcp-growth-selection
    mptcp_growth_select || fail MPTCP_GROWTH_ROUTE_UNAVAILABLE
    jq -n --arg run "$RUN_ID" '{run_id:$run}' >"$WORK/mptcp-growth-run.json"
    mptcp_loss_path=$(jq -er '.paths[0].path_id' "$WORK/mptcp-growth-selection.json")
    mptcp_loss_node=$(jq -er --argjson path "$mptcp_loss_path" \
        '.exit.paths[] | select(.path_id == $path) | .relay_node' "$WORK/mptcp-growth-owners.json")
    case $mptcp_loss_node in relay0|relay1|relay2) ;; *) fail MPTCP_GROWTH_LOSS_TARGET_INVALID ;; esac
    mptcp_loss_interface=xr${mptcp_loss_node#relay}
    ip netns exec "$EXIT_NODE" tc -j -s qdisc show dev "$mptcp_loss_interface" \
        >"$WORK/mptcp-growth-qdisc-before.json" || fail MPTCP_GROWTH_QDISC_UNAVAILABLE
    jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
        "$WORK/mptcp-growth-qdisc-before.json" >/dev/null || fail MPTCP_GROWTH_PREEXISTING_QDISC
    jq -n --arg node "$mptcp_loss_node" --arg interface "$mptcp_loss_interface" --argjson path "$mptcp_loss_path" \
        '{relay_node:$node,interface:$interface,path_id:$path,namespace_role:"exit",loss_percent:15}' \
        >"$WORK/mptcp-growth-injection.json"
    # Existing A03 8 Mbps download legs, fixed before results; no application pacing/sleeps.
    mptcp_rate_owned=
    for mptcp_rate_node in 0 1 2; do
        case $mptcp_rate_node in 0) mptcp_rate_ns=$R0 ;; 1) mptcp_rate_ns=$R1 ;; 2) mptcp_rate_ns=$R2 ;; esac
        ip netns exec "$mptcp_rate_ns" tc -j qdisc show dev "r${mptcp_rate_node}c" \
            >"$WORK/mptcp-growth-rate-$mptcp_rate_node-before.json" || fail MPTCP_GROWTH_RATE_UNAVAILABLE
        jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
            "$WORK/mptcp-growth-rate-$mptcp_rate_node-before.json" >/dev/null || fail MPTCP_GROWTH_PREEXISTING_QDISC
        mptcp_rate_owned="$mptcp_rate_owned $mptcp_rate_node"
        ip netns exec "$mptcp_rate_ns" tc qdisc add dev "r${mptcp_rate_node}c" root handle 7a02: \
            tbf rate 8mbit burst 128kb latency 250ms || fail MPTCP_GROWTH_RATE_INSTALL_FAILED
        ip netns exec "$mptcp_rate_ns" tc -j -s qdisc show dev "r${mptcp_rate_node}c" \
            >"$WORK/mptcp-growth-rate-$mptcp_rate_node-during.json" || fail MPTCP_GROWTH_RATE_UNAVAILABLE
    done

    PHASE=mptcp-growth-application
    start_privacy_observers mptcp-growth-initial-privacy || fail MPTCP_GROWTH_CAPTURE_UNAVAILABLE
    DOWNLOAD_DESTINATION_READY="$WORK/destination/download-mptcp-growth-0.ready"
    DOWNLOAD_DESTINATION_RELEASE="$WORK/destination/download-mptcp-growth-0.release"
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 "$WORK/bin/mptcp-download-client.py" "$RUN_ID" mptcp-growth 0 \
        >"$WORK/mptcp-growth-client.json" 2>"$WORK/mptcp-growth-client.err" &
    DOWNLOAD_CLIENT_PID=$!
    mptcp_poll=0
    while [ "$mptcp_poll" -lt 600 ]; do
        [ ! -s "$DOWNLOAD_DESTINATION_READY" ] || break
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_GROWTH_APPLICATION_FAILED
        sleep 0.1
        mptcp_poll=$((mptcp_poll + 1))
    done
    [ -s "$DOWNLOAD_DESTINATION_READY" ] || fail MPTCP_GROWTH_DESTINATION_UNAVAILABLE
    # The destination release gate may become ready just before the second authenticated
    # kernel subflow finishes its handshake. Wait for that real initial set, not a sleep
    # followed by a single race-prone observation, and never release data without it.
    mptcp_poll=0
    while [ "$mptcp_poll" -lt 300 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_GROWTH_APPLICATION_FAILED
        if mptcp_growth_sample baseline \
            && jq -e '(.client.kernel.subflows | length) == 2 and (.exit.kernel.subflows | length) == 2' \
                "$WORK/mptcp-growth-baseline.json" >/dev/null; then break; fi
        sleep 0.1
        mptcp_poll=$((mptcp_poll + 1))
    done
    [ "$mptcp_poll" -lt 300 ] || fail MPTCP_GROWTH_KERNEL_BASELINE_UNAVAILABLE
    release_mptcp_download
    mptcp_growth_progress baseline before-loss 2 || fail MPTCP_GROWTH_INITIAL_PAYLOAD_MISSING

    PHASE=mptcp-growth-sustained-download-loss
    mptcp_loss_owned=true
    ip netns exec "$EXIT_NODE" tc qdisc add dev "$mptcp_loss_interface" root handle 7a01: \
        netem loss random 15% || fail MPTCP_GROWTH_LOSS_INSTALL_FAILED
    mptcp_poll=0
    while [ "$mptcp_poll" -lt 450 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_GROWTH_FLOW_ENDED_BEFORE_GROWTH
        if mptcp_growth_sample expanded \
            && jq -e '(.client.kernel.subflows | length) == 3 and (.exit.kernel.subflows | length) == 3' \
                "$WORK/mptcp-growth-expanded.json" >/dev/null; then break; fi
        sleep 0.1
        mptcp_poll=$((mptcp_poll + 1))
    done
    [ "$mptcp_poll" -lt 450 ] || fail MPTCP_GROWTH_THIRD_SUBFLOW_MISSING
    stop_privacy_observers || fail MPTCP_GROWTH_INITIAL_CAPTURE_NOT_DRAINED
    start_privacy_observers mptcp-growth-expanded-privacy || fail MPTCP_GROWTH_CAPTURE_UNAVAILABLE
    mptcp_growth_sample expanded || fail MPTCP_GROWTH_KERNEL_BASELINE_UNAVAILABLE
    mptcp_growth_progress expanded expanded-progress 3 || fail MPTCP_GROWTH_THIRD_PAYLOAD_MISSING
    stop_privacy_observers || fail MPTCP_GROWTH_EXPANDED_CAPTURE_NOT_DRAINED
    ip netns exec "$EXIT_NODE" tc -j -s qdisc show dev "$mptcp_loss_interface" \
        >"$WORK/mptcp-growth-qdisc-during.json" || fail MPTCP_GROWTH_QDISC_UNAVAILABLE
    mptcp_growth_cleanup || fail MPTCP_GROWTH_QDISC_CLEANUP_FAILED
    ip netns exec "$EXIT_NODE" tc -j -s qdisc show dev "$mptcp_loss_interface" \
        >"$WORK/mptcp-growth-qdisc-after.json" || fail MPTCP_GROWTH_QDISC_UNAVAILABLE
    PHASE=mptcp-growth-completion
    mptcp_status=0
    wait "$DOWNLOAD_CLIENT_PID" || mptcp_status=$?
    DOWNLOAD_CLIENT_PID=
    [ "$mptcp_status" -eq 0 ] || fail MPTCP_GROWTH_APPLICATION_FAILED
    mptcp_poll=0
    while [ "$mptcp_poll" -lt 100 ] && [ ! -s "$WORK/destination/download-mptcp-growth-0.json" ]; do
        sleep 0.1
        mptcp_poll=$((mptcp_poll + 1))
    done
    install -o root -g root -m 0600 "$WORK/destination/download-mptcp-growth-0.json" \
        "$WORK/mptcp-growth-server.json" || fail MPTCP_GROWTH_SERVER_COMPLETION_MISSING
    benchmark_disconnect_route mptcp-growth || fail MPTCP_GROWTH_DISCONNECT_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/mptcp-growth-final-status.txt" || fail MPTCP_GROWTH_FINAL_STATUS_UNAVAILABLE
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/mptcp-growth-final-paths.txt" || fail MPTCP_GROWTH_FINAL_STATUS_UNAVAILABLE
    jq -n '{client_exit_status:0,route_disconnected:true,active_contexts:0,paths_empty:true,
            loss_removed:true,rate_limits_removed:true}' >"$WORK/mptcp-growth-cleanup.json"
    mptcp_growth_check evidence "$WORK" "$WORK/mptcp-growth-evidence.json" || fail MPTCP_GROWTH_RAW_PROOF_FAILED
    OBSERVED_BLOCKER=NONE
    PHASE=mptcp-growth-complete
}
