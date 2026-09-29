#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced exclusively by the explicitly approved disposable KVM topology.
# shellcheck disable=SC2154,SC2034

mptcp_refill_check() {
    python3 -B "$source_directory/tests/integration/mptcp-refill-smoke.py" "$@"
}

mptcp_refill_stop_captures() {
    mref_capture_status=0
    if [ -n "${mref_r3_capture_pid:-}" ]; then
        kill -TERM "$mref_r3_capture_pid" 2>/dev/null || true
    fi
    if [ -n "${mref_r4_capture_pid:-}" ]; then
        kill -TERM "$mref_r4_capture_pid" 2>/dev/null || true
    fi
    if [ -n "${mref_r3_capture_pid:-}" ]; then
        wait "$mref_r3_capture_pid" || mref_capture_status=1
        mref_r3_capture_pid=
    fi
    if [ -n "${mref_r4_capture_pid:-}" ]; then
        wait "$mref_r4_capture_pid" || mref_capture_status=1
        mref_r4_capture_pid=
    fi
    if command -v stop_privacy_observers >/dev/null 2>&1; then
        stop_privacy_observers || mref_capture_status=1
    fi
    return "$mref_capture_status"
}

mptcp_refill_captures() {
    start_privacy_observers "mptcp-refill-$1-privacy" || return 1
    ip netns exec "$R3" python3 "$WORK/bin/privacy-observer.py" relay3 \
        "$WORK/mptcp-refill-$1-privacy-relay3.json" "$WORK/mptcp-refill-$1-privacy-relay3.ready" \
        --mptcp-refill r3c r3x underlay >"$WORK/mptcp-refill-$1-privacy-relay3.log" 2>&1 &
    mref_r3_capture_pid=$!
    wait_observer "$mref_r3_capture_pid" "$WORK/mptcp-refill-$1-privacy-relay3.ready" || return 1
    ip netns exec "$R4" python3 "$WORK/bin/privacy-observer.py" relay4 \
        "$WORK/mptcp-refill-$1-privacy-relay4.json" "$WORK/mptcp-refill-$1-privacy-relay4.ready" \
        --mptcp-refill r4c r4x underlay >"$WORK/mptcp-refill-$1-privacy-relay4.log" 2>&1 &
    mref_r4_capture_pid=$!
    wait_observer "$mref_r4_capture_pid" "$WORK/mptcp-refill-$1-privacy-relay4.ready"
}

mptcp_refill_cleanup() {
    mptcp_refill_stop_captures || return 1
    for mref_kind in risky warm; do
        case $mref_kind in
            risky) mref_owned=${mref_risky_owned:-false}; mref_interface=${mref_risky_interface:-}; mref_handle=7b01: ;;
            warm) mref_owned=${mref_warm_owned:-false}; mref_interface=${mref_warm_interface:-}; mref_handle=7b02: ;;
        esac
        [ "$mref_owned" = true ] || continue
        case $mref_interface in xr0|xr1|xr2|xr3) ;; *) return 1 ;; esac
        ip netns exec "$EXIT_NODE" tc -j -s qdisc show dev "$mref_interface" \
            >"$WORK/mptcp-refill-$mref_kind-cleanup.json" || return 1
        if jq -e --arg handle "$mref_handle" 'length == 1 and .[0].kind == "netem" and .[0].handle == $handle' \
            "$WORK/mptcp-refill-$mref_kind-cleanup.json" >/dev/null; then
            install -m 0600 "$WORK/mptcp-refill-$mref_kind-cleanup.json" "$WORK/mptcp-refill-$mref_kind-during.json" || return 1
            ip netns exec "$EXIT_NODE" tc qdisc del dev "$mref_interface" root handle "$mref_handle" || return 1
        else
            jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
                "$WORK/mptcp-refill-$mref_kind-cleanup.json" >/dev/null || return 1
        fi
        ip netns exec "$EXIT_NODE" tc -j -s qdisc show dev "$mref_interface" \
            >"$WORK/mptcp-refill-$mref_kind-after.json" || return 1
        case $mref_kind in risky) mref_risky_owned=false ;; warm) mref_warm_owned=false ;; esac
    done
    for mref_number in ${mref_rate_owned:-}; do
        case $mref_number in 0) mref_ns=$R0 ;; 1) mref_ns=$R1 ;; 2) mref_ns=$R2 ;; 3) mref_ns=$R3 ;; 4) mref_ns=$R4 ;; *) return 1 ;; esac
        ip netns exec "$mref_ns" tc -j qdisc show dev "r${mref_number}c" \
            >"$WORK/mptcp-refill-rate-$mref_number-cleanup.json" || return 1
        if jq -e 'length == 1 and .[0].kind == "tbf" and .[0].handle == "7b03:"' \
            "$WORK/mptcp-refill-rate-$mref_number-cleanup.json" >/dev/null; then
            ip netns exec "$mref_ns" tc qdisc del dev "r${mref_number}c" root handle 7b03: || return 1
        else
            jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' \
                "$WORK/mptcp-refill-rate-$mref_number-cleanup.json" >/dev/null || return 1
        fi
        ip netns exec "$mref_ns" tc -j qdisc show dev "r${mref_number}c" \
            >"$WORK/mptcp-refill-rate-$mref_number-after.json" || return 1
    done
    mref_rate_owned=
}

mptcp_refill_sample() {
    case $2 in retiring|retired|refilled|refilled-progress)
        mptcp_refill_check sample "$WORK/mptcp-refill-owners-$1.json" "$WORK/mptcp-refill-layout-$1.json" \
            "$WORK/mptcp-refill-warm-progress.json" "$mref_warm" \
            "$WORK/mptcp-refill-$2.json" 2>"$WORK/mptcp-refill-sample.err"
        return $? ;;
    esac
    mptcp_refill_check sample "$WORK/mptcp-refill-owners-$1.json" "$WORK/mptcp-refill-layout-$1.json" \
        "$WORK/mptcp-refill-$2.json" 2>"$WORK/mptcp-refill-sample.err"
}

mptcp_refill_progress() {
    mref_poll=0
    while [ "$mref_poll" -lt 300 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || return 1
        if mptcp_refill_sample "$1" "$3" \
            && mptcp_refill_check "$4" "$WORK/mptcp-refill-$2.json" "$WORK/mptcp-refill-$3.json" "$5" \
                2>"$WORK/mptcp-refill-progress.err"; then return 0; fi
        sleep 0.1
        mref_poll=$((mref_poll + 1))
    done
    return 1
}

mptcp_refill_record_selection_failure() {
    printf 'draw=%s blocker=%s\n' "$mref_draw" "$mref_selection_blocker" \
        >>"$WORK/mptcp-refill-selection-attempts.log"
    case $mref_selection_blocker in
        MPTCP_REFILL_CONNECT_UNAVAILABLE) mref_error=connect ;;
        MPTCP_REFILL_SELECTION_INVALID) mref_error=selection ;;
        MPTCP_REFILL_OWNER_EVIDENCE_UNAVAILABLE) mref_error=owners ;;
        MPTCP_REFILL_ORIGINAL_RELAY_SET_INVALID) mref_error=original-relays ;;
        *) return 1 ;;
    esac
    if [ -f "$WORK/mptcp-refill-$mref_error.err" ]; then
        head -c 2048 "$WORK/mptcp-refill-$mref_error.err" >>"$WORK/mptcp-refill-selection-attempts.log"
    fi
}

mptcp_refill_select() {
    mref_deadline=$(($(date +%s) + 600))
    mref_draw=0
    mref_selection_blocker=MPTCP_REFILL_CONNECT_UNAVAILABLE
    while [ "$mref_draw" -lt 64 ] && [ "$(date +%s)" -lt "$mref_deadline" ]; do
        mref_selection_blocker=MPTCP_REFILL_CONNECT_UNAVAILABLE
        if timeout --signal=TERM --kill-after=5s 90s "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" connect --transport mptcp \
            >"$WORK/mptcp-refill-connect.out" 2>"$WORK/mptcp-refill-connect.err"; then
            mref_selection_blocker=MPTCP_REFILL_SELECTION_INVALID
            "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
                >"$WORK/mptcp-refill-selection.txt" || return 1
            if mptcp_refill_check select "$WORK/mptcp-refill-selection.txt" "$WORK/a01-expected-peers.json" \
                "$WORK/mptcp-refill-selection.json" 2>"$WORK/mptcp-refill-selection.err"; then
                mref_context=$(jq -er '.route_context_id' "$WORK/mptcp-refill-selection.json") || return 1
                "$WORK/bin/examples/http3-acceptance-fixture" route-layout "$mref_context" 3 \
                    >"$WORK/mptcp-refill-layout-initial.json" || return 1
                "$WORK/bin/examples/http3-acceptance-fixture" route-layout "$mref_context" 4 \
                    >"$WORK/mptcp-refill-layout-refilled.json" || return 1
                mref_selection_blocker=MPTCP_REFILL_OWNER_EVIDENCE_UNAVAILABLE
                if mptcp_refill_check owners "$WORK/mptcp-refill-layout-initial.json" \
                    "$WORK/mptcp-refill-owners-initial.json" 2>"$WORK/mptcp-refill-owners.err"; then
                    mref_selection_blocker=MPTCP_REFILL_ORIGINAL_RELAY_SET_INVALID
                    if mptcp_refill_check original-relays "$WORK/mptcp-refill-owners-initial.json" \
                        2>"$WORK/mptcp-refill-original-relays.err"; then return 0; fi
                fi
            fi
            mptcp_refill_record_selection_failure || return 1
            benchmark_disconnect_route mptcp-refill-draw || return 1
            mref_draw=$((mref_draw + 1))
        else
            mptcp_refill_record_selection_failure || return 1
            a01_transient_connect_unavailable "$WORK/mptcp-refill-connect.err" || return 1
        fi
        sleep 1
    done
    return 1
}

mptcp_refill_run() {
    PHASE=mptcp-refill-selection
    mptcp_refill_select || fail "$mref_selection_blocker"
    jq -n --arg run "$RUN_ID" '{run_id:$run}' >"$WORK/mptcp-refill-run.json"
    mref_risky=$(jq -er '.paths[0].path_id' "$WORK/mptcp-refill-selection.json")
    mref_warm=$(jq -er '[1,2,3] - [.paths[].path_id] | .[0]' "$WORK/mptcp-refill-selection.json")
    mref_risky_node=$(jq -er --argjson p "$mref_risky" '.exit.paths[] | select(.path_id == $p) | .relay_node' "$WORK/mptcp-refill-owners-initial.json")
    mref_warm_node=$(jq -er --argjson p "$mref_warm" '.exit.paths[] | select(.path_id == $p) | .relay_node' "$WORK/mptcp-refill-owners-initial.json")
    case $mref_risky_node:$mref_warm_node in relay[0123]:relay[0123]) ;; *) fail MPTCP_REFILL_INJECTION_SCOPE_INVALID ;; esac
    mref_risky_interface=xr${mref_risky_node#relay}; mref_warm_interface=xr${mref_warm_node#relay}
    for mref_kind in risky warm; do
        case $mref_kind in risky) mref_interface=$mref_risky_interface ;; warm) mref_interface=$mref_warm_interface ;; esac
        ip netns exec "$EXIT_NODE" tc -j qdisc show dev "$mref_interface" >"$WORK/mptcp-refill-$mref_kind-before.json"
        jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' "$WORK/mptcp-refill-$mref_kind-before.json" >/dev/null \
            || fail MPTCP_REFILL_FOREIGN_QDISC
    done
    jq -n --argjson risky "$mref_risky" --argjson warm "$mref_warm" --arg r "$mref_risky_interface" --arg w "$mref_warm_interface" \
        '{risky_path:$risky,warm_path:$warm,risky_interface:$r,warm_interface:$w,namespace_role:"exit",initial_loss_percent:15,final_loss_percent:100}' \
        >"$WORK/mptcp-refill-injection.json"
    mref_rate_owned=
    for mref_number in 0 1 2 3 4; do
        case $mref_number in 0) mref_ns=$R0 ;; 1) mref_ns=$R1 ;; 2) mref_ns=$R2 ;; 3) mref_ns=$R3 ;; 4) mref_ns=$R4 ;; esac
        ip netns exec "$mref_ns" tc -j qdisc show dev "r${mref_number}c" >"$WORK/mptcp-refill-rate-$mref_number-before.json"
        jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].handle == "0:"' "$WORK/mptcp-refill-rate-$mref_number-before.json" >/dev/null \
            || fail MPTCP_REFILL_FOREIGN_QDISC
        mref_rate_owned="$mref_rate_owned $mref_number"
        ip netns exec "$mref_ns" tc qdisc add dev "r${mref_number}c" root handle 7b03: tbf rate 8mbit burst 128kb latency 250ms \
            || fail MPTCP_REFILL_RATE_INSTALL_FAILED
        ip netns exec "$mref_ns" tc -j qdisc show dev "r${mref_number}c" >"$WORK/mptcp-refill-rate-$mref_number-during.json"
    done
    PHASE=mptcp-refill-application
    mptcp_refill_captures initial || fail MPTCP_REFILL_CAPTURE_FAILED
    DOWNLOAD_DESTINATION_READY="$WORK/destination/download-mptcp-refill-0.ready"
    DOWNLOAD_DESTINATION_RELEASE="$WORK/destination/download-mptcp-refill-0.release"
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 "$WORK/bin/mptcp-download-client.py" "$RUN_ID" mptcp-refill 0 \
        >"$WORK/mptcp-refill-client.json" 2>"$WORK/mptcp-refill-client.err" &
    DOWNLOAD_CLIENT_PID=$!
    mref_poll=0
    while [ "$mref_poll" -lt 600 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_REFILL_APPLICATION_FAILED
        if [ -s "$DOWNLOAD_DESTINATION_READY" ] && mptcp_refill_sample initial baseline \
            && jq -e '(.client.kernel.subflows | length) == 2 and (.exit.kernel.subflows | length) == 2' "$WORK/mptcp-refill-baseline.json" >/dev/null; then break; fi
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    [ "$mref_poll" -lt 600 ] || fail MPTCP_REFILL_INITIAL_KERNEL_MISSING
    release_mptcp_download
    mptcp_refill_progress initial baseline initial-progress progress 2 || fail MPTCP_REFILL_INITIAL_PAYLOAD_MISSING
    mref_risky_owned=true
    ip netns exec "$EXIT_NODE" tc qdisc add dev "$mref_risky_interface" root handle 7b01: netem loss random 15% \
        || fail MPTCP_REFILL_LOSS_INSTALL_FAILED
    PHASE=mptcp-refill-old-warm
    mref_poll=0
    while [ "$mref_poll" -lt 450 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_REFILL_APPLICATION_ENDED
        mref_sample_ok=false
        if mptcp_refill_sample initial warm; then mref_sample_ok=true; fi
        # Keep the short announcement window, not only the final overwritten sample.
        # These observations diagnose failures; they do not replace any acceptance check.
        mptcp_refill_check warm-diagnostics "$WORK/mptcp-refill-warm.json" "$mref_warm" \
            "$WORK/mptcp-refill-warm-diagnostics.json" 2>"$WORK/mptcp-refill-warm-diagnostics.err" || true
        if [ "$mref_sample_ok" = true ]; then
            if [ ! -e "$WORK/mptcp-refill-warm-endpoint-first.json" ] \
                && jq -e --argjson warm "$mref_warm" '.exit.kernel.endpoints | any(.path_id == $warm)' \
                    "$WORK/mptcp-refill-warm.json" >/dev/null; then
                install -m 0600 "$WORK/mptcp-refill-warm.json" "$WORK/mptcp-refill-warm-endpoint-first.json" || true
            fi
            if jq -e '(.client.kernel.subflows | length) == 3 and (.exit.kernel.subflows | length) == 3' \
                "$WORK/mptcp-refill-warm.json" >/dev/null; then break; fi
        fi
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    [ "$mref_poll" -lt 450 ] || fail MPTCP_REFILL_WARM_NEVER_APPEARED
    mptcp_refill_progress initial warm warm-progress progress 3 || fail MPTCP_REFILL_WARM_PAYLOAD_MISSING
    mptcp_refill_stop_captures || fail MPTCP_REFILL_CAPTURE_DRAIN_FAILED
    ip netns exec "$EXIT_NODE" tc qdisc change dev "$mref_risky_interface" root handle 7b01: netem loss random 100% \
        || fail MPTCP_REFILL_LOSS_INSTALL_FAILED
    mref_warm_owned=true
    ip netns exec "$EXIT_NODE" tc qdisc add dev "$mref_warm_interface" root handle 7b02: netem loss random 100% \
        || fail MPTCP_REFILL_LOSS_INSTALL_FAILED
    PHASE=mptcp-refill-warm-retirement
    mref_poll=0
    while [ "$mref_poll" -lt 450 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_REFILL_APPLICATION_ENDED
        if mptcp_refill_sample initial retiring \
            && mptcp_refill_check retirement-candidate "$WORK/mptcp-refill-warm-progress.json" \
                "$WORK/mptcp-refill-retiring.json" "$WORK/mptcp-refill-layout-initial.json" "$mref_warm" \
                2>"$WORK/mptcp-refill-retirement.err"; then break; fi
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    [ "$mref_poll" -lt 450 ] || fail MPTCP_REFILL_WARM_NOT_RETIRED
    mref_healthy=$(jq -er --argjson risky "$mref_risky" '.paths[] | select(.path_id != $risky) | .path_id' "$WORK/mptcp-refill-selection.json")
    mref_poll=0
    while [ "$mref_poll" -lt 300 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_REFILL_APPLICATION_ENDED
        if mptcp_refill_sample initial retired \
            && mptcp_refill_check retired "$WORK/mptcp-refill-warm-progress.json" "$WORK/mptcp-refill-retiring.json" \
                "$WORK/mptcp-refill-retired.json" "$WORK/mptcp-refill-layout-initial.json" "$mref_warm" "$mref_healthy" \
                2>"$WORK/mptcp-refill-retirement.err"; then break; fi
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    [ "$mref_poll" -lt 300 ] || fail MPTCP_REFILL_WARM_RETIREMENT_UNPROVEN
    mref_started=$(python3 -c 'import time; print(time.monotonic_ns())')
    mref_agent_before=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay4.service)
    mref_helper_before=$(systemctl show --property=MainPID --value volparossa-alpha-helper@relay4.service)
    install -m 0600 "$WORK/config-relay4.yaml" "$WORK/mptcp-refill-r4-config-before.yaml"
    mptcp_refill_exposed=true
    write_config relay4 acceptance-relay-four true false 49.165.5.1 \
        "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
        "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
    install -m 0600 "$WORK/config-relay4.yaml" "$WORK/mptcp-refill-r4-config-after.yaml"
    systemctl restart volparossa-alpha-agent@relay4.service || fail MPTCP_REFILL_R4_RESTART_FAILED
    mref_agent_after=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay4.service)
    mref_helper_after=$(systemctl show --property=MainPID --value volparossa-alpha-helper@relay4.service)
    jq -n --arg peer "$R4_PEER" --argjson started "$mref_started" --argjson before "$mref_agent_before" --argjson after "$mref_agent_after" \
        --argjson hbefore "$mref_helper_before" --argjson hafter "$mref_helper_after" \
        '{relay_peer_id:$peer,started_monotonic_ns:$started,capacity_before_mbps:1,capacity_after_mbps:32,
          agent_pid_before:$before,agent_pid_after:$after,helper_pid_before:$hbefore,helper_pid_after:$hafter}' \
        >"$WORK/mptcp-refill-exposure.json"
    mptcp_refill_captures expanded || fail MPTCP_REFILL_CAPTURE_FAILED
    PHASE=mptcp-refill-fresh-admission
    mref_poll=0
    while [ "$mref_poll" -lt 900 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_REFILL_APPLICATION_ENDED
        if mptcp_refill_check owners "$WORK/mptcp-refill-layout-refilled.json" "$WORK/mptcp-refill-owners-refilled.json" \
                2>"$WORK/mptcp-refill-owners.err" \
            && mptcp_refill_sample refilled refilled \
            && jq -e 'any(.client.kernel.subflows[]; .path_id == 4) and any(.exit.kernel.subflows[]; .path_id == 4)' \
                "$WORK/mptcp-refill-refilled.json" >/dev/null; then break; fi
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    [ "$mref_poll" -lt 900 ] || fail MPTCP_REFILL_FRESH_PATH_MISSING
    mref_healthy=$(jq -er --argjson risky "$mref_risky" '.paths[] | select(.path_id != $risky) | .path_id' "$WORK/mptcp-refill-selection.json")
    mref_poll=0
    while [ "$mref_poll" -lt 300 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail MPTCP_REFILL_APPLICATION_ENDED
        if mptcp_refill_sample refilled refilled-progress \
            && mptcp_refill_check path-progress "$WORK/mptcp-refill-refilled.json" "$WORK/mptcp-refill-refilled-progress.json" 4 \
                2>"$WORK/mptcp-refill-progress.err" \
            && mptcp_refill_check path-progress "$WORK/mptcp-refill-refilled.json" "$WORK/mptcp-refill-refilled-progress.json" "$mref_healthy" \
                2>"$WORK/mptcp-refill-progress.err"; then break; fi
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    [ "$mref_poll" -lt 300 ] || fail MPTCP_REFILL_FRESH_PAYLOAD_MISSING
    mptcp_refill_stop_captures || fail MPTCP_REFILL_CAPTURE_DRAIN_FAILED
    mptcp_refill_cleanup || fail MPTCP_REFILL_QDISC_CLEANUP_FAILED
    PHASE=mptcp-refill-completion
    mref_exit_status=0; wait "$DOWNLOAD_CLIENT_PID" || mref_exit_status=$?; DOWNLOAD_CLIENT_PID=
    [ "$mref_exit_status" -eq 0 ] || fail MPTCP_REFILL_APPLICATION_FAILED
    mref_poll=0
    while [ "$mref_poll" -lt 100 ] && [ ! -s "$WORK/destination/download-mptcp-refill-0.json" ]; do
        sleep 0.1; mref_poll=$((mref_poll + 1))
    done
    install -m 0600 "$WORK/destination/download-mptcp-refill-0.json" "$WORK/mptcp-refill-server.json" || fail MPTCP_REFILL_SERVER_HASH_MISSING
    benchmark_disconnect_route mptcp-refill || fail MPTCP_REFILL_DISCONNECT_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" status >"$WORK/mptcp-refill-final-status.txt"
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths >"$WORK/mptcp-refill-final-paths.txt"
    jq -n '{application_complete:true,route_disconnected:true,owned_qdiscs_removed:true}' >"$WORK/mptcp-refill-cleanup.json"
    mptcp_refill_check evidence "$WORK" "$WORK/mptcp-refill-evidence.json" || fail MPTCP_REFILL_ORIGINAL_PROOF_FAILED
    OBSERVED_BLOCKER=NONE
    PHASE=mptcp-refill-complete
}

mptcp_refill_finalize_report() {
    mref_evidence=$(optional_json_evidence "$WORK/mptcp-refill-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$1" --argjson evidence "$mref_evidence" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" --slurpfile host "$WORK/a15-evidence.json" '
        {schema_version:1,acceptance_version:3,report_kind:"volparossa-mptcp-refill-runtime",source_revision:$revision,run_id:$run_id,phase:$phase,
         success:($status == 0 and $evidence.success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
         transfer:$evidence,observed_blocker:(if $blocker == "" then null else $blocker end),
         cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
         scope:"v3: exact warm endpoint withdrawal and anchored TCP closing residue; three distinct original relays from R0-R3; same application and MPTCP meta socket adds fresh R4 outside that set; kernel/WG observations, not exported signed capability inspection; no speed or full-alpha claim"}' \
        >"$WORK/mptcp-refill-smoke.json" || return 1
    for mref_artifact in "$WORK"/mptcp-refill-*.json "$WORK"/mptcp-refill-*.txt "$WORK"/mptcp-refill-*.yaml \
        "$WORK"/mptcp-refill-*.out "$WORK"/mptcp-refill-*.err "$WORK"/mptcp-refill-*.log; do
        if [ ! -f "$mref_artifact" ] || [ -L "$mref_artifact" ]; then continue; fi
        [ "$(stat -Lc '%s' "$mref_artifact")" -le 8388608 ] || return 1
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$mref_artifact" "$output_directory/$(basename -- "$mref_artifact")" || return 1
    done
    jq -e '.success == true' "$WORK/mptcp-refill-smoke.json" >/dev/null
}
