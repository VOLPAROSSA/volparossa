#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the disposable content-provider KVM topology.
# shellcheck disable=SC2154,SC2034

content_provider_pressure_node() {
    case $1 in
        relay3) pp_ns=$R3; pp_dev=r3x; pp_owned=${CONTENT_PROVIDER_PRESSURE_R3_OWNED:-no} ;;
        relay4) pp_ns=$R4; pp_dev=r4x; pp_owned=${CONTENT_PROVIDER_PRESSURE_R4_OWNED:-no} ;;
        relay5) pp_ns=$R5; pp_dev=r5x; pp_owned=${CONTENT_PROVIDER_PRESSURE_R5_OWNED:-no} ;;
        *) return 1 ;;
    esac
}

content_provider_pressure_snapshot() {
    case $1 in before|limited|after) ;; *) return 1 ;; esac
    for pp_node in relay3 relay4 relay5; do
        content_provider_pressure_node "$pp_node" || return 1
        ip netns exec "$pp_ns" tc -j qdisc show dev "$pp_dev" \
            >"$WORK/.content-provider-pressure-$pp_node-$1.json" || return 1
    done
    jq -n --slurpfile r3 "$WORK/.content-provider-pressure-relay3-$1.json" \
        --slurpfile r4 "$WORK/.content-provider-pressure-relay4-$1.json" \
        --slurpfile r5 "$WORK/.content-provider-pressure-relay5-$1.json" \
        '{relay3:$r3[0],relay4:$r4[0],relay5:$r5[0]}' \
        >"$WORK/content-provider-pressure-qdisc-$1.json"
}

content_provider_pressure_unshape() {
    pp_unshape_result=0
    for pp_node in relay3 relay4 relay5; do
        content_provider_pressure_node "$pp_node" || return 1
        [ "$pp_owned" = yes ] || continue
        # Never remove an unrelated qdisc, even while unwinding a failed trial.
        if ! ip netns exec "$pp_ns" tc -j qdisc show dev "$pp_dev" \
            >"$WORK/.content-provider-pressure-$pp_node-final.json" \
            || ! jq -e 'length == 1 and .[0].kind == "tbf" and .[0].root == true
                and .[0].handle == "884:" and .[0].options.rate == 250000' \
                "$WORK/.content-provider-pressure-$pp_node-final.json" >/dev/null; then
            pp_unshape_result=1
            continue
        fi
        printf '%s\n' "Removing only owned TBF 884: from disposable namespace $pp_ns interface $pp_dev."
        if ! ip netns exec "$pp_ns" tc qdisc del dev "$pp_dev" root handle 884:; then
            pp_unshape_result=1
            continue
        fi
        case $pp_node in
            relay3) CONTENT_PROVIDER_PRESSURE_R3_OWNED=no ;;
            relay4) CONTENT_PROVIDER_PRESSURE_R4_OWNED=no ;;
            relay5) CONTENT_PROVIDER_PRESSURE_R5_OWNED=no ;;
        esac
    done
    return "$pp_unshape_result"
}

content_provider_pressure_cleanup() {
    # These are our unreaped timeout supervisors, never PID files from an agent.
    # timeout forwards TERM to its own process group and bounds forced drain.
    if [ -n "${CONTENT_PROVIDER_PRESSURE_FETCH_PID:-}" ]; then
        kill -TERM "$CONTENT_PROVIDER_PRESSURE_FETCH_PID" 2>/dev/null || true
        wait "$CONTENT_PROVIDER_PRESSURE_FETCH_PID" 2>/dev/null || true
        CONTENT_PROVIDER_PRESSURE_FETCH_PID=
    fi
    if [ -n "${CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID:-}" ]; then
        kill -TERM "$CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID" 2>/dev/null || true
        wait "$CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID" 2>/dev/null || true
        CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID=
    fi
    content_provider_pressure_unshape
}

content_provider_pressure_shape() {
    # Controller readiness already checked the exact disposable KVM/root boundary.
    # Check all three links before making any change; never replace a preexisting qdisc.
    pp_parent_ns=$(readlink /proc/self/ns/net) || return 1
    for pp_node in relay3 relay4 relay5; do
        content_provider_pressure_node "$pp_node" || return 1
        [ "$pp_owned" = no ] || return 1
        pp_child_ns=$(ip netns exec "$pp_ns" readlink /proc/self/ns/net) || return 1
        [ -n "$pp_child_ns" ] && [ "$pp_child_ns" != "$pp_parent_ns" ] || return 1
    done
    content_provider_pressure_snapshot before || return 1
    jq -e 'keys == ["relay3","relay4","relay5"] and
        all(.[]; length == 1 and .[0].kind == "noqueue" and .[0].root == true)' \
        "$WORK/content-provider-pressure-qdisc-before.json" >/dev/null || return 1
    for pp_node in relay3 relay4 relay5; do
        content_provider_pressure_node "$pp_node" || return 1
        printf '%s\n' "Adding fixed TBF 884: rate 2mbit burst 128kb latency 250ms to disposable namespace $pp_ns interface $pp_dev; remove before route teardown."
        ip netns exec "$pp_ns" tc qdisc add dev "$pp_dev" root handle 884: \
            tbf rate 2mbit burst 128kb latency 250ms || return 1
        case $pp_node in
            relay3) CONTENT_PROVIDER_PRESSURE_R3_OWNED=yes ;;
            relay4) CONTENT_PROVIDER_PRESSURE_R4_OWNED=yes ;;
            relay5) CONTENT_PROVIDER_PRESSURE_R5_OWNED=yes ;;
        esac
    done
    content_provider_pressure_snapshot limited || return 1
    jq -e 'all(.[]; length == 1 and .[0].kind == "tbf" and .[0].root == true
        and .[0].handle == "884:" and .[0].options.rate == 250000)' \
        "$WORK/content-provider-pressure-qdisc-limited.json" >/dev/null || return 1
    jq -n '{profile:"fixed-provider-egress-2mbit",
        devices:{relay3:"r3x",relay4:"r4x",relay5:"r5x"},handle:"884:",
        rate_bits_per_second:2000000,burst_bytes:131072,queue_latency_ms:250}' \
        >"$WORK/content-provider-pressure-qdisc-profile.json"
}

content_provider_pressure_event_count() {
    # Millisecond event timestamps include the whole fetch, but no setup/history
    # before it or unrelated later work. Equal timestamps at its start are valid.
    awk -v baseline="$pp_baseline_ms" -v started="$pp_started_unix" \
        -v completed="$pp_completed_unix" -v event="event=$1" \
        '$1 > baseline && $1 >= started && $1 <= completed && $3 == event {n++} END {print n+0}' "$2"
}

content_provider_pressure_discovery_counts() {
    pp_queries=0
    pp_offers=0
    pp_exact_started=0
    pp_exact_finished=0
    for pp_node in relay0 relay1 relay2 relay3 relay4 relay5; do
        pp_queries=$((pp_queries + $(content_provider_pressure_event_count \
            CONTENT_PROVIDER_QUERY_STARTED "$WORK/logs-$pp_node.txt")))
        pp_offers=$((pp_offers + $(content_provider_pressure_event_count \
            CONTENT_PROVIDER_OFFER_VERIFIED "$WORK/logs-$pp_node.txt")))
        pp_exact_started=$((pp_exact_started + $(content_provider_pressure_event_count \
            CONTENT_EXACT_LOOKUP_STARTED "$WORK/logs-$pp_node.txt")))
        pp_exact_finished=$((pp_exact_finished + $(content_provider_pressure_event_count \
            CONTENT_EXACT_LOOKUP_FINISHED "$WORK/logs-$pp_node.txt")))
    done
    pp_discovered=$(content_provider_pressure_event_count CONTENT_DISCOVERY_COMPLETED "$WORK/logs-client.txt")
    pp_nonempty=$(content_provider_pressure_event_count CONTENT_DISCOVERY_RECEIVED_OFFERS "$WORK/logs-client.txt")
}

content_provider_pressure_run() {
    PHASE=content-provider-pressure-setup
    pp_prefix=content-provider-pressure
    pp_client=$WORK/state-client/content-adaptive-pressure
    if [ -e "$pp_client" ] || [ -L "$pp_client" ] \
        || [ -n "${CONTENT_PROVIDER_PRESSURE_FETCH_PID:-}" ] \
        || [ -n "${CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID:-}" ]; then
        fail CONTENT_PROVIDER_PRESSURE_NOT_COLD
    fi
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$pp_client"
    # Use the original native publication and route, not the HTTPS index identities.
    cp -- "$WORK/content-provider-adaptive-live-selection.json" "$WORK/$pp_prefix-selection.json"
    for pp_provider in relay3 relay4 relay5; do
        case $pp_provider in
            relay3) pp_address=48.164.4.1; pp_hostname=provider-c.volparossa.test ;;
            relay4) pp_address=49.165.5.1; pp_hostname=provider-a.volparossa.test ;;
            relay5) pp_address=50.166.6.1; pp_hostname=provider-b.volparossa.test ;;
        esac
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$pp_provider/control/agent.sock" \
            content stop >"$WORK/$pp_prefix-$pp_provider-reset.json" \
            || fail CONTENT_PROVIDER_PRESSURE_PROVIDER_RESET_FAILED
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$pp_provider/control/agent.sock" \
            content serve --manifest "$adaptive_manifest" \
            --publisher-key "$adaptive_publisher" --cache "$WORK/state-$pp_provider/content-adaptive/cache" \
            --bind "$pp_address:18080" --advertised-hostname "$pp_hostname" \
            >"$WORK/$pp_prefix-$pp_provider-serve.json" \
            || fail CONTENT_PROVIDER_PRESSURE_PROVIDER_SERVE_FAILED
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$pp_provider/control/agent.sock" \
            content status >"$WORK/$pp_prefix-$pp_provider-status.json" \
            || fail CONTENT_PROVIDER_PRESSURE_PROVIDER_STATUS_FAILED
        jq -e '.serving == true and .publications == 1 and .replication_enabled == false' \
            "$WORK/$pp_prefix-$pp_provider-status.json" >/dev/null \
            || fail CONTENT_PROVIDER_PRESSURE_PROVIDER_NOT_READY
    done
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/$pp_prefix-status-before.json" \
        || fail CONTENT_PROVIDER_PRESSURE_STATUS_FAILED
    # Repeat the positive mount control and all provider-store denials for this phase.
    nsenter --target "$adaptive_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$adaptive_manifest" || fail CONTENT_PROVIDER_PRESSURE_MOUNT_UNAVAILABLE
    for pp_private in "$WORK/state-relay3" "$WORK/state-relay4" "$WORK/state-relay5" "$adaptive_root"; do
        if nsenter --target "$adaptive_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$pp_private"; then fail CONTENT_PROVIDER_PRESSURE_LOCAL_SHORTCUT; fi
    done
    PHASE=content-provider-pressure-resource-ready
    python3 -B "$source_directory/tests/integration/content-provider-resource-ready.py" "$WORK" pressure \
        || fail CONTENT_PROVIDER_PRESSURE_RESOURCE_UNAVAILABLE
    capture_product_logs
    pp_baseline_ms=$(client_log_baseline_ms) || fail CONTENT_PROVIDER_PRESSURE_BASELINE_UNAVAILABLE
    start_privacy_observers "$pp_prefix-privacy" || fail CONTENT_PROVIDER_PRESSURE_CAPTURE_FAILED
    content_provider_adaptive_start_control_observer "$pp_prefix-control-privacy" \
        || fail CONTENT_PROVIDER_PRESSURE_CONTROL_FAILED
    PHASE=content-provider-pressure-observer
    timeout --signal=TERM --kill-after=5s 45s python3 -B \
        "$WORK/bin/content-provider-pressure.py" observe "$WORK" \
        >"$WORK/$pp_prefix-controller.log" 2>&1 &
    CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID=$!
    pp_ready_attempt=0
    while [ "$pp_ready_attempt" -lt 50 ]; do
        if [ -e "$WORK/$pp_prefix-ready.json" ]; then break; fi
        kill -0 "$CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID" 2>/dev/null \
            || fail CONTENT_PROVIDER_PRESSURE_OBSERVER_EXITED
        sleep 0.1
        pp_ready_attempt=$((pp_ready_attempt + 1))
    done
    python3 -B "$source_directory/tests/integration/content-provider-pressure-smoke.py" ready "$WORK" \
        || fail CONTENT_PROVIDER_PRESSURE_OBSERVER_NOT_READY
    content_provider_pressure_shape || fail CONTENT_PROVIDER_PRESSURE_QDISC_FAILED

    PHASE=content-provider-pressure-fetch
    content_provider_worker_budget_capture mark pressure
    pp_started_mono=$(python3 -B -c 'import time; print(time.monotonic_ns())')
    pp_started_unix=$(date +%s%3N)
    # Ordinary CLI: unchanged production admission/PSI, deadlines and continuation.
    timeout --signal=TERM --kill-after=5s 120s "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch --manifest "$adaptive_manifest" --publisher-key "$adaptive_publisher" \
        --cache "$pp_client/cache" --output "$pp_client/object.bin" \
        >"$WORK/$pp_prefix-fetch.json" 2>"$WORK/$pp_prefix-fetch.err" &
    CONTENT_PROVIDER_PRESSURE_FETCH_PID=$!
    pp_fetch_status=0
    wait "$CONTENT_PROVIDER_PRESSURE_FETCH_PID" || pp_fetch_status=$?
    CONTENT_PROVIDER_PRESSURE_FETCH_PID=
    pp_completed_mono=$(python3 -B -c 'import time; print(time.monotonic_ns())')
    pp_completed_unix=$(date +%s%3N)
    if [ "$pp_fetch_status" -eq 0 ]; then
        content_provider_worker_budget_capture finish pressure
    else
        content_provider_worker_budget_capture pending pressure
        fail CONTENT_PROVIDER_PRESSURE_FETCH_FAILED
    fi
    pp_controller_status=0
    wait "$CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID" || pp_controller_status=$?
    CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID=
    [ "$pp_controller_status" -eq 0 ] || fail CONTENT_PROVIDER_PRESSURE_NOT_OBSERVED
    benchmark_capture_paths "$pp_prefix-live" mptcp || fail CONTENT_PROVIDER_PRESSURE_PATHS_FAILED
    jq -e --arg context "$adaptive_context" '.route_context_id == $context' \
        "$WORK/$pp_prefix-live-selection.json" >/dev/null || fail CONTENT_PROVIDER_PRESSURE_ROUTE_CHANGED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/$pp_prefix-status-after.json" || fail CONTENT_PROVIDER_PRESSURE_STATUS_FAILED
    stop_privacy_observers || fail CONTENT_PROVIDER_PRESSURE_CAPTURE_NOT_DRAINED
    content_provider_stop_control_observer || fail CONTENT_PROVIDER_PRESSURE_CONTROL_NOT_DRAINED
    capture_product_logs
    content_provider_pressure_discovery_counts
    if [ -L "$pp_client/object.bin" ] \
        || [ "$(stat -Lc '%a:%u:%g:%h' "$pp_client/object.bin")" != "600:$AGENT_UID:$AGENT_GID:1" ]; then
        fail CONTENT_PROVIDER_PRESSURE_OUTPUT_UNSAFE
    fi
    jq -n --arg sha256 "$(sha256sum "$pp_client/object.bin" | awk '{print $1}')" \
        --argjson bytes "$(stat -Lc '%s' "$pp_client/object.bin")" \
        --argjson baseline "$pp_baseline_ms" --argjson queries "$pp_queries" \
        --argjson offers "$pp_offers" --argjson discovered "$pp_discovered" \
        --argjson exact_started "$pp_exact_started" --argjson exact_finished "$pp_exact_finished" \
        --argjson nonempty "$pp_nonempty" \
        --argjson started_mono "$pp_started_mono" --argjson completed_mono "$pp_completed_mono" \
        --argjson started_unix "$pp_started_unix" --argjson completed_unix "$pp_completed_unix" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          client_mount_positive_control:true,client_mount_cannot_read_replica_stores:true,
          publisher_process_exited_before_fetch:true,event_baseline_unix_ms:$baseline,
          generic_dht_queries:$queries,authenticated_upstream_offers:$offers,
          exact_lookup_started:$exact_started,exact_lookup_finished:$exact_finished,
          client_nonempty_verified_responses:$nonempty,
          client_forwarded_discovery:$discovered,started_monotonic_ns:$started_mono,
          completed_monotonic_ns:$completed_mono,started_unix_ms:$started_unix,completed_unix_ms:$completed_unix}' \
        >"$WORK/$pp_prefix-object.json"
    PHASE=content-provider-pressure-cleanup
    for pp_provider in relay3 relay4 relay5; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$pp_provider/control/agent.sock" \
            content stop >"$WORK/$pp_prefix-$pp_provider-stop.json" \
            || fail CONTENT_PROVIDER_PRESSURE_PROVIDER_STOP_FAILED
    done
    content_provider_pressure_cleanup || fail CONTENT_PROVIDER_PRESSURE_CLEANUP_FAILED
    content_provider_pressure_snapshot after || fail CONTENT_PROVIDER_PRESSURE_QDISC_CLEANUP_FAILED
    jq -e 'all(.[]; length == 1 and .[0].kind == "noqueue" and .[0].root == true)' \
        "$WORK/$pp_prefix-qdisc-after.json" >/dev/null || fail CONTENT_PROVIDER_PRESSURE_QDISC_NOT_RESTORED
    # As with native adaptive cache, whole-topology teardown owns cache removal.
    rm -- "$WORK/state-client/content-adaptive-pressure/object.bin"
    if [ -e "$pp_client/object.bin" ] || [ -L "$pp_client/object.bin" ]; then
        fail CONTENT_PROVIDER_PRESSURE_OUTPUT_CLEANUP_FAILED
    fi
    jq -n '{controller_reaped:true,fetch_reaped:true,owned_output_removed:true,
        cache_teardown_deferred_to_topology:true,qdisc_restored:true,route_retained:true}' \
        >"$WORK/$pp_prefix-cleanup.json"
    python3 -B "$source_directory/tests/integration/content-provider-pressure-smoke.py" \
        evidence "$WORK" "$WORK/$pp_prefix-evidence.json" || fail CONTENT_PROVIDER_PRESSURE_EVIDENCE_INVALID
}
