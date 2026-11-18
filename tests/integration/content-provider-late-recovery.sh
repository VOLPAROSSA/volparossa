#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Separate availability proof after adaptive overlap, before cancellation.
# shellcheck disable=SC2154,SC2034

content_provider_late_recovery_cleanup() {
    [ -f "$WORK/bin/content-provider-late-recovery.py" ] || return 0
    python3 -B "$WORK/bin/content-provider-late-recovery.py" cleanup "$WORK"
}

content_provider_late_recovery_run() {
    PHASE=content-provider-late-recovery-selection
    late_prefix=content-provider-late-recovery
    benchmark_select_route "$late_prefix" mptcp || fail CONTENT_PROVIDER_LATE_SELECTION_FAILED
    benchmark_bind_slots "$WORK/$late_prefix-selection.json" || fail CONTENT_PROVIDER_LATE_SELECTION_INVALID
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" content status \
        >"$WORK/$late_prefix-status-before.json" || fail CONTENT_PROVIDER_LATE_STATUS_FAILED
    late_control=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' \
        "$WORK/$late_prefix-status-before.json") || fail CONTENT_PROVIDER_LATE_CONTROL_INVALID
    late_broker=$(jq -er --arg peer "$late_control" 'to_entries[] | select(.value == $peer) | .key' \
        "$WORK/a01-expected-peers.json") || fail CONTENT_PROVIDER_LATE_CONTROL_INVALID
    case $late_broker in relay0|relay1|relay2) ;; *) fail CONTENT_PROVIDER_LATE_CONTROL_INVALID ;; esac
    jq -n --arg peer "$late_control" '{provider_nodes:["relay4","relay5"],control_relay_peer_id:$peer}' \
        >"$WORK/$late_prefix-layout.json"
    install -o root -g root -m 0600 "$WORK/a01-expected-peers.json" "$WORK/$late_prefix-peers.json"
    content_provider_node "$late_broker" || fail CONTENT_PROVIDER_LATE_CONTROL_INVALID
    late_control_ns=$provider_ns; late_control_ip=$provider_ip; late_control_ips=$provider_ip
    late_slot=0
    for late_node in relay4 relay5; do
        content_provider_node "$late_node" || fail CONTENT_PROVIDER_LATE_CONTROL_INVALID
        late_segment=$((86 + late_slot))
        link_nodes "$late_control_ns" "lc$late_slot" "10.241.$late_segment.1/30" \
            "$provider_ns" "lp$late_slot" "10.241.$late_segment.2/30" || fail CONTENT_PROVIDER_LATE_LINK_FAILED
        content_provider_filter_link "$late_control_ns" "late_$late_slot" "lc$late_slot" \
            "$late_control_ip" "$provider_ip" || fail CONTENT_PROVIDER_LATE_FILTER_FAILED
        content_provider_filter_link "$provider_ns" "late_$late_slot" "lp$late_slot" \
            "$provider_ip" "$late_control_ip" || fail CONTENT_PROVIDER_LATE_FILTER_FAILED
        ip -n "$late_control_ns" route replace "$provider_ip/32" via "10.241.$late_segment.2" \
            dev "lc$late_slot" src "$late_control_ip" || fail CONTENT_PROVIDER_LATE_ROUTE_FAILED
        ip -n "$provider_ns" route replace "$late_control_ip/32" via "10.241.$late_segment.1" \
            dev "lp$late_slot" src "$provider_ip" || fail CONTENT_PROVIDER_LATE_ROUTE_FAILED
        ip -n "$late_control_ns" -j route get "$provider_ip" \
            >"$WORK/$late_prefix-control-$late_node-out.json" || fail CONTENT_PROVIDER_LATE_ROUTE_FAILED
        ip -n "$provider_ns" -j route get "$late_control_ip" \
            >"$WORK/$late_prefix-control-$late_node-back.json" || fail CONTENT_PROVIDER_LATE_ROUTE_FAILED
        late_control_ips=$late_control_ips,$provider_ip
        late_slot=$((late_slot + 1))
    done
    PHASE=content-provider-late-recovery-seed
    late_root=$WORK/content-provider-seed/late-publication
    late_client=$WORK/state-client/content-late-recovery
    for late_node in relay4 relay5; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$late_node/control/agent.sock" content status \
            >"$WORK/$late_prefix-$late_node-before.json" || fail CONTENT_PROVIDER_LATE_STATUS_FAILED
        jq -e '.serving == false and .publications == 0' "$WORK/$late_prefix-$late_node-before.json" >/dev/null \
            || fail CONTENT_PROVIDER_LATE_PROVIDER_NOT_EMPTY
    done
    if [ -e "$late_root" ] || [ -L "$late_root" ] || [ -e "$late_client" ] || [ -L "$late_client" ]; then
        fail CONTENT_PROVIDER_LATE_NOT_FRESH
    fi
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$late_client" \
        "$WORK/state-relay4/content-late-recovery" "$WORK/state-relay5/content-late-recovery"
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/examples/content-acceptance-fixture" seed-late-providers "$late_root" \
        "$WORK/state-relay4/content-late-recovery/cache" "$WORK/state-relay5/content-late-recovery/cache" \
        >"$WORK/$late_prefix-seed.log" 2>&1 || fail CONTENT_PROVIDER_LATE_SEED_FAILED
    install -o root -g root -m 0600 "$late_root/publication.json" "$WORK/$late_prefix-publication.json"
    late_publisher=$(jq -er '.publisher_hex | select(test("^[0-9a-f]{64}$"))' "$WORK/$late_prefix-publication.json") \
        || fail CONTENT_PROVIDER_LATE_KEY_INVALID
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$late_root/manifest.bin" "$late_client/manifest.bin"
    late_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $late_pid in ''|0|*[!0-9]*) fail CONTENT_PROVIDER_LATE_CLIENT_PID_INVALID ;; esac
    nsenter --target "$late_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$late_client/manifest.bin" || fail CONTENT_PROVIDER_LATE_ISOLATION_UNAVAILABLE
    for late_private in "$WORK/state-relay3" "$WORK/state-relay4" "$WORK/state-relay5" "$late_root"; do
        if nsenter --target "$late_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$late_private"; then fail CONTENT_PROVIDER_LATE_LOCAL_SHORTCUT; fi
    done
    PHASE=content-provider-late-recovery-register-a
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay4/control/agent.sock" \
        content serve --manifest "$late_client/manifest.bin" --publisher-key "$late_publisher" \
        --cache "$WORK/state-relay4/content-late-recovery/cache" --bind 49.165.5.1:18080 \
        --advertised-hostname provider-a.volparossa.test >"$WORK/$late_prefix-relay4-serve.json" \
        || fail CONTENT_PROVIDER_LATE_REGISTER_A_FAILED
    start_privacy_observers "$late_prefix-privacy" || fail CONTENT_PROVIDER_LATE_CAPTURE_FAILED
    [ -z "$PROVIDER_CONTROL_PID" ] || fail CONTENT_PROVIDER_LATE_CONTROL_CAPTURE_BUSY
    ip netns exec "$late_control_ns" python3 "$WORK/bin/privacy-observer.py" content-control \
        "$WORK/$late_prefix-control-privacy.json" "$WORK/$late_prefix-control-privacy.ready" \
        --content-providers "--content-control=$late_control_ips" lc0 lc1 \
        >"$WORK/$late_prefix-control-privacy.log" 2>&1 &
    PROVIDER_CONTROL_PID=$!
    wait_observer "$PROVIDER_CONTROL_PID" "$WORK/$late_prefix-control-privacy.ready" \
        || fail CONTENT_PROVIDER_LATE_CONTROL_CAPTURE_FAILED
    PHASE=content-provider-late-recovery-readiness
    python3 -B "$WORK/bin/content-provider-late-recovery.py" prepare "$WORK" "$binary_directory/volparossa" \
        "$binary_directory/examples/content-acceptance-fixture" || fail CONTENT_PROVIDER_LATE_READINESS_FAILED
    PHASE=content-provider-late-recovery-fetch
    python3 -B "$WORK/bin/content-provider-late-recovery.py" run "$WORK" "$binary_directory/volparossa" "$R4" \
        || fail CONTENT_PROVIDER_LATE_FETCH_FAILED
    benchmark_capture_paths "$late_prefix-live" mptcp || fail CONTENT_PROVIDER_LATE_PATHS_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" content status \
        >"$WORK/$late_prefix-status-after.json" || fail CONTENT_PROVIDER_LATE_STATUS_FAILED
    stop_privacy_observers || fail CONTENT_PROVIDER_LATE_CAPTURE_NOT_DRAINED
    content_provider_stop_control_observer || fail CONTENT_PROVIDER_LATE_CONTROL_NOT_DRAINED
    PHASE=content-provider-late-recovery-cleanup
    content_provider_late_recovery_cleanup || fail CONTENT_PROVIDER_LATE_PROCESS_CLEANUP_FAILED
    for late_node in relay4 relay5; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$late_node/control/agent.sock" content stop \
            >"$WORK/$late_prefix-$late_node-stop.json" || fail CONTENT_PROVIDER_LATE_STOP_FAILED
    done
    benchmark_disconnect_route "$late_prefix" || fail CONTENT_PROVIDER_LATE_DISCONNECT_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/$late_prefix-final-status.txt" || fail CONTENT_PROVIDER_LATE_STATUS_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/$late_prefix-final-paths.txt" || fail CONTENT_PROVIDER_LATE_STATUS_FAILED
    if ! grep -Fx 'connected: false' "$WORK/$late_prefix-final-status.txt" >/dev/null \
        || ! grep -Fx 'active contexts: 0' "$WORK/$late_prefix-final-status.txt" >/dev/null \
        || [ -s "$WORK/$late_prefix-final-paths.txt" ]; then
        fail CONTENT_PROVIDER_LATE_DISCONNECT_INCOMPLETE
    fi
    if [ -L "$late_client/object.bin" ] || [ -L "$late_client/manifest.bin" ]; then
        fail CONTENT_PROVIDER_LATE_OUTPUT_UNSAFE
    fi
    rm -- "$late_client/object.bin" "$late_client/manifest.bin" || fail CONTENT_PROVIDER_LATE_OUTPUT_CLEANUP_FAILED
    jq -n '{route_disconnected:true,active_contexts:0,paths_empty:true,
        client_output_removed:true,client_manifest_removed:true,client_mount_isolated:true}' \
        >"$WORK/$late_prefix-cleanup.json"
    python3 -B "$WORK/bin/content-provider-late-recovery.py" evidence "$WORK" "$WORK/$late_prefix-evidence.json" \
        || fail CONTENT_PROVIDER_LATE_EVIDENCE_INVALID
}
