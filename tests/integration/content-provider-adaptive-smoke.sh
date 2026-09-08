#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the disposable content-provider KVM topology.
# shellcheck disable=SC2154,SC2034

content_provider_adaptive_event_count() {
    awk -v baseline="$adaptive_baseline_ms" -v event="event=$2" '
        $1 ~ /^[0-9]+$/ && $1 > baseline && $3 == event { count++ }
        END { print count+0 }' "$WORK/logs-$1.txt"
}

content_provider_adaptive_run() {
    PHASE=content-provider-adaptive-selection
    benchmark_select_route content-provider-adaptive mptcp \
        || fail CONTENT_PROVIDER_ADAPTIVE_SELECTION_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-provider-adaptive-selection.json" \
        || fail CONTENT_PROVIDER_ADAPTIVE_SELECTION_INVALID
    adaptive_context=$(jq -er '.route_context_id' "$WORK/content-provider-adaptive-selection.json")
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/content-provider-adaptive-status-before.json" \
        2>"$WORK/content-provider-adaptive-status-before.err" \
        || fail CONTENT_PROVIDER_ADAPTIVE_STATUS_UNAVAILABLE
    adaptive_control=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' \
        "$WORK/content-provider-adaptive-status-before.json") \
        || fail CONTENT_PROVIDER_ADAPTIVE_CONTROL_UNAVAILABLE
    jq -e --arg peer "$adaptive_control" '[.relay0,.relay1,.relay2] | index($peer) != null' \
        "$WORK/a01-expected-peers.json" >/dev/null \
        || fail CONTENT_PROVIDER_ADAPTIVE_CONTROL_NOT_INDEPENDENT
    jq -n --arg control "$adaptive_control" \
        '{provider_nodes:["relay3","relay4","relay5"],control_relay_peer_id:$control}' \
        >"$WORK/content-provider-adaptive-layout.json"
    content_provider_adaptive_control_underlay "$adaptive_control" \
        || fail CONTENT_PROVIDER_ADAPTIVE_CONTROL_UNDERLAY_FAILED

    PHASE=content-provider-adaptive-seed
    adaptive_root=$WORK/content-provider-seed/adaptive-publication
    adaptive_client=$WORK/state-client/content-adaptive
    for adaptive_node in relay3 relay4 relay5; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$adaptive_node/control/agent.sock" \
            content status >"$WORK/content-provider-adaptive-$adaptive_node-before.json" \
            2>"$WORK/content-provider-adaptive-$adaptive_node-before.err" \
            || fail CONTENT_PROVIDER_ADAPTIVE_SERVICE_STATUS_FAILED
        jq -e '.serving == false and .publications == 0' \
            "$WORK/content-provider-adaptive-$adaptive_node-before.json" >/dev/null \
            || fail CONTENT_PROVIDER_ADAPTIVE_SERVICE_NOT_EMPTY
    done
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 \
        "$WORK/content-provider-seed" "$adaptive_client" \
        "$WORK/state-relay3/content-adaptive" "$WORK/state-relay4/content-adaptive" \
        "$WORK/state-relay5/content-adaptive"
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/examples/content-acceptance-fixture" seed-adaptive-providers \
        "$adaptive_root" "$WORK/state-relay3/content-adaptive/cache" \
        "$WORK/state-relay4/content-adaptive/cache" "$WORK/state-relay5/content-adaptive/cache" \
        >"$WORK/content-provider-adaptive-seed.log" 2>&1 || fail CONTENT_PROVIDER_ADAPTIVE_SEED_FAILED
    install -o root -g root -m 0600 "$adaptive_root/publication.json" \
        "$WORK/content-provider-adaptive-publication.json"
    adaptive_publisher=$(jq -er '.publisher_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-provider-adaptive-publication.json") || fail CONTENT_PROVIDER_ADAPTIVE_KEY_INVALID
    jq -e '.publisher_removed == true and .publisher_private_key_persisted == false
        and .bytes == 3932160 and .chunks == 15
        and .replica_a_chunks == 5 and .replica_b_chunks == 5 and .replica_c_chunks == 5' \
        "$WORK/content-provider-adaptive-publication.json" >/dev/null \
        || fail CONTENT_PROVIDER_ADAPTIVE_SEED_INVALID
    adaptive_manifest=$adaptive_client/manifest.bin
    if [ -e "$adaptive_manifest" ] || [ -e "$adaptive_client/cache" ] \
        || [ -e "$adaptive_client/object.bin" ]; then
        fail CONTENT_PROVIDER_ADAPTIVE_CACHE_NOT_COLD
    fi
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$adaptive_root/manifest.bin" "$adaptive_manifest"
    adaptive_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $adaptive_pid in ''|0|*[!0-9]*) fail CONTENT_PROVIDER_ADAPTIVE_CLIENT_PID_INVALID ;; esac
    # The same real mount/UID command must read known public metadata before its denials count.
    nsenter --target "$adaptive_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$adaptive_manifest" || fail CONTENT_PROVIDER_ADAPTIVE_ISOLATION_UNAVAILABLE
    for adaptive_private in "$WORK/state-relay3" "$WORK/state-relay4" \
        "$WORK/state-relay5" "$adaptive_root"; do
        if nsenter --target "$adaptive_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$adaptive_private"; then
            fail CONTENT_PROVIDER_ADAPTIVE_LOCAL_SHORTCUT
        fi
    done

    PHASE=content-provider-adaptive-register
    for adaptive_node in relay3 relay4 relay5; do
        case $adaptive_node in
            relay3) adaptive_address=48.164.4.1; adaptive_hostname=provider-c.volparossa.test ;;
            relay4) adaptive_address=49.165.5.1; adaptive_hostname=provider-a.volparossa.test ;;
            relay5) adaptive_address=50.166.6.1; adaptive_hostname=provider-b.volparossa.test ;;
        esac
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$adaptive_node/control/agent.sock" \
            content serve --manifest "$adaptive_manifest" --publisher-key "$adaptive_publisher" \
            --cache "$WORK/state-$adaptive_node/content-adaptive/cache" --bind "$adaptive_address:18080" \
            --advertised-hostname "$adaptive_hostname" \
            >"$WORK/content-provider-adaptive-$adaptive_node-serve.json" \
            2>"$WORK/content-provider-adaptive-$adaptive_node-serve.err" \
            || fail CONTENT_PROVIDER_ADAPTIVE_REGISTRATION_FAILED
        jq -e '.serving == true and .publications == 1 and .replication_enabled == false' \
            "$WORK/content-provider-adaptive-$adaptive_node-serve.json" >/dev/null \
            || fail CONTENT_PROVIDER_ADAPTIVE_REGISTRATION_INCOMPLETE
    done
    capture_product_logs
    adaptive_baseline_ms=$(client_log_baseline_ms) || fail CONTENT_PROVIDER_ADAPTIVE_BASELINE_UNAVAILABLE
    PHASE=content-provider-adaptive-capture
    start_privacy_observers content-provider-adaptive-privacy \
        || fail CONTENT_PROVIDER_ADAPTIVE_CAPTURE_UNAVAILABLE
    content_provider_adaptive_start_control_observer content-provider-adaptive-control-privacy \
        || fail CONTENT_PROVIDER_ADAPTIVE_CONTROL_CAPTURE_UNAVAILABLE
    PHASE=content-provider-adaptive-fetch
    timeout --signal=TERM --kill-after=5s 120s "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch --manifest "$adaptive_manifest" --publisher-key "$adaptive_publisher" \
        --cache "$adaptive_client/cache" --output "$adaptive_client/object.bin" \
        >"$WORK/content-provider-adaptive-fetch.json" 2>"$WORK/content-provider-adaptive-fetch.err" \
        || fail CONTENT_PROVIDER_ADAPTIVE_RUNTIME_FETCH_FAILED
    benchmark_capture_paths content-provider-adaptive-live mptcp \
        || fail CONTENT_PROVIDER_ADAPTIVE_LIVE_PATHS_UNAVAILABLE
    jq -e --arg context "$adaptive_context" '.route_context_id == $context' \
        "$WORK/content-provider-adaptive-live-selection.json" >/dev/null \
        || fail CONTENT_PROVIDER_ADAPTIVE_CONTEXT_CHANGED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/content-provider-adaptive-status-after.json" \
        2>"$WORK/content-provider-adaptive-status-after.err" \
        || fail CONTENT_PROVIDER_ADAPTIVE_STATUS_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_PROVIDER_ADAPTIVE_CAPTURE_NOT_DRAINED
    content_provider_stop_control_observer || fail CONTENT_PROVIDER_ADAPTIVE_CONTROL_NOT_DRAINED
    capture_product_logs
    adaptive_queries=0
    adaptive_offers=0
    for adaptive_node in relay0 relay1 relay2 relay3 relay4 relay5; do
        adaptive_queries=$((adaptive_queries + $(content_provider_adaptive_event_count "$adaptive_node" CONTENT_PROVIDER_QUERY_STARTED)))
        adaptive_offers=$((adaptive_offers + $(content_provider_adaptive_event_count "$adaptive_node" CONTENT_PROVIDER_OFFER_VERIFIED)))
    done
    adaptive_discovered=$(content_provider_adaptive_event_count client CONTENT_DISCOVERY_COMPLETED)
    jq -n --arg sha256 "$(sha256sum "$adaptive_client/object.bin" | awk '{print $1}')" \
        --argjson bytes "$(stat -Lc '%s' "$adaptive_client/object.bin")" \
        --argjson baseline "$adaptive_baseline_ms" --argjson queries "$adaptive_queries" \
        --argjson offers "$adaptive_offers" --argjson discovered "$adaptive_discovered" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          client_mount_positive_control:true,client_mount_cannot_read_replica_stores:true,
          publisher_process_exited_before_fetch:true,event_baseline_unix_ms:$baseline,
          generic_dht_queries:$queries,authenticated_upstream_offers:$offers,
          client_forwarded_discovery:$discovered}' >"$WORK/content-provider-adaptive-object.json"

    PHASE=content-provider-adaptive-cleanup
    for adaptive_node in relay3 relay4 relay5; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$adaptive_node/control/agent.sock" \
            content stop >"$WORK/content-provider-adaptive-$adaptive_node-stop.json" \
            2>"$WORK/content-provider-adaptive-$adaptive_node-stop.err" \
            || fail CONTENT_PROVIDER_ADAPTIVE_STOP_FAILED
    done
    benchmark_disconnect_route content-provider-adaptive || fail CONTENT_PROVIDER_ADAPTIVE_RETIRE_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/content-provider-adaptive-final-status.txt" || fail CONTENT_PROVIDER_ADAPTIVE_RETIRE_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/content-provider-adaptive-final-paths.txt" || fail CONTENT_PROVIDER_ADAPTIVE_RETIRE_FAILED
    if ! grep -Fx 'connected: false' "$WORK/content-provider-adaptive-final-status.txt" >/dev/null \
        || ! grep -Fx 'active contexts: 0' "$WORK/content-provider-adaptive-final-status.txt" >/dev/null \
        || [ -s "$WORK/content-provider-adaptive-final-paths.txt" ]; then
        fail CONTENT_PROVIDER_ADAPTIVE_RETIRE_INCOMPLETE
    fi
    # Only these two fresh, exact phase-owned public files; cache teardown stays with the topology.
    rm -- "$WORK/state-client/content-adaptive/object.bin" "$WORK/state-client/content-adaptive/manifest.bin"
    if [ -e "$adaptive_client/object.bin" ] || [ -e "$adaptive_manifest" ]; then
        fail CONTENT_PROVIDER_ADAPTIVE_OUTPUT_CLEANUP_FAILED
    fi
    jq -n '{previous_route_disconnected:true,route_disconnected:true,active_contexts:0,
        paths_empty:true,client_output_removed:true,client_manifest_removed:true}' \
        >"$WORK/content-provider-adaptive-cleanup.json"
    python3 -B "$source_directory/tests/integration/content-provider-adaptive-smoke.py" \
        evidence "$WORK" "$WORK/content-provider-adaptive-evidence.json" \
        || fail CONTENT_PROVIDER_ADAPTIVE_EVIDENCE_INVALID
}
