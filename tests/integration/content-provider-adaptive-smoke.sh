#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the disposable content-provider KVM topology.
# shellcheck disable=SC2154,SC2034

content_provider_adaptive_event_count() {
    awk -v baseline="$adaptive_baseline_ms" -v event="event=$2" '
        $1 ~ /^[0-9]+$/ && $1 > baseline && $3 == event { count++ }
        END { print count+0 }' "$WORK/logs-$1.txt"
}

content_provider_adaptive_https_cleanup() {
    adaptive_https_cleanup=$WORK/client-fixtures/adaptive-https-output
    [ ! -L "$adaptive_https_cleanup" ] || return 1
    if [ -e "$adaptive_https_cleanup" ]; then
        [ "$(stat -Lc '%a:%u:%g' "$adaptive_https_cleanup")" = "700:$WORKER_UID:$WORKER_GID" ] || return 1
        for adaptive_https_file in origin.pem digest-peers-first-object.bin; do
            adaptive_https_mode=600
            [ "$adaptive_https_file" != origin.pem ] || adaptive_https_mode=400
            if [ -e "$adaptive_https_cleanup/$adaptive_https_file" ]; then
                [ ! -L "$adaptive_https_cleanup/$adaptive_https_file" ] \
                    && [ "$(stat -Lc '%a:%u:%g' "$adaptive_https_cleanup/$adaptive_https_file")" = "$adaptive_https_mode:$WORKER_UID:$WORKER_GID" ] || return 1
                rm -- "$adaptive_https_cleanup/$adaptive_https_file" || return 1
            fi
        done
        rmdir -- "$adaptive_https_cleanup" || return 1
    fi
}

content_provider_adaptive_https_run() {
    PHASE=content-provider-adaptive-https-indexes
    ah_prefix=content-provider-adaptive-https
    ah_binary=$binary_directory/examples/https-content-acceptance-fixture
    ah_origin=$adaptive_root/https-origin
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$ah_binary" seed-adaptive-origin "$ah_origin" "$adaptive_manifest" "$adaptive_publisher" \
        >"$WORK/$ah_prefix-seed.log" 2>&1 || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_SEED_FAILED
    install -o root -g root -m 0600 "$ah_origin/publication.json" "$WORK/$ah_prefix-publication.json"
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay3/control/agent.sock" \
        content status >"$WORK/$ah_prefix-a-status.json" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_STATUS_FAILED
    for ah_node in relay4 relay5; do
        case $ah_node in
            relay4) ah_shard=1; ah_address=49.165.5.1; ah_hostname=provider-a.volparossa.test ;;
            relay5) ah_shard=2; ah_address=50.166.6.1; ah_hostname=provider-b.volparossa.test ;;
        esac
        ah_cache=$WORK/state-$ah_node/content-adaptive/cache
        ah_index=$WORK/state-$ah_node/content-adaptive/digest-index
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$ah_node/control/agent.sock" \
            content stop >"$WORK/$ah_prefix-$ah_node-stop.json" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_STOP_FAILED
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$ah_binary" independent-adaptive-index "$ah_index" "$adaptive_manifest" \
            "$adaptive_publisher" "$ah_cache" "$ah_shard" \
            >"$WORK/$ah_prefix-$ah_node-index.log" 2>&1 || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_INDEX_FAILED
        install -o root -g root -m 0600 "$ah_index/publication.json" "$WORK/$ah_prefix-$ah_node-index.json"
        ah_key=$(jq -er '.independent.publisher_hex | select(test("^[0-9a-f]{64}$"))' \
            "$WORK/$ah_prefix-$ah_node-index.json") || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_KEY_INVALID
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$ah_node/control/agent.sock" \
            content serve --manifest "$ah_index/manifest.bin" --publisher-key "$ah_key" \
            --cache "$ah_cache" --bind "$ah_address:18080" --advertised-hostname "$ah_hostname" \
            >"$WORK/$ah_prefix-$ah_node-serve.json" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_SERVE_FAILED
        jq -n --arg node "$ah_node" --arg key "$ah_key" --arg cache "$ah_cache" \
            --arg manifest "$ah_index/manifest.bin" --arg bind "$ah_address:18080" --arg host "$ah_hostname" \
            --arg sha "$(sha256sum "$ah_index/manifest.bin" | awk '{print $1}')" \
            --arg original "$(sha256sum "$adaptive_manifest" | awk '{print $1}')" \
            --argjson registered "$(date +%s)" --slurpfile peers "$WORK/a01-expected-peers.json" \
            '{provider_node:$node,provider_peer_id:$peers[0][$node],publisher_hex:$key,cache:$cache,
              manifest_path:$manifest,manifest_file_sha256:$sha,original_manifest_file_sha256:$original,
              bind_address:$bind,advertised_hostname:$host,registered_unix_seconds:$registered}' \
            >"$WORK/$ah_prefix-$ah_node-binding.json"
    done
    ah_user=$WORK/client-fixtures/adaptive-https-output
    ah_cache=$adaptive_client/https-cache
    [ ! -e "$ah_user" ] && [ ! -L "$ah_user" ] && [ ! -e "$ah_cache" ] \
        || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_NOT_COLD
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$ah_user"
    ah_parent_ns=$(readlink /proc/self/ns/net)
    ah_client_ns=$(ip netns exec "$CLIENT" readlink /proc/self/ns/net)
    ah_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $ah_control_gid in ''|*[!0-9]*) fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_GROUP_INVALID ;; esac
    nsenter --target "$adaptive_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$adaptive_manifest" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_ISOLATION_UNAVAILABLE
    for ah_private in "$ah_user" "$ah_origin/object.bin"; do
        if nsenter --target "$adaptive_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$ah_private"; then fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_LOCAL_SHORTCUT; fi
    done
    PHASE=content-provider-adaptive-https-origin
    [ -z "$TLS_POLICY_SERVER_PID" ] || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_ORIGIN_BUSY
    ah_origin_report=$WORK/destination/$ah_prefix-origin.json
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$ah_binary" origin-pem "$ah_origin" 47.163.4.2:18443 \
        "$WORK/destination/$ah_prefix-origin.pem" "$ah_origin_report" 1 \
        >"$WORK/$ah_prefix-origin.log" 2>&1 &
    TLS_POLICY_SERVER_PID=$!
    wait_observer "$TLS_POLICY_SERVER_PID" "$ah_origin_report.ready" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_ORIGIN_FAILED
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$WORK/destination/$ah_prefix-origin.pem" "$ah_user/origin.pem"
    start_privacy_observers "$ah_prefix-privacy" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_CAPTURE_FAILED
    content_provider_adaptive_start_control_observer "$ah_prefix-control-privacy" \
        || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_CONTROL_FAILED
    PHASE=content-provider-adaptive-https-fetch
    # Reuse the existing non-browser consumer: it checks real inherited UID/caps/netns and
    # executes ordinary origin-digest CLI without a publisher key or manifest argument.
    timeout --signal=TERM --kill-after=5s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ah_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-provider-https-smoke.py" consume digest-peers-first \
        "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" "$ah_cache" "$ah_user" \
        "$ah_parent_ns" "$ah_client_ns" "$WORKER_UID" "$WORKER_GID" "$ah_control_gid" \
        >"$WORK/$ah_prefix-application.json" 2>"$WORK/$ah_prefix-application.err" \
        || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_FETCH_FAILED
    jq -e '.final' "$WORK/$ah_prefix-application.json" >"$WORK/$ah_prefix-fetch.json" \
        || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_RECEIPT_INVALID
    benchmark_capture_paths "$ah_prefix-live" mptcp || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_PATHS_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/$ah_prefix-status.json" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_STATUS_FAILED
    stop_privacy_observers || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_CAPTURE_NOT_DRAINED
    content_provider_stop_control_observer || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_CONTROL_NOT_DRAINED
    wait "$TLS_POLICY_SERVER_PID" || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_ORIGIN_FAILED
    TLS_POLICY_SERVER_PID=
    install -o root -g root -m 0600 "$ah_origin_report" "$WORK/$ah_prefix-origin.json"
    ah_output=$ah_user/digest-peers-first-object.bin
    ah_sha=$(sha256sum "$ah_output" | awk '{print $1}')
    # No-clobber is rejected locally; do not add another authorized origin request.
    if timeout --signal=TERM --kill-after=5s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ah_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch-https --url https://destination.volparossa.test:18443/asset.bin --origin-digest \
        --ca-file "$ah_user/origin.pem" --cache "$ah_cache" --source-strategy peers-first \
        --local-output "$ah_output" >"$WORK/$ah_prefix-no-clobber.out" 2>"$WORK/$ah_prefix-no-clobber.err"; then
        fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_OVERWRITTEN
    fi
    grep -F 'already exists' "$WORK/$ah_prefix-no-clobber.err" >/dev/null \
        && [ "$(sha256sum "$ah_output" | awk '{print $1}')" = "$ah_sha" ] \
        && [ "$(stat -Lc '%a:%u:%g' "$ah_output")" = "600:$WORKER_UID:$WORKER_GID" ] \
        && [ "$(stat -Lc '%a:%u:%g' "$ah_user")" = "700:$WORKER_UID:$WORKER_GID" ] \
        && [ "$(stat -Lc '%a:%u:%g' "$ah_cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
        || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_OUTPUT_UNSAFE
    jq -n --arg path "$ah_output" --arg cache "$ah_cache" --arg sha "$ah_sha" \
        --argjson bytes "$(stat -Lc '%s' "$ah_output")" --argjson user "$WORKER_UID" \
        --argjson agent "$AGENT_UID" --argjson group "$ah_control_gid" \
        '{path:$path,agent_cache:$cache,sha256:$sha,bytes:$bytes,user_uid:$user,agent_uid:$agent,
          control_gid:$group,output_mode:"0600",directory_mode:"0700",agent_cache_mode:"0700",
          client_cache_initially_absent:true,local_output_initially_absent:true,
          no_clobber_verified:true,no_clobber_rejected_before_network:true,
          agent_mount_positive_control:true,agent_cannot_read_user_output_directory:true,
          client_mount_cannot_read_origin:true}' >"$WORK/$ah_prefix-output.json"
    content_provider_adaptive_https_cleanup || fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_CLEANUP_FAILED
    rm -- "$ah_origin/object.bin"
    jq -n '{user_output_removed:true,user_directory_removed:true,fixture_ca_removed:true,
        origin_body_removed:true}' >"$WORK/$ah_prefix-cleanup.json"
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

    content_provider_adaptive_https_run

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
