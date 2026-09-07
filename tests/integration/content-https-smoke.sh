#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the exact-build disposable guest. No host TLS trust/network changes.
# shellcheck disable=SC2154,SC2034 # Parent owns UID, capture, process and cleanup slots.

content_https_event_count() {
    awk -v baseline="$https_baseline" -v event="event=$2" '
        $1 ~ /^[0-9]+$/ && $1 > baseline && $3 == event { count++ }
        END { print count+0 }
    ' "$WORK/logs-$1.txt"
}

content_https_phase() {
    https_variant=$1
    https_prefix=content-https-$https_variant
    PHASE=$https_prefix-provider
    https_peer_report=$WORK/destination/$https_prefix-peers.json
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$https_binary" peers "$https_root" 47.163.4.2:18080 \
        "$https_variant" "$https_peer_report" >"$WORK/$https_prefix-peers.log" 2>&1 &
    DESTINATION_PID=$!
    https_peer_pid=$DESTINATION_PID
    wait_observer "$DESTINATION_PID" "$https_peer_report.ready" || fail HTTPS_PEERS_NOT_READY

    PHASE=$https_prefix-capture
    start_privacy_observers "$https_prefix-privacy" || fail HTTPS_PRIVACY_CAPTURE_UNAVAILABLE
    ip netns exec "$CLIENT" python3 "$WORK/bin/a02-observer.py" client \
        "$WORK/$https_prefix-client-capture.json" "$WORK/$https_prefix-client-capture.ready" - \
        --benchmark-relays "$BENCH_INDEX1" "$BENCH_INDEX2" \
        "$BENCH_CLIENT_IF1" "$BENCH_CLIENT_IF2" underlay \
        >"$WORK/$https_prefix-client-capture.log" 2>&1 &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a02-observer.py" exit \
        "$WORK/$https_prefix-exit-capture.json" "$WORK/$https_prefix-exit-capture.ready" - \
        --benchmark-relays "$BENCH_INDEX1" "$BENCH_INDEX2" \
        "$BENCH_EXIT_IF1" "$BENCH_EXIT_IF2" xd \
        >"$WORK/$https_prefix-exit-capture.log" 2>&1 &
    EXIT_OBSERVER_PID=$!
    if ! wait_observer "$CLIENT_OBSERVER_PID" "$WORK/$https_prefix-client-capture.ready" \
        || ! wait_observer "$EXIT_OBSERVER_PID" "$WORK/$https_prefix-exit-capture.ready"; then
        fail HTTPS_APPLICATION_CAPTURE_UNAVAILABLE
    fi
    capture_product_logs
    https_baseline=$(client_log_baseline_ms) || fail HTTPS_EVENT_BASELINE_UNAVAILABLE

    PHASE=$https_prefix-consumer
    https_client_root=$WORK/client-fixtures/$https_prefix
    [ ! -e "$https_client_root" ] || fail HTTPS_CLIENT_CACHE_NOT_EMPTY
    https_client_report=$WORK/client-fixtures/$https_prefix-consumer.json
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$https_binary" consume "$https_client_root" 47.163.4.2:18443 \
        "$WORK/client-fixtures/content-https-origin.der" 47.163.4.2:18080 \
        "$https_variant" "$https_client_report" >"$WORK/$https_prefix-consumer.log" 2>&1 &
    DOWNLOAD_CLIENT_PID=$!
    https_client_status=0
    wait "$DOWNLOAD_CLIENT_PID" || https_client_status=$?
    DOWNLOAD_CLIENT_PID=
    [ "$https_client_status" -eq 0 ] || fail HTTPS_CONTENT_CONSUMER_FAILED
    https_peer_status=0
    wait "$DESTINATION_PID" || https_peer_status=$?
    DESTINATION_PID=
    [ "$https_peer_status" -eq 0 ] || fail HTTPS_CONTENT_PEERS_FAILED
    if ! benchmark_capture_paths "$https_prefix-live" mptcp \
        || ! jq -e --arg context "$https_context" '.route_context_id == $context' \
            "$WORK/$https_prefix-live-selection.json" >/dev/null; then
        fail HTTPS_ROUTE_CHANGED_DURING_TRANSFER
    fi
    stop_observers || fail HTTPS_APPLICATION_CAPTURE_INCOMPLETE
    stop_privacy_observers || fail HTTPS_PRIVACY_CAPTURE_INCOMPLETE
    for https_attempt in 1 2 3 4 5 6 7 8 9 10; do
        capture_product_logs
        https_ingress_count=$(content_https_event_count client INGRESS_TCP_STREAM_COMPLETED)
        https_exit_count=$(content_https_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        [ "$https_ingress_count" -lt 3 ] || [ "$https_exit_count" -lt 3 ] || break
        sleep 0.1
    done
    if [ "$https_ingress_count" -lt 3 ] || [ "$https_exit_count" -lt 3 ]; then
        fail HTTPS_THREE_PROTECTED_FLOWS_NOT_PROVEN
    fi
    install -o root -g root -m 0600 "$https_client_report" "$WORK/$https_prefix-consumer.json"
    install -o root -g root -m 0600 "$https_peer_report" "$WORK/$https_prefix-peers.json"
    jq -n --argjson pid "$https_peer_pid" --argjson baseline "$https_baseline" \
        --argjson ingress "$https_ingress_count" --argjson exit "$https_exit_count" \
        --arg sha "$(sha256sum "$https_client_root/object.bin" | awk '{print $1}')" \
        --argjson bytes "$(stat -Lc '%s' "$https_client_root/object.bin")" \
        '{peer_pid:$pid,event_baseline_unix_ms:$baseline,ingress_completed:$ingress,
          exit_mptcp_tls_open_completed:$exit,object_sha256:$sha,bytes:$bytes,
          client_cache_initially_absent:true,client_cannot_read_origin_or_replica_files:true}' \
        >"$WORK/$https_prefix-gates.json"
}

content_https_run() {
    PHASE=content-https-selection
    https_binary=$binary_directory/examples/https-content-acceptance-fixture
    # Select before starting bounded origin/metadata lifetimes. The existing route is reused;
    # each of the six app connections still gets its own genuine MPTCP/TLS/OPEN_TCP flow.
    benchmark_select_route content-https mptcp || fail HTTPS_MPTCP_SELECTION_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-https-selection.json" || fail HTTPS_MPTCP_SELECTION_INVALID
    https_context=$(jq -er '.route_context_id' "$WORK/content-https-selection.json")
    PHASE=content-https-seed
    https_root=$WORK/content-https-seed/publication
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$WORK/content-https-seed"
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$https_binary" seed "$https_root" >"$WORK/content-https-seed.log" 2>&1 \
        || fail HTTPS_CONTENT_SEED_FAILED
    install -o root -g root -m 0600 "$https_root/publication.json" "$WORK/content-https-publication.json"
    for https_source_file in object.bin manifest.bin descriptor.bin replica-a replica-b; do
        if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$https_root/$https_source_file"; then
            fail HTTPS_CLIENT_CAN_READ_SOURCE_FILES
        fi
    done
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    PHASE=content-https-origin
    https_origin_report=$WORK/destination/content-https-origin.json
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$https_binary" origin "$https_root" 47.163.4.2:18443 \
        "$WORK/destination/content-https-origin.der" "$https_origin_report" 3 \
        >"$WORK/content-https-origin.log" 2>&1 &
    TLS_POLICY_SERVER_PID=$!
    wait_observer "$TLS_POLICY_SERVER_PID" "$https_origin_report.ready" || fail HTTPS_ORIGIN_NOT_READY
    # Public fixture certificate is the only out-of-band client input. No descriptor, manifest,
    # publisher key, private TLS key or OS-wide interception CA is passed to the consumer.
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
        "$WORK/destination/content-https-origin.der" "$WORK/client-fixtures/content-https-origin.der"
    content_https_phase complete
    content_https_phase missing
    https_origin_status=0
    wait "$TLS_POLICY_SERVER_PID" || https_origin_status=$?
    TLS_POLICY_SERVER_PID=
    [ "$https_origin_status" -eq 0 ] || fail HTTPS_ORIGIN_FAILED
    install -o root -g root -m 0600 "$https_origin_report" "$WORK/content-https-origin.json"
    benchmark_disconnect_route content-https || fail HTTPS_ROUTE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-https-smoke.py" \
        evidence "$WORK" "$WORK/content-https-evidence.json" || fail HTTPS_CONTENT_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-https-complete
}

content_https_finalize_report() {
    https_status=$1
    https_evidence=$(optional_json_evidence "$WORK/content-https-evidence.json")
    https_host=$(optional_json_evidence "$WORK/a15-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" \
        --arg blocker "$OBSERVED_BLOCKER" --argjson status "$https_status" \
        --argjson evidence "$https_evidence" --argjson host "$https_host" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-https-content-network",source_revision:$revision,
       run_id:$run,phase:$phase,runner_exit_status:$status,transfer:$evidence,
       success:($status == 0 and $evidence.success == true and $complete and $remaining == 0
         and $host.unchanged == true),observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host|del(.acceptance_id)),
       scope:"origin-cooperating native HTTPS client; fixture-only app trust, two partial stores at one peer endpoint",
       browser_integration_claimed:false,provider_discovery_claimed:false,
       distinct_provider_nodes_claimed:false,speed_improvement_claimed:false,
       full_c08_claimed:false,full_alpha_acceptance_claimed:false}
    ' >"$WORK/content-https-smoke.json" || return 1
    for https_artifact in "$WORK"/content-https-*.json "$WORK"/content-https-*.txt \
        "$WORK"/content-https-*.log "$WORK"/content-https-*.out "$WORK"/content-https-*.err; do
        [ ! -f "$https_artifact" ] || [ -L "$https_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$https_artifact" \
                "$output_directory/$(basename -- "$https_artifact")"
    done
    python3 -B "$source_directory/tests/integration/content-https-smoke.py" \
        report "$WORK/content-https-smoke.json" "$expected_commit"
}
