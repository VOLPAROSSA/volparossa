#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the exact-build disposable KVM topology. No host networking actions.
# shellcheck disable=SC2154,SC2034 # Guarded parent owns process slots, identities and cleanup.

content_network_event_after() {
    awk -v baseline="$content_baseline_ms" -v event="event=$2" '
        $1 ~ /^[0-9]+$/ && $1 > baseline && $3 == event { found=1 }
        END { exit !found }
    ' "$WORK/logs-$1.txt"
}

content_network_phase() {
    content_replica=$1
    content_prefix=content-$content_replica
    PHASE=$content_prefix-selection
    benchmark_select_route "$content_prefix" mptcp || fail CONTENT_MPTCP_SELECTION_UNAVAILABLE
    benchmark_bind_slots "$WORK/$content_prefix-selection.json" \
        || fail CONTENT_MPTCP_SELECTION_INVALID
    content_context=$(jq -er '.route_context_id' "$WORK/$content_prefix-selection.json")

    PHASE=$content_prefix-provider
    content_provider_report=$WORK/destination/$content_prefix-provider.json
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$content_binary" serve "$content_root" "$content_replica" \
        47.163.4.2:18080 "$content_provider_report" \
        >"$WORK/$content_prefix-provider.log" 2>&1 &
    DESTINATION_PID=$!
    content_serving_pid=$DESTINATION_PID
    wait_observer "$DESTINATION_PID" "$content_provider_report.ready" \
        || fail CONTENT_PROVIDER_NOT_READY

    PHASE=$content_prefix-capture
    start_privacy_observers "$content_prefix-privacy" || fail CONTENT_PRIVACY_CAPTURE_UNAVAILABLE
    ip netns exec "$CLIENT" python3 "$WORK/bin/a02-observer.py" client \
        "$WORK/$content_prefix-client-capture.json" "$WORK/$content_prefix-client-capture.ready" - \
        --benchmark-relays "$BENCH_INDEX1" "$BENCH_INDEX2" \
        "$BENCH_CLIENT_IF1" "$BENCH_CLIENT_IF2" underlay \
        >"$WORK/$content_prefix-client-capture.log" 2>&1 &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a02-observer.py" exit \
        "$WORK/$content_prefix-exit-capture.json" "$WORK/$content_prefix-exit-capture.ready" - \
        --benchmark-relays "$BENCH_INDEX1" "$BENCH_INDEX2" \
        "$BENCH_EXIT_IF1" "$BENCH_EXIT_IF2" xd \
        >"$WORK/$content_prefix-exit-capture.log" 2>&1 &
    EXIT_OBSERVER_PID=$!
    if ! wait_observer "$CLIENT_OBSERVER_PID" "$WORK/$content_prefix-client-capture.ready" \
        || ! wait_observer "$EXIT_OBSERVER_PID" "$WORK/$content_prefix-exit-capture.ready"; then
        fail CONTENT_APPLICATION_CAPTURE_UNAVAILABLE
    fi
    capture_product_logs
    content_baseline_ms=$(client_log_baseline_ms) || fail CONTENT_EVENT_BASELINE_UNAVAILABLE

    PHASE=$content_prefix-fetch
    content_fetch_report=$WORK/client-fixtures/$content_prefix-fetch.json
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$content_binary" fetch "$content_client_root" \
        "$WORK/client-fixtures/content-manifest.bin" "$content_publisher" \
        47.163.4.2:18080 "$content_fetch_report" \
        >"$WORK/$content_prefix-fetch.log" 2>&1 &
    DOWNLOAD_CLIENT_PID=$!
    content_client_status=0
    wait "$DOWNLOAD_CLIENT_PID" || content_client_status=$?
    DOWNLOAD_CLIENT_PID=
    [ "$content_client_status" -eq 0 ] || fail CONTENT_NETWORK_FETCH_FAILED
    content_provider_status=0
    wait "$DESTINATION_PID" || content_provider_status=$?
    DESTINATION_PID=
    [ "$content_provider_status" -eq 0 ] || fail CONTENT_NETWORK_PROVIDER_FAILED
    if ! benchmark_capture_paths "$content_prefix-live" mptcp \
        || ! jq -e --arg context "$content_context" '.route_context_id == $context' \
            "$WORK/$content_prefix-live-selection.json" >/dev/null; then
        fail CONTENT_ROUTE_CHANGED_DURING_FETCH
    fi
    stop_observers || fail CONTENT_APPLICATION_CAPTURE_INCOMPLETE
    stop_privacy_observers || fail CONTENT_PRIVACY_CAPTURE_INCOMPLETE
    for content_attempt in 1 2 3 4 5 6 7 8 9 10; do
        capture_product_logs
        if content_network_event_after client INGRESS_TCP_STREAM_COMPLETED \
            && content_network_event_after exit MPTCP_EXIT_FLOW_COMPLETED; then
            break
        fi
        sleep 0.1
    done
    if ! content_network_event_after client INGRESS_TCP_STREAM_COMPLETED \
        || ! content_network_event_after exit MPTCP_EXIT_FLOW_COMPLETED; then
        fail CONTENT_PROTECTED_STREAM_NOT_PROVEN
    fi
    install -o root -g root -m 0600 "$content_fetch_report" "$WORK/$content_prefix-fetch.json"
    install -o root -g root -m 0600 "$content_provider_report" "$WORK/$content_prefix-provider.json"
    jq -n --argjson pid "$content_serving_pid" --argjson baseline "$content_baseline_ms" \
        '{serving_pid:$pid,publisher_process_exited_before_fetch:true,
          event_baseline_unix_ms:$baseline,ingress_completed:true,exit_mptcp_tls_open_completed:true}' \
        >"$WORK/$content_prefix-gates.json"
    # Close the exact completed route before choosing the next provider's protected route.
    benchmark_disconnect_route "$content_prefix" || fail CONTENT_ROUTE_CLEANUP_FAILED
}

content_network_run() {
    PHASE=content-seed
    content_binary=$binary_directory/examples/content-acceptance-fixture
    content_root=$WORK/content-seed/publication
    content_client_root=$WORK/client-fixtures/content
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$WORK/content-seed"
    # Persistent cache markers bind their creator UID and inode: do not chown a seeded store.
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$content_binary" seed "$content_root" \
        >"$WORK/content-seed.log" 2>&1 || fail CONTENT_SEED_FAILED
    install -o root -g root -m 0600 "$content_root/publication.json" "$WORK/content-publication.json"
    jq -e '.publisher_removed == true and .publisher_private_key_persisted == false
        and .chunks == 9 and .bytes == 2097275 and .replica_a_chunks == 5 and .replica_b_chunks == 4
        and (.publisher_hex | test("^[0-9a-f]{64}$"))
        and (.object_sha256 | test("^[0-9a-f]{64}$"))' \
        "$WORK/content-publication.json" >/dev/null || fail CONTENT_PUBLICATION_INVALID
    content_publisher=$(jq -er '.publisher_hex' "$WORK/content-publication.json")
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$content_client_root"
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$content_root/manifest.bin" \
        "$WORK/client-fixtures/content-manifest.bin"
    if [ -e "$content_client_root/cache" ] || [ -e "$content_client_root/object.bin" ]; then
        fail CONTENT_CLIENT_CACHE_NOT_EMPTY
    fi
    # No client access to either replica or the removed publisher; only public trust metadata.
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$content_root/replica-a"; then
        fail CONTENT_REPLICA_ACCESS_NOT_ISOLATED
    fi
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    content_network_phase a
    jq -e '.complete == false and .cached_chunks == 5 and .chunks_received == 5
        and .missing == 4 and .output_bytes == 0 and .object_sha256 == null' \
        "$WORK/content-a-fetch.json" >/dev/null || fail CONTENT_FIRST_REPLICA_NOT_PARTIAL
    [ ! -e "$content_client_root/object.bin" ] || fail CONTENT_PARTIAL_OUTPUT_PUBLISHED
    content_network_phase b
    sha256sum "$content_client_root/object.bin" | awk '{print $1}' >"$WORK/content-object-sha256.txt"
    jq -n --arg sha256 "$(cat "$WORK/content-object-sha256.txt")" \
        --argjson bytes "$(stat -Lc '%s' "$content_client_root/object.bin")" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          client_cannot_read_replica_stores:true,publisher_process_exited_before_fetch:true}' \
        >"$WORK/content-object.json"
    python3 -B "$source_directory/tests/integration/content-network-smoke.py" \
        evidence "$WORK" "$WORK/content-evidence.json" || fail CONTENT_NETWORK_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-complete
}

content_network_finalize_report() {
    content_status=$1
    content_evidence=$(optional_json_evidence "$WORK/content-evidence.json")
    content_host=$(optional_json_evidence "$WORK/a15-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$content_status" --argjson evidence "$content_evidence" \
        --argjson host "$content_host" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-native-content-network",
       source_revision:$revision,run_id:$run_id,phase:$phase,
       success:($status == 0 and $evidence.success == true and $complete and
         $remaining == 0 and $host.unchanged == true),
       transfer:$evidence,runner_exit_status:$status,
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},
       host_state:($host | del(.acceptance_id)),
       scope:"two separate replica processes at one authorized destination through actual MPTCP/TLS/WireGuard; native signatures, not HTTPS origin authentication",
       distinct_provider_nodes_claimed:false,provider_discovery_claimed:false,
       full_alpha_acceptance_claimed:false,https_authentication_claimed:false}
    ' >"$WORK/content-network-smoke.json" || return 1
    for content_artifact in "$WORK"/content-*.json "$WORK"/content-*.txt \
        "$WORK"/content-*.log "$WORK"/content-*.out "$WORK"/content-*.err; do
        [ ! -f "$content_artifact" ] || [ -L "$content_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$content_artifact" \
                "$output_directory/$(basename -- "$content_artifact")"
    done
    python3 -B "$source_directory/tests/integration/content-network-smoke.py" \
        report "$WORK/content-network-smoke.json" "$expected_commit"
}
