#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only inside the exact-build disposable KVM topology.
# shellcheck disable=SC2154,SC2034

content_provider_event_count() {
    awk -v baseline="$provider_baseline_ms" -v event="event=$2" '
        $1 ~ /^[0-9]+$/ && $1 > baseline && $3 == event { count++ }
        END { print count + 0 }
    ' "$WORK/logs-$1.txt"
}

content_provider_node() {
    case $1 in
        relay0) provider_ns=$R0; provider_ip=42.158.0.1 ;;
        relay1) provider_ns=$R1; provider_ip=44.160.1.1 ;;
        relay2) provider_ns=$R2; provider_ip=45.161.2.1 ;;
        relay3) provider_ns=$R3; provider_ip=48.164.4.1 ;;
        relay4) provider_ns=$R4; provider_ip=49.165.5.1 ;;
        relay5) provider_ns=$R5; provider_ip=50.166.6.1 ;;
        *) return 1 ;;
    esac
}

content_provider_filter_link() {
    # This fixture-only physical link models Internet reachability for the generic
    # authenticated control RPC. It cannot carry TCP content, WG, or forwarding.
    ip netns exec "$1" nft -f - <<RULES
table inet vpa_content_control_$2 {
    chain input {
        type filter hook input priority -20; policy accept;
        iifname "$3" ip saddr $5 ip daddr $4 udp dport 41000 accept
        iifname "$3" ip saddr $5 ip daddr $4 udp sport 41000 accept
        iifname "$3" drop
    }
    chain output {
        type filter hook output priority -20; policy accept;
        oifname "$3" ip saddr $4 ip daddr $5 udp dport 41000 accept
        oifname "$3" ip saddr $4 ip daddr $5 udp sport 41000 accept
        oifname "$3" drop
    }
    chain forward {
        type filter hook forward priority -20; policy accept;
        iifname "$3" drop
        oifname "$3" drop
    }
}
RULES
}

content_provider_control_underlay() {
    provider_control_node=$(jq -er --arg peer "$provider_control_peer" \
        'to_entries[] | select(.value == $peer) | .key' "$WORK/a01-expected-peers.json") \
        || fail CONTENT_PROVIDER_CONTROL_NODE_INVALID
    content_provider_node "$provider_control_node" || fail CONTENT_PROVIDER_CONTROL_NODE_INVALID
    provider_control_ns=$provider_ns
    provider_control_ip=$provider_ip
    provider_control_ips=$provider_ip
    provider_slot=0
    for provider_node in "$provider_node_a" "$provider_node_b"; do
        content_provider_node "$provider_node" || fail CONTENT_PROVIDER_NODE_INVALID
        provider_segment=$((80 + provider_slot))
        link_nodes "$provider_control_ns" "cp$provider_slot" "10.241.$provider_segment.1/30" \
            "$provider_ns" "pc$provider_slot" "10.241.$provider_segment.2/30"
        content_provider_filter_link "$provider_control_ns" "$provider_slot" "cp$provider_slot" \
            "$provider_control_ip" "$provider_ip" || fail CONTENT_PROVIDER_CONTROL_FILTER_FAILED
        content_provider_filter_link "$provider_ns" "$provider_slot" "pc$provider_slot" \
            "$provider_ip" "$provider_control_ip" || fail CONTENT_PROVIDER_CONTROL_FILTER_FAILED
        ip -n "$provider_control_ns" route add "$provider_ip/32" \
            via "10.241.$provider_segment.2" dev "cp$provider_slot" src "$provider_control_ip"
        ip -n "$provider_ns" route add "$provider_control_ip/32" \
            via "10.241.$provider_segment.1" dev "pc$provider_slot" src "$provider_ip"
        # Retain actual kernel-selected routes, not only the intended commands.
        ip -n "$provider_control_ns" -j route get "$provider_ip" \
            >"$WORK/content-provider-control-$provider_node-out.json"
        ip -n "$provider_ns" -j route get "$provider_control_ip" \
            >"$WORK/content-provider-control-$provider_node-back.json"
        provider_control_ips=$provider_control_ips,$provider_ip
        provider_slot=$((provider_slot + 1))
    done
}

content_provider_start_control_observer() {
    provider_control_prefix=$1
    case $provider_control_prefix in content-provider-*) ;; *) return 1 ;; esac
    [ -z "$PROVIDER_CONTROL_PID" ] || return 1
    ip netns exec "$provider_control_ns" python3 "$WORK/bin/privacy-observer.py" \
        content-control "$WORK/$provider_control_prefix.json" \
        "$WORK/$provider_control_prefix.ready" --content-providers \
        "--content-control=$provider_control_ips" cp0 cp1 \
        >"$WORK/$provider_control_prefix.log" 2>&1 &
    PROVIDER_CONTROL_PID=$!
    wait_observer "$PROVIDER_CONTROL_PID" "$WORK/$provider_control_prefix.ready"
}

content_provider_stop_control_observer() {
    [ -n "$PROVIDER_CONTROL_PID" ] || return 1
    kill -TERM "$PROVIDER_CONTROL_PID" || return 1
    wait "$PROVIDER_CONTROL_PID" || return 1
    PROVIDER_CONTROL_PID=
}

content_provider_run() {
    PHASE=content-provider-selection
    benchmark_select_route content-provider mptcp || fail CONTENT_PROVIDER_MPTCP_SELECTION_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-provider-selection.json" || fail CONTENT_PROVIDER_SELECTION_INVALID
    provider_context=$(jq -er '.route_context_id' "$WORK/content-provider-selection.json")
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/content-provider-status-before.json" \
        2>"$WORK/content-provider-status-before.err" || fail CONTENT_PROVIDER_CONTROL_STATUS_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' \
        "$WORK/content-provider-status-before.json") || fail CONTENT_PROVIDER_CONTROL_RELAY_UNAVAILABLE
    # These spare nodes are not the selected data relays. Exclude the actual control
    # relay as well; a random fixture identity must not make a supplier its own broker.
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '
        . as $peers | ["relay4", "relay5", "relay3"]
        | map(select($peers[.] != $control)) | .[:2] | select(length == 2)' \
        "$WORK/a01-expected-peers.json") || fail CONTENT_PROVIDER_INDEPENDENT_NODES_UNAVAILABLE
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    jq -n --argjson nodes "$provider_nodes" --arg control "$provider_control_peer" \
        '{provider_nodes:$nodes,control_relay_peer_id:$control}' >"$WORK/content-provider-layout.json"
    PHASE=content-provider-control-underlay
    content_provider_control_underlay

    PHASE=content-provider-seed
    provider_root=$WORK/content-provider-seed/publication
    provider_a=$WORK/state-$provider_node_a/content
    provider_b=$WORK/state-$provider_node_b/content
    provider_client=$WORK/state-client/content
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 \
        "$WORK/content-provider-seed" "$provider_a" "$provider_b" "$provider_client"
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/examples/content-acceptance-fixture" seed-providers \
        "$provider_root" "$provider_a/cache" "$provider_b/cache" \
        >"$WORK/content-provider-seed.log" 2>&1 || fail CONTENT_PROVIDER_SEED_FAILED
    install -o root -g root -m 0600 "$provider_root/publication.json" \
        "$WORK/content-provider-publication.json"
    provider_publisher=$(jq -er '.publisher_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-provider-publication.json") || fail CONTENT_PROVIDER_PUBLISHER_INVALID
    jq -e '.publisher_removed == true and .publisher_private_key_persisted == false
        and .bytes == 2097275 and .chunks == 9
        and .replica_a_chunks == 5 and .replica_b_chunks == 4' \
        "$WORK/content-provider-publication.json" >/dev/null || fail CONTENT_PROVIDER_PUBLICATION_INVALID
    # Copy only public, independently authenticated metadata; never copy/rehome cache roots.
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$provider_root/manifest.bin" \
        "$provider_client/manifest.bin"
    provider_manifest=$provider_client/manifest.bin
    if [ -e "$provider_client/cache" ] || [ -e "$provider_client/object.bin" ]; then
        fail CONTENT_PROVIDER_CLIENT_CACHE_NOT_EMPTY
    fi
    provider_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $provider_client_pid in ''|0|*[!0-9]*) fail CONTENT_PROVIDER_CLIENT_PID_INVALID ;; esac
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$provider_manifest" || fail CONTENT_PROVIDER_ISOLATION_PROBE_UNAVAILABLE
    for provider_private in "$WORK/state-relay3" "$WORK/state-relay4" \
        "$WORK/state-relay5" "$provider_root"; do
        if nsenter --target "$provider_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$provider_private"; then
            fail CONTENT_PROVIDER_LOCAL_REPLICA_SHORTCUT
        fi
    done

    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail CONTENT_PROVIDER_EVENT_BASELINE_UNAVAILABLE

    PHASE=content-provider-register
    for provider_node in "$provider_node_a" "$provider_node_b"; do
        case $provider_node in
            relay4) provider_address=49.165.5.1; provider_hostname=provider-a.volparossa.test ;;
            relay5) provider_address=50.166.6.1; provider_hostname=provider-b.volparossa.test ;;
            relay3) provider_address=48.164.4.1; provider_hostname=provider-c.volparossa.test ;;
            *) fail CONTENT_PROVIDER_NODE_INVALID ;;
        esac
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node/control/agent.sock" \
            content serve --manifest "$provider_manifest" --publisher-key "$provider_publisher" \
            --cache "$WORK/state-$provider_node/content/cache" --bind "$provider_address:18080" \
            --advertised-hostname "$provider_hostname" \
            >"$WORK/content-provider-$provider_node-serve.json" \
            2>"$WORK/content-provider-$provider_node-serve.err" || fail CONTENT_PROVIDER_REGISTRATION_FAILED
        jq -e '.serving == true and .publications == 1' \
            "$WORK/content-provider-$provider_node-serve.json" >/dev/null \
            || fail CONTENT_PROVIDER_REGISTRATION_NOT_ACTIVE
    done

    PHASE=content-provider-capture
    start_privacy_observers content-provider-privacy || fail CONTENT_PROVIDER_PRIVACY_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer content-provider-control-privacy \
        || fail CONTENT_PROVIDER_CONTROL_CAPTURE_UNAVAILABLE
    PHASE=content-provider-fetch
    timeout --signal=TERM --kill-after=5s 120s "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch --manifest "$provider_manifest" --publisher-key "$provider_publisher" \
        --cache "$provider_client/cache" --output "$provider_client/object.bin" \
        >"$WORK/content-provider-fetch.json" 2>"$WORK/content-provider-fetch.err" \
        || fail CONTENT_PROVIDER_RUNTIME_FETCH_FAILED
    benchmark_capture_paths content-provider-live mptcp || fail CONTENT_PROVIDER_LIVE_PATHS_UNAVAILABLE
    jq -e --arg context "$provider_context" '.route_context_id == $context' \
        "$WORK/content-provider-live-selection.json" >/dev/null || fail CONTENT_PROVIDER_ROUTE_CHANGED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content status >"$WORK/content-provider-status-after.json" \
        2>"$WORK/content-provider-status-after.err" || fail CONTENT_PROVIDER_CONTROL_STATUS_UNAVAILABLE
    for provider_control_receipt in "$WORK/content-provider-status-after.json" "$WORK/content-provider-fetch.json"; do
        jq -e --arg control "$provider_control_peer" '.control_relay_peer_id == $control' \
            "$provider_control_receipt" >/dev/null || fail CONTENT_PROVIDER_CONTROL_RELAY_CHANGED
    done
    stop_privacy_observers || fail CONTENT_PROVIDER_PRIVACY_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail CONTENT_PROVIDER_CONTROL_CAPTURE_INCOMPLETE
    capture_product_logs
    provider_query_events=0
    provider_offer_events=0
    for provider_control in relay0 relay1 relay2 relay3 relay4 relay5; do
        provider_query_events=$((provider_query_events + $(content_provider_event_count "$provider_control" CONTENT_PROVIDER_QUERY_STARTED)))
        provider_offer_events=$((provider_offer_events + $(content_provider_event_count "$provider_control" CONTENT_PROVIDER_OFFER_VERIFIED)))
    done
    provider_discovery_events=$(content_provider_event_count client CONTENT_DISCOVERY_COMPLETED)
    jq -n --arg sha256 "$(sha256sum "$provider_client/object.bin" | awk '{print $1}')" \
        --argjson bytes "$(stat -Lc '%s' "$provider_client/object.bin")" \
        --argjson baseline "$provider_baseline_ms" --argjson queries "$provider_query_events" \
        --argjson verified "$provider_offer_events" --argjson discovered "$provider_discovery_events" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          client_mount_cannot_read_replica_stores:true,publisher_process_exited_before_fetch:true,
          event_baseline_unix_ms:$baseline,generic_dht_queries:$queries,
          authenticated_upstream_offers:$verified,client_forwarded_discovery:$discovered}' \
        >"$WORK/content-provider-object.json"
    # The exact same explicit native publication also supports the independently
    # origin-authenticated HTTPS case; its checker owns those additional claims.
    # shellcheck source=tests/integration/content-provider-https-smoke.sh
    . "$source_directory/tests/integration/content-provider-https-smoke.sh"
    content_provider_https_run
    # Add one normal operator publication without replacing the 5+4/HTTPS fixture authority.
    content_publication_run
    # Public publisher-key/name retrieval needs no manifest file at the consumer.
    # shellcheck source=tests/integration/content-named-smoke.sh
    . "$source_directory/tests/integration/content-named-smoke.sh"
    content_named_run
    PHASE=content-provider-stop
    for provider_node in "$provider_node_a" "$provider_node_b"; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node/control/agent.sock" \
            content stop >"$WORK/content-provider-$provider_node-stop.json" \
            2>"$WORK/content-provider-$provider_node-stop.err" || fail CONTENT_PROVIDER_STOP_FAILED
        jq -e '.serving == false and .publications == 0' \
            "$WORK/content-provider-$provider_node-stop.json" >/dev/null || fail CONTENT_PROVIDER_STOP_NOT_COMPLETE
    done
    benchmark_disconnect_route content-provider || fail CONTENT_PROVIDER_ROUTE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-provider-smoke.py" \
        evidence "$WORK" "$WORK/content-provider-evidence.json" || fail CONTENT_PROVIDER_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-provider-complete
}

content_provider_finalize_report() {
    provider_status=$1
    # Keep complete raw evidence even when the report fails, and never place the potentially
    # large native plus HTTPS capture bundle in a single operating-system argument.
    for provider_artifact in "$WORK"/content-provider-*.json "$WORK"/content-provider-*.txt \
        "$WORK"/content-provider-*.log "$WORK"/content-provider-*.out "$WORK"/content-provider-*.err; do
        [ ! -f "$provider_artifact" ] || [ -L "$provider_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$provider_artifact" \
                "$output_directory/$(basename -- "$provider_artifact")"
    done
    optional_json_evidence "$WORK/content-provider-evidence.json" \
        >"$WORK/content-provider-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/content-provider-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$provider_status" \
        --slurpfile evidence_input "$WORK/content-provider-report-evidence.part" \
        --slurpfile host_input "$WORK/content-provider-report-host.part" \
        --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      $evidence_input[0] as $evidence | $host_input[0] as $host |
      {schema_version:1,report_kind:"volparossa-native-content-providers",
       source_revision:$revision,run_id:$run_id,phase:$phase,
       success:($status == 0 and $evidence.success == true and
         $evidence.ordinary_publication.success == true and $complete and
         $remaining == 0 and $host.unchanged == true),transfer:$evidence,
       runner_exit_status:$status,observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host | del(.acceptance_id)),
       scope:"explicit native publication and cooperative-origin HTTPS for the same object, two policy-authorized providers via generic DHT/control-relay discovery and protected MPTCP/TLS/WireGuard, complete peers and missing origin ranges",
       general_nat_reachability_claimed:false,full_c02_claimed:false,
       explicit_origin_authenticated_https:($evidence.https.success == true),
       normal_user_publication:($evidence.ordinary_publication.success == true),
       native_name_retrieval:($evidence.named_publication.success == true),
       browser_integration_claimed:false,arbitrary_https_integration_claimed:false,
       speed_improvement_claimed:false,full_alpha_acceptance_claimed:false}' \
        >"$WORK/content-provider-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/content-provider-smoke.json" \
        "$output_directory/content-provider-smoke.json"
    python3 -B "$source_directory/tests/integration/content-provider-smoke.py" \
        report "$WORK/content-provider-smoke.json" "$expected_commit"
}
