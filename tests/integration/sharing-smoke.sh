#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only after the disposable Debian/KVM/root guards in kvm-alpha-topology.sh.
# shellcheck disable=SC2154 # Exact namespaces, identities and ownership are parent-owned.

sharing_python() {
    python3 "$source_directory/tests/integration/sharing-smoke.py" "$@"
}

sharing_extend_network() {
    reciprocity_extend_network
    # B1 is dormant in this scenario. Its existing namespace becomes a restricted fanout;
    # only three exact Exit endpoints move, and every measured TX crosses sharing0.
    for sharing_interface in xr0 xr2 xd; do
        ip -n "$EXIT_NODE" link set "$sharing_interface" netns "$B1"
        ip -n "$B1" link set "$sharing_interface" up
    done
    ip -n "$B1" address replace 10.241.20.2/30 dev xr0
    ip -n "$B1" address replace 10.241.22.2/30 dev xr2
    ip -n "$B1" address replace 10.241.31.1/30 dev xd
    link_nodes "$EXIT_NODE" sharing0 10.241.36.1/30 "$B1" sharepeer 10.241.36.2/30
    ip -n "$EXIT_NODE" route replace 42.158.0.1/32 via 10.241.36.2 dev sharing0 src 46.162.3.1
    ip -n "$EXIT_NODE" route replace 45.161.2.1/32 via 10.241.36.2 dev sharing0 src 46.162.3.1
    ip -n "$EXIT_NODE" route replace 10.241.31.2/32 via 10.241.36.2 dev sharing0 src 10.241.36.1
    ip -n "$B1" route replace 46.162.3.1/32 via 10.241.36.1 dev sharepeer
    ip -n "$B1" route replace 42.158.0.1/32 via 10.241.20.1 dev xr0
    ip -n "$B1" route replace 45.161.2.1/32 via 10.241.22.1 dev xr2
    ip -n "$DEST" route add 10.241.36.0/30 via 10.241.31.1 dev dx
    ip netns exec "$B1" nft -f - <<'NFT'
table inet sharing_fixture {
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "sharepeer" oifname { "xr0", "xr2" } ip saddr 46.162.3.1 ip daddr { 42.158.0.1, 45.161.2.1 } accept
    iifname { "xr0", "xr2" } oifname "sharepeer" ip saddr { 42.158.0.1, 45.161.2.1 } ip daddr 46.162.3.1 accept
    iifname "sharepeer" oifname "xd" ip saddr 10.241.36.1 ip daddr 10.241.31.2 udp dport 18081 accept
    iifname "xd" oifname "sharepeer" ip saddr 10.241.31.2 ip daddr 10.241.36.1 udp sport 18081 accept
  }
}
NFT
    ip netns exec "$B1" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    for sharing_peer in 42.158.0.1 45.161.2.1 10.241.31.2; do
        ip -n "$EXIT_NODE" -j route get "$sharing_peer" \
            | jq -e 'length == 1 and .[0].dev == "sharing0"' >/dev/null \
            || fail SHARING_PHYSICAL_EGRESS_MISMATCH
    done
    # The Client's local Internet route exists for its Exit capability; worker-UID
    # applications are intercepted and packet captures reject any direct payload egress.
    if ip -n "$CLIENT" route get 46.162.3.1 >/dev/null 2>&1; then
        fail SHARING_DIRECT_EXIT_ROUTE_PRESENT
    fi
    sharing_python snapshot "$WORK" "$RUN_ID" "$EXIT_NODE" baseline
}

sharing_phase() {
    sharing_phase_file=$(mktemp "$WORK/sharing-app/phase.XXXXXX")
    printf '%s\n' "$1" >"$sharing_phase_file"
    chmod 0644 "$sharing_phase_file"
    mv -fT -- "$sharing_phase_file" "$WORK/sharing-app/phase"
}

sharing_run() {
    PHASE=sharing-discovery
    # The sticky disposable directory permits only each unprivileged fixture's own records;
    # the root-owned phase marker cannot be replaced by either fixture identity.
    install -d -o root -g root -m 1777 "$WORK/sharing-app"
    for sharing_fixture in reciprocity-smoke.py sharing-smoke.py; do
        install -o root -g root -m 0555 \
            "$source_directory/tests/integration/$sharing_fixture" "$WORK/bin/$sharing_fixture"
    done
    reciprocity_agent_snapshot before
    reciprocity_wait_neighbors || fail SHARING_NEIGHBOR_DISCOVERY_UNAVAILABLE
    (reciprocity_connect client) || fail SHARING_NATIVE_ROUTE_UNAVAILABLE
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    sharing_phase waiting
    ip netns exec "$DEST" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/sharing-smoke.py" server \
        "$WORK/sharing-app" "$RUN_ID" >"$WORK/sharing-server.log" 2>&1 &
    sharing_server_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $sharing_server_pid"
    ip netns exec "$B1" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/sharing-smoke.py" owner-sink \
        "$WORK/sharing-app" "$RUN_ID" >"$WORK/sharing-owner-sink.log" 2>&1 &
    sharing_sink_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $sharing_sink_pid"
    reciprocity_wait_file "$WORK/sharing-app/server.ready" "$sharing_server_pid" \
        || fail SHARING_DESTINATION_NOT_READY
    reciprocity_wait_file "$WORK/sharing-app/owner-sink.ready" "$sharing_sink_pid" \
        || fail SHARING_OWNER_SINK_NOT_READY
    sharing_capture_pids=
    for sharing_node in client relay0 relay2 exit; do
        sharing_namespace=$(reciprocity_namespace "$sharing_node")
        ip netns exec "$sharing_namespace" python3 "$WORK/bin/sharing-smoke.py" capture \
            "$WORK" "$RUN_ID" "$sharing_node" >"$WORK/sharing-capture-$sharing_node.log" 2>&1 &
        sharing_capture_pid=$!
        sharing_capture_pids="$sharing_capture_pids $sharing_capture_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $sharing_capture_pid"
        reciprocity_wait_file "$WORK/reciprocity-capture-$sharing_node.ready" "$sharing_capture_pid" \
            || fail SHARING_CAPTURE_NOT_READY
    done
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/sharing-smoke.py" client \
        "$WORK/sharing-app" "$RUN_ID" >"$WORK/sharing-client.log" 2>&1 &
    sharing_client_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $sharing_client_pid"
    ip netns exec "$EXIT_NODE" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/sharing-smoke.py" owner \
        "$WORK/sharing-app" "$RUN_ID" >"$WORK/sharing-owner.log" 2>&1 &
    sharing_owner_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $sharing_owner_pid"
    sharing_phase idle
    reciprocity_wait_file "$WORK/sharing-app/client.active" "$sharing_client_pid" \
        || fail SHARING_PROTECTED_APPLICATION_UNAVAILABLE
    for sharing_window in idle owner recovery; do
        PHASE=sharing-$sharing_window
        sharing_phase "$sharing_window"
        sleep 1
        sharing_python snapshot "$WORK" "$RUN_ID" "$EXIT_NODE" "$sharing_window-before"
        sleep 5
        sharing_python snapshot "$WORK" "$RUN_ID" "$EXIT_NODE" "$sharing_window-after"
    done
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        paths >"$WORK/sharing-paths-client.txt"
    reciprocity_agent_snapshot after
    sharing_phase 'done'
    for sharing_pid in "$sharing_client_pid" "$sharing_owner_pid" "$sharing_server_pid" "$sharing_sink_pid"; do
        wait "$sharing_pid" || fail SHARING_APPLICATION_FAILED
    done
    for sharing_pid in $sharing_capture_pids; do kill -TERM "$sharing_pid" || fail SHARING_CAPTURE_EARLY_EXIT; done
    for sharing_pid in $sharing_capture_pids; do wait "$sharing_pid" || fail SHARING_CAPTURE_FAILED; done
    RECIPROCITY_PIDS=
    timeout --kill-after=5 30 "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-exit/control/agent.sock" disconnect \
        >"$WORK/sharing-route-cleanup.txt" 2>&1 || fail SHARING_ROUTE_CLEANUP_FAILED
    sharing_python snapshot "$WORK" "$RUN_ID" "$EXIT_NODE" route-cleanup
    sharing_python evidence "$WORK" "$RUN_ID" || fail SHARING_EVIDENCE_INVALID
    PHASE=sharing-complete
    OBSERVED_BLOCKER=
}

sharing_verify_cleanup() {
    [ -f "$WORK/sharing-baseline.json" ] || return 0
    sharing_python snapshot "$WORK" "$RUN_ID" "$EXIT_NODE" cleanup \
        && sharing_python cleanup-evidence "$WORK" "$RUN_ID"
}

sharing_finalize_report() {
    sharing_status=$1
    sharing_evidence='{"success":false}'
    sharing_cleanup='{"baseline_restored":false}'
    [ ! -s "$WORK/sharing-evidence.json" ] || sharing_evidence=$(cat "$WORK/sharing-evidence.json")
    [ ! -s "$WORK/sharing-cleanup-evidence.json" ] || sharing_cleanup=$(cat "$WORK/sharing-cleanup-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" --argjson status "$sharing_status" \
        --argjson evidence "$sharing_evidence" --argjson scheduler_cleanup "$sharing_cleanup" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" \
        '$evidence + {schema_version:1,report_kind:"volparossa-owner-priority-uplink",
          source_revision:$revision,run_id:$run_id,phase:$phase,
          success:($status == 0 and $evidence.success and $complete and $remaining == 0 and
            $scheduler_cleanup.baseline_restored and $host[0].unchanged),
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:($scheduler_cleanup + {complete:$complete,remaining_owned_objects:$remaining}),
          host_state:($host[0] | del(.acceptance_id))}' >"$WORK/sharing-smoke.json"
    for sharing_artifact in "$WORK"/sharing-*.json "$WORK"/sharing-*.txt "$WORK"/sharing-*.log \
        "$WORK"/reciprocity-capture-*.json "$WORK"/reciprocity-node-*.json \
        "$WORK"/reciprocity-connect-client.* "$WORK"/mpquic-*-client.log "$WORK"/mpquic-*-exit.log; do
        if [ ! -f "$sharing_artifact" ] || [ -L "$sharing_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$sharing_artifact" \
            "$output_directory/$(basename -- "$sharing_artifact")"
    done
    for sharing_artifact in "$WORK"/sharing-app/*.json; do
        if [ ! -f "$sharing_artifact" ] || [ -L "$sharing_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$sharing_artifact" \
            "$output_directory/sharing-app-$(basename -- "$sharing_artifact")"
    done
    jq -e '.success == true' "$WORK/sharing-smoke.json" >/dev/null
}
