#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only inside the guarded disposable KVM topology; overrides sharing hooks.
# shellcheck disable=SC2154

download_sharing_python() {
    python3 "$source_directory/tests/integration/download-sharing-smoke.py" "$@"
}

sharing_extend_network() {
    reciprocity_extend_network
    # Exit packets and independent owner traffic meet BEFORE the receiving Relay.
    # B1 is a dormant, disposable fanout, not a production peer or Internet gateway.
    for download_interface in r0x r2x; do
        case $download_interface in
            r0x) download_namespace=$R0; download_address=10.241.20.1/30 ;;
            r2x) download_namespace=$R2; download_address=10.241.22.1/30 ;;
        esac
        ip -n "$download_namespace" link set "$download_interface" netns "$B1"
        ip -n "$B1" link set "$download_interface" up
        ip -n "$B1" address replace "$download_address" dev "$download_interface"
    done
    link_nodes "$R0" down0 10.241.37.1/30 "$B1" d0 10.241.37.2/30
    link_nodes "$R2" down0 10.241.38.1/30 "$B1" d2 10.241.38.2/30
    # Accounting and the kernel-proven public underlay must name the SAME real receive
    # interface. Keep the public identity assigned throughout the move so existing
    # source-pinned peer routes remain valid; no production guard is bypassed.
    for download_namespace in "$R0" "$R2"; do
        if [ "$download_namespace" = "$R0" ]; then download_public=42.158.0.1
        else download_public=45.161.2.1; fi
        ip -n "$download_namespace" address add "$download_public/32" dev down0
        ip -n "$download_namespace" route replace default dev down0 scope global
        ip -n "$download_namespace" address del "$download_public/32" dev underlay
    done
    ip -n "$R0" route replace 46.162.3.1/32 via 10.241.37.2 dev down0 src 42.158.0.1
    ip -n "$R2" route replace 46.162.3.1/32 via 10.241.38.2 dev down0 src 45.161.2.1
    ip -n "$B1" route replace 42.158.0.1/32 via 10.241.37.1 dev d0
    ip -n "$B1" route replace 45.161.2.1/32 via 10.241.38.1 dev d2
    # Distinct source rules retain each selected physical Exit-facing leg, never cross-wire it.
    ip -n "$B1" route add table 137 10.241.20.0/30 dev r0x
    ip -n "$B1" route add table 137 46.162.3.1/32 via 10.241.20.2 dev r0x
    ip -n "$B1" rule add priority 137 from 42.158.0.1/32 lookup 137
    ip -n "$B1" route add table 138 10.241.22.0/30 dev r2x
    ip -n "$B1" route add table 138 46.162.3.1/32 via 10.241.22.2 dev r2x
    ip -n "$B1" rule add priority 138 from 45.161.2.1/32 lookup 138
    ip netns exec "$B1" nft -f - <<'NFT'
table inet download_fixture {
 chain forward {
  type filter hook forward priority 0; policy drop;
  iifname "d0" oifname "r0x" ip saddr 42.158.0.1 ip daddr 46.162.3.1 accept
  iifname "r0x" oifname "d0" ip saddr 46.162.3.1 ip daddr 42.158.0.1 accept
  iifname "d2" oifname "r2x" ip saddr 45.161.2.1 ip daddr 46.162.3.1 accept
  iifname "r2x" oifname "d2" ip saddr 46.162.3.1 ip daddr 45.161.2.1 accept
 }
}
NFT
    ip netns exec "$B1" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    for download_interface in d0 d2; do
        ip netns exec "$B1" tc qdisc add dev "$download_interface" root handle 137: \
            tbf rate 12mbit burst 16kb latency 30ms
    done
    if ip -n "$CLIENT" route get 46.162.3.1 >/dev/null 2>&1; then
        fail DOWNLOAD_SHARING_DIRECT_EXIT_ROUTE_PRESENT
    fi
}

download_sharing_phase() {
    download_phase_file=$(mktemp "$WORK/download-sharing-app/phase.XXXXXX")
    printf '%s\n' "$1" >"$download_phase_file"
    chmod 0644 "$download_phase_file"
    mv -fT -- "$download_phase_file" "$WORK/download-sharing-app/phase"
}

download_sharing_snapshot() {
    python3 "$source_directory/tests/integration/download-sharing-snapshot.py" \
        "$WORK" "$RUN_ID" "$download_relay_namespace" "$B1" "$EXIT_NODE" \
        "$binary_directory" "$1"
}

download_sharing_resume() {
    [ -n "${download_paused_pid:-}" ] || return 0
    if [ "$(systemctl show --property=MainPID --value \
        "volparossa-alpha-agent@$download_relay_node.service")" != "$download_paused_pid" ] \
        || [ "$(readlink -f "/proc/$download_paused_pid/exe")" != \
            "$binary_directory/volparossa-agent" ]; then
        return 1
    fi
    kill -CONT "$download_paused_pid"
    download_paused_pid=
}

sharing_run() {
    PHASE=download-sharing-discovery
    install -d -o root -g root -m 1777 "$WORK/download-sharing-app"
    for download_fixture in reciprocity-smoke.py download-sharing-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$download_fixture" \
            "$WORK/bin/$download_fixture"
    done
    reciprocity_agent_snapshot before
    reciprocity_wait_neighbors || fail DOWNLOAD_SHARING_DISCOVERY_UNAVAILABLE
    (reciprocity_connect client) || fail DOWNLOAD_SHARING_NATIVE_ROUTE_UNAVAILABLE
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    download_sharing_phase waiting
    ip netns exec "$DEST" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/download-sharing-smoke.py" server \
        "$WORK/download-sharing-app" "$RUN_ID" >"$WORK/download-sharing-server.log" 2>&1 &
    download_server_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $download_server_pid"
    reciprocity_wait_file "$WORK/download-sharing-app/server.ready" "$download_server_pid" \
        || fail DOWNLOAD_SHARING_SERVER_NOT_READY
    download_capture_pids=
    for download_node in client relay0 relay2 exit; do
        download_namespace=$(reciprocity_namespace "$download_node")
        ip netns exec "$download_namespace" python3 "$WORK/bin/download-sharing-smoke.py" capture \
            "$WORK" "$RUN_ID" "$download_node" >"$WORK/download-sharing-capture-$download_node.log" 2>&1 &
        download_capture_pid=$!
        download_capture_pids="$download_capture_pids $download_capture_pid"
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $download_capture_pid"
        reciprocity_wait_file "$WORK/download-sharing-capture-$download_node.ready" "$download_capture_pid" \
            || fail DOWNLOAD_SHARING_CAPTURE_NOT_READY
    done
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/download-sharing-smoke.py" client \
        "$WORK/download-sharing-app" "$RUN_ID" >"$WORK/download-sharing-client.log" 2>&1 &
    download_client_pid=$!
    RECIPROCITY_PIDS="$RECIPROCITY_PIDS $download_client_pid"
    download_sharing_phase idle
    reciprocity_wait_file "$WORK/download-sharing-app/client.active" "$download_client_pid" \
        || fail DOWNLOAD_SHARING_PROTECTED_DOWNLOAD_UNAVAILABLE
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        paths >"$WORK/download-sharing-paths-before.txt"
    download_sharing_python selection "$WORK" "$RUN_ID" || fail DOWNLOAD_SHARING_ROUTE_IDENTITY_INVALID
    # Public, disposable topology metadata is read by both unprivileged owner fixtures.
    chmod 0644 "$WORK/download-sharing-selection.json"
    download_relay_node=$(jq -er '.relay_node' "$WORK/download-sharing-selection.json")
    download_relay_namespace=$(reciprocity_namespace "$download_relay_node")
    for download_mode in owner-sink owner; do
        if [ "$download_mode" = owner-sink ]; then download_namespace=$download_relay_namespace
        else download_namespace=$B1; fi
        ip netns exec "$download_namespace" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
            --no-new-privs -- python3 "$WORK/bin/download-sharing-smoke.py" "$download_mode" \
            "$WORK/download-sharing-app" "$RUN_ID" >"$WORK/download-sharing-$download_mode.log" 2>&1 &
        download_owner_pid=$!
        RECIPROCITY_PIDS="$RECIPROCITY_PIDS $download_owner_pid"
        reciprocity_wait_file "$WORK/download-sharing-app/$download_mode.ready" "$download_owner_pid" \
            || fail DOWNLOAD_SHARING_OWNER_NOT_READY
    done
    for download_window in baseline idle owner recovery; do
        PHASE=download-sharing-$download_window
        download_sharing_phase "$download_window"
        sleep 2
        download_sharing_snapshot "$download_window-before" || fail DOWNLOAD_SHARING_KERNEL_SNAPSHOT_INVALID
        download_sharing_python app-snapshot "$WORK" "$RUN_ID" "$download_window-before"
        sleep 5
        download_sharing_snapshot "$download_window-after" || fail DOWNLOAD_SHARING_KERNEL_SNAPSHOT_INVALID
        download_sharing_python app-snapshot "$WORK" "$RUN_ID" "$download_window-after"
    done
    PHASE=download-sharing-expiry
    download_sharing_phase expiry
    download_paused_pid=$(systemctl show --property=MainPID --value \
        "volparossa-alpha-agent@$download_relay_node.service")
    case $download_paused_pid in ''|0|*[!0-9]*) fail DOWNLOAD_SHARING_AGENT_PID_INVALID ;; esac
    [ "$(readlink -f "/proc/$download_paused_pid/exe")" = "$binary_directory/volparossa-agent" ] \
        || fail DOWNLOAD_SHARING_AGENT_IDENTITY_INVALID
    kill -STOP "$download_paused_pid"
    download_sharing_snapshot stopped-before || fail DOWNLOAD_SHARING_KERNEL_SNAPSHOT_INVALID
    # Maximum signed validity is 5 s. Seven seconds also drains the finite admitted queue.
    sleep 7
    download_sharing_snapshot stopped-after || fail DOWNLOAD_SHARING_KERNEL_SNAPSHOT_INVALID
    download_sharing_snapshot expiry-before || fail DOWNLOAD_SHARING_KERNEL_SNAPSHOT_INVALID
    download_sharing_python app-snapshot "$WORK" "$RUN_ID" expiry-before
    sleep 5
    download_sharing_snapshot expiry-after || fail DOWNLOAD_SHARING_KERNEL_SNAPSHOT_INVALID
    download_sharing_python app-snapshot "$WORK" "$RUN_ID" expiry-after
    download_sharing_resume || fail DOWNLOAD_SHARING_AGENT_RESUME_FAILED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        paths >"$WORK/download-sharing-paths-after.txt"
    reciprocity_agent_snapshot after
    download_sharing_phase 'done'
    for download_pid in $RECIPROCITY_PIDS; do
        case " $download_capture_pids " in *" $download_pid "*) continue ;; esac
        wait "$download_pid" || fail DOWNLOAD_SHARING_APPLICATION_FAILED
    done
    for download_pid in $download_capture_pids; do kill -TERM "$download_pid" || fail DOWNLOAD_SHARING_CAPTURE_EARLY_EXIT; done
    for download_pid in $download_capture_pids; do wait "$download_pid" || fail DOWNLOAD_SHARING_CAPTURE_FAILED; done
    RECIPROCITY_PIDS=
    download_sharing_python evidence "$WORK" "$RUN_ID" || fail DOWNLOAD_SHARING_EVIDENCE_INVALID
    PHASE=download-sharing-complete
    OBSERVED_BLOCKER=
}

sharing_verify_cleanup() {
    [ -f "$WORK/download-sharing-selection.json" ] || return 0
    download_sharing_resume || return 1
    download_sharing_snapshot cleanup
}

sharing_finalize_report() {
    download_status=$1
    download_evidence='{"success":false}'
    download_cleanup='{"accounting_removed":false}'
    [ ! -s "$WORK/download-sharing-evidence.json" ] || download_evidence=$(cat "$WORK/download-sharing-evidence.json")
    [ ! -s "$WORK/download-sharing-cleanup.json" ] || download_cleanup=$(cat "$WORK/download-sharing-cleanup.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" --argjson status "$download_status" \
        --argjson evidence "$download_evidence" --argjson scheduler_cleanup "$download_cleanup" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" \
        '$evidence + {schema_version:1,report_kind:"volparossa-owner-priority-downlink",
          source_revision:$revision,run_id:$run_id,phase:$phase,
          success:($status == 0 and $evidence.success and $complete and $remaining == 0 and
            $scheduler_cleanup.accounting_removed and $host[0].unchanged),
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:($scheduler_cleanup + {complete:$complete,remaining_owned_objects:$remaining}),
          host_state:($host[0] | del(.acceptance_id))}' >"$WORK/download-sharing-smoke.json"
    for download_artifact in "$WORK"/download-sharing-*.json "$WORK"/download-sharing-*.txt \
        "$WORK"/download-sharing-*.log "$WORK"/reciprocity-node-*.json \
        "$WORK"/reciprocity-connect-client.*; do
        if [ ! -f "$download_artifact" ] || [ -L "$download_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$download_artifact" \
            "$output_directory/$(basename -- "$download_artifact")"
    done
    for download_artifact in "$WORK"/download-sharing-app/*.json; do
        if [ ! -f "$download_artifact" ] || [ -L "$download_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$download_artifact" \
            "$output_directory/download-sharing-app-$(basename -- "$download_artifact")"
    done
    jq -e '.success == true' "$WORK/download-sharing-smoke.json" >/dev/null
}
