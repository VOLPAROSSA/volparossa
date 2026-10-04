#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Only sourced inside the explicitly approved disposable KVM topology.
# shellcheck disable=SC2154,SC2034

signal_backup_private() {
    timeout --signal=TERM --kill-after=10s 2800s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/signal-backup-smoke.py" "$@"
}

signal_backup_cleanup() {
    if [ -n "${SIGNAL_BACKUP_PARENT_MODE:-}" ]; then
        chmod "$SIGNAL_BACKUP_PARENT_MODE" /home/vpci || return 1
        SIGNAL_BACKUP_PARENT_MODE=
    fi
    if ip netns list | cut -d' ' -f1 | grep -Fx "$CLIENT" >/dev/null \
        && ip netns exec "$CLIENT" nft list table inet vpa_signal_backup >/dev/null 2>&1; then
        ip netns exec "$CLIENT" nft delete table inet vpa_signal_backup || return 1
    fi
    [ -f "$WORK/bin/signal-backup-smoke.py" ] || return 0
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    signal_backup_private cleanup "$WORK/client-fixtures/signal-backup-user" \
        >"$WORK/signal-backup-private_cleanup.json"
}

signal_backup_run() {
    PHASE=signal-backup-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail SIGNAL_BACKUP_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail SIGNAL_BACKUP_CONTROL_GROUP_INVALID
    storage_user=$WORK/client-fixtures/signal-backup-user
    if [ -e "$storage_user" ] || [ -L "$storage_user" ]; then fail SIGNAL_BACKUP_USER_NOT_NEW; fi
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_user"
    benchmark_select_route signal-backup mptcp || fail SIGNAL_BACKUP_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/signal-backup-selection.json" || fail SIGNAL_BACKUP_ROUTE_INVALID
    storage_context=$(jq -er '.route_context_id' "$WORK/signal-backup-selection.json")
    provider_control_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || fail SIGNAL_BACKUP_CONTROL_UNAVAILABLE
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '. as $p | ["relay4","relay5","relay3"]
        | map(select($p[.] != $control)) | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") \
        || fail SIGNAL_BACKUP_PROVIDER_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    content_provider_control_underlay
    storage_key_a=$(private_storage_replicas_key "$provider_node_a") || fail SIGNAL_BACKUP_PROVIDER_KEY_FAILED
    storage_key_b=$(private_storage_replicas_key "$provider_node_b") || fail SIGNAL_BACKUP_PROVIDER_KEY_FAILED
    [ "$storage_key_a" != "$storage_key_b" ] || fail SIGNAL_BACKUP_PROVIDER_KEY_EQUAL
    for storage_node in "$provider_node_a" "$provider_node_b"; do
        content_custody_endpoint "$storage_node" || fail SIGNAL_BACKUP_PROVIDER_INVALID
        content_custody_cli "$storage_node" storage peer serve \
            --bind "$custody_address:18080" --advertised-hostname "$custody_hostname" \
            --store "$WORK/state-$storage_node/private-store" --capacity-bytes 67108864 --min-free-bytes 268435456 \
            >/dev/null || fail SIGNAL_BACKUP_SERVE_FAILED
        storage_key=$(private_storage_replicas_key "$storage_node") || fail SIGNAL_BACKUP_PROVIDER_KEY_FAILED
        storage_peer=$(jq -er --arg node "$storage_node" '.[$node]' "$WORK/a01-expected-peers.json")
        python3 -B - "$source_directory/tests/integration/content-custody-smoke.py" "$storage_peer" "$storage_key" <<'PY' \
            || fail SIGNAL_BACKUP_PROVIDER_IDENTITY_MISMATCH
import runpy, sys
assert runpy.run_path(sys.argv[1])["peer_key"](sys.argv[2]) == sys.argv[3]
PY
    done
    content_provider_node "$provider_node_a" || fail SIGNAL_BACKUP_NAMESPACE_INVALID
    storage_net_a=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail SIGNAL_BACKUP_NAMESPACE_INVALID
    content_provider_node "$provider_node_b" || fail SIGNAL_BACKUP_NAMESPACE_INVALID
    storage_net_b=$(stat -Lc '%d:%i' "/run/netns/$provider_ns") || fail SIGNAL_BACKUP_NAMESPACE_INVALID
    [ "$storage_net_a" != "$storage_net_b" ] || fail SIGNAL_BACKUP_NAMESPACES_EQUAL
    signal_backup_private prepare "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-$provider_node_a/control/agent.sock" \
        "$WORK/runtime-$provider_node_b/control/agent.sock" "$storage_key_a" "$storage_key_b" \
        >"$WORK/signal-backup-prepare.json" || fail SIGNAL_BACKUP_OWNER_PREPARE_FAILED
    storage_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $storage_client_pid in ''|0|*[!0-9]*) fail SIGNAL_BACKUP_CLIENT_PID_INVALID ;; esac
    nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail SIGNAL_BACKUP_POSITIVE_ISOLATION_FAILED
    for storage_private in "$storage_user" "$WORK/state-$provider_node_a/private-store" "$WORK/state-$provider_node_b/private-store"; do
        if nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$storage_private"; then fail SIGNAL_BACKUP_LOCAL_SHORTCUT; fi
    done
    jq -n --argjson nodes "$provider_nodes" --arg control "$provider_control_peer" --arg context "$storage_context" \
        '{provider_nodes:$nodes,control_relay_peer_id:$control,route_context_id:$context}' >"$WORK/signal-backup-layout.json"
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$group,
        agent_cannot_read_user_state:true,client_cannot_read_either_provider_store:true,agent_mount_positive_control:true,
        both_provider_keys_match_independent_fixture_peers:true,provider_namespaces_distinct:true}' >"$WORK/signal-backup-isolation.json"
    if [ ! -d /home/vpci ] || [ -L /home/vpci ]; then fail SIGNAL_BACKUP_RUNTIME_PARENT_INVALID; fi
    SIGNAL_BACKUP_PARENT_MODE=$(stat -Lc '%a' /home/vpci)
    chmod o+x /home/vpci || fail SIGNAL_BACKUP_RUNTIME_TRAVERSAL_FAILED
    install -o root -g root -m 0444 /home/vpci/signal-backup-runtime/provision.json "$WORK/bin/signal-backup-runtime.json"
    if ip netns exec "$CLIENT" nft list table inet vpa_signal_backup >/dev/null 2>&1; then
        fail SIGNAL_BACKUP_GUARD_ALREADY_EXISTS
    fi
    ip netns exec "$CLIENT" nft -f - <<EOF
table inet vpa_signal_backup {
    chain output {
        type filter hook output priority -150; policy accept;
        meta skuid $WORKER_UID ip daddr != 127.0.0.1 counter reject
        meta skuid $WORKER_UID ip6 daddr != ::1 counter reject
    }
}
EOF
    PHASE=signal-backup-native
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail SIGNAL_BACKUP_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers signal-backup-native-privacy || fail SIGNAL_BACKUP_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer content-provider-signal-backup-native-control \
        || fail SIGNAL_BACKUP_CONTROL_CAPTURE_UNAVAILABLE
    # Run the actual Electron/Signal test as a different UID inside Client's namespace.
    ip netns exec "$CLIENT" timeout --signal=TERM --kill-after=10s 2800s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/signal-backup-smoke.py" native "$storage_user" \
        >"$WORK/signal-backup-native.json" &
    DOWNLOAD_CLIENT_PID=$!
    if wait "$DOWNLOAD_CLIENT_PID"; then DOWNLOAD_CLIENT_PID=; else DOWNLOAD_CLIENT_PID=; fail SIGNAL_BACKUP_NATIVE_TEST_FAILED; fi
    signal_backup_private finish "$storage_user" "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        >"$WORK/signal-backup-finish.json" || fail SIGNAL_BACKUP_FINAL_RECEIPTS_FAILED
    benchmark_capture_paths signal-backup-native-live mptcp || fail SIGNAL_BACKUP_ROUTE_UNAVAILABLE
    jq -e --arg context "$storage_context" '.route_context_id == $context' \
        "$WORK/signal-backup-native-live-selection.json" >/dev/null || fail SIGNAL_BACKUP_ROUTE_CHANGED
    stop_privacy_observers || fail SIGNAL_BACKUP_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail SIGNAL_BACKUP_CONTROL_CAPTURE_INCOMPLETE
    storage_poll=0
    while [ "$storage_poll" -lt 50 ]; do
        capture_product_logs
        storage_flows=$(content_provider_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        [ "$storage_flows" -lt 6 ] || break
        sleep 0.1
        storage_poll=$((storage_poll + 1))
    done
    jq -n --argjson baseline "$provider_baseline_ms" --argjson count "$storage_flows" \
        '{event_baseline_unix_ms:$baseline,exit_mptcp_tls_completed:$count}' >"$WORK/signal-backup-native-gates.json"
    [ "$storage_flows" -ge 6 ] || fail SIGNAL_BACKUP_PROTECTED_FLOW_INCOMPLETE
    ip netns exec "$CLIENT" nft -j list table inet vpa_signal_backup | jq --argjson uid "$WORKER_UID" \
        '{app_uid:$uid,loopback_ipv4_ipv6_only:true,blocked_packets:([.nftables[]?.rule.expr[]?.counter.packets // empty] | add // 0)}' \
        >"$WORK/signal-backup-guard.json"
    for storage_node in "$provider_node_a" "$provider_node_b"; do
        content_custody_cli "$storage_node" content stop >/dev/null || fail SIGNAL_BACKUP_FINAL_STOP_FAILED
        private_storage_replicas_usage "$storage_node" | jq -e '{reserved_bytes,committed_bytes,leases}' \
            >"$WORK/signal-backup-usage-$storage_node.json" || fail SIGNAL_BACKUP_FINAL_USAGE_FAILED
    done
    jq -s '.' "$WORK/signal-backup-usage-$provider_node_a.json" "$WORK/signal-backup-usage-$provider_node_b.json" \
        >"$WORK/signal-backup-deleted_usage.json"
    benchmark_disconnect_route signal-backup || fail SIGNAL_BACKUP_ROUTE_CLEANUP_FAILED
    signal_backup_cleanup || fail SIGNAL_BACKUP_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/signal-backup-smoke.py" evidence "$WORK" \
        "$WORK/signal-backup-evidence.json" >/dev/null || fail SIGNAL_BACKUP_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=signal-backup-complete
}

signal_backup_finalize_report() {
    storage_status=$1
    optional_json_evidence "$WORK/signal-backup-evidence.json" >"$WORK/signal-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/signal-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/signal-report-evidence.part" \
        --slurpfile host "$WORK/signal-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-signal-backup",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,backup:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"one exact native Signal encrypted export/import with two real protected storage providers; local mock server still handles registration/relink; no server-free messaging or independent-hardware claim"}' \
        >"$WORK/signal-backup-smoke.json" || return 1
    storage_exports=$(python3 -B "$source_directory/tests/integration/signal-backup-smoke.py" export-names) || return 1
    for storage_name in $storage_exports; do
        storage_artifact=$WORK/$storage_name
        if [ -f "$storage_artifact" ] && [ ! -L "$storage_artifact" ]; then
            [ "$(wc -c <"$storage_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$storage_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/signal-backup-smoke.py" report \
        "$WORK/signal-backup-smoke.json" "$expected_commit"
}
