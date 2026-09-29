#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the approved disposable KVM topology, not on the development host.
# shellcheck disable=SC2154,SC2034

private_storage_peer_private() {
    timeout --signal=TERM --kill-after=5s 240s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-peer-smoke.py" "$@"
}

private_storage_peer_cleanup() {
    [ -f "$WORK/bin/private-storage-peer-smoke.py" ] || return 0
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    private_storage_peer_private cleanup "$WORK/client-fixtures/private-storage-user" \
        >"$WORK/private-storage-peer-private_cleanup.json"
}

private_storage_peer_serve() {
    storage_reuse=$1
    content_custody_endpoint "$provider_node_a" || return 1
    if [ "$storage_reuse" = yes ]; then
        set -- --reuse-store
    else
        set -- --capacity-bytes 1048576 --min-free-bytes 268435456
    fi
    content_custody_cli "$provider_node_a" storage peer serve \
        --bind "$custody_address:18080" --advertised-hostname "$custody_hostname" \
        --store "$storage_store" "$@" >/dev/null
}

private_storage_peer_usage() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" storage local status --store "$storage_store"
}

private_storage_peer_run() {
    PHASE=private-storage-peer-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail STORAGE_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail STORAGE_CONTROL_GROUP_INVALID
    storage_user=$WORK/client-fixtures/private-storage-user
    [ ! -e "$storage_user" ] && [ ! -L "$storage_user" ] || fail STORAGE_USER_NOT_NEW
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_user"
    benchmark_select_route private-storage-peer mptcp || fail STORAGE_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/private-storage-peer-selection.json" || fail STORAGE_ROUTE_INVALID
    storage_context=$(jq -er '.route_context_id' "$WORK/private-storage-peer-selection.json")
    provider_control_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || fail STORAGE_CONTROL_UNAVAILABLE
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '. as $p | ["relay4","relay5","relay3"]
        | map(select($p[.] != $control)) | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") \
        || fail STORAGE_PROVIDER_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    # Reuse two tightly filtered control links; only the first provider stores this archive.
    content_provider_control_underlay
    storage_store=$WORK/state-$provider_node_a/private-store
    private_storage_peer_serve no || fail STORAGE_SERVE_FAILED
    storage_provider_key=$(setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" content recipient-key \
        --identity "$WORK/state-$provider_node_a/identity.key" \
        --passphrase-file "$WORK/credential-$provider_node_a/identity-passphrase" \
        | jq -er '.identity_public_key_hex | select(test("^[0-9a-f]{64}$"))') || fail STORAGE_PROVIDER_KEY_FAILED
    storage_peer=$(jq -er --arg node "$provider_node_a" '.[$node]' "$WORK/a01-expected-peers.json")
    # Independent fixture identity is not taken from a server grant or challenge response.
    python3 -B - "$source_directory/tests/integration/content-custody-smoke.py" "$storage_peer" "$storage_provider_key" <<'PY' \
        || fail STORAGE_PROVIDER_IDENTITY_MISMATCH
import runpy, sys
assert runpy.run_path(sys.argv[1])["peer_key"](sys.argv[2]) == sys.argv[3]
PY
    private_storage_peer_private prepare "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-$provider_node_a/control/agent.sock" \
        "$storage_provider_key" >"$WORK/private-storage-peer-prepare.json" || fail STORAGE_OWNER_PREPARE_FAILED
    storage_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $storage_client_pid in ''|0|*[!0-9]*) fail STORAGE_CLIENT_PID_INVALID ;; esac
    nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail STORAGE_POSITIVE_ISOLATION_FAILED
    for storage_private in "$storage_user" "$storage_store"; do
        if nsenter --target "$storage_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$storage_private"; then fail STORAGE_LOCAL_SHORTCUT; fi
    done
    jq -n --arg node "$provider_node_a" --argjson nodes "$provider_nodes" --arg control "$provider_control_peer" \
        --arg context "$storage_context" '{provider_node:$node,control_provider_nodes:$nodes,
        control_relay_peer_id:$control,route_context_id:$context}' >"$WORK/private-storage-peer-layout.json"
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$group,
        agent_cannot_read_user_state:true,client_cannot_read_provider_store:true,agent_mount_positive_control:true,
        provider_key_matches_independent_fixture_peer:true}' >"$WORK/private-storage-peer-isolation.json"

    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail STORAGE_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers private-storage-peer-privacy || fail STORAGE_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer content-provider-private-storage-control || fail STORAGE_CONTROL_CAPTURE_UNAVAILABLE
    PHASE=private-storage-peer-upload
    private_storage_peer_private upload "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_provider_key" \
        >"$WORK/private-storage-peer-upload.json" || fail STORAGE_UPLOAD_FAILED
    PHASE=private-storage-peer-reopen
    content_custody_cli "$provider_node_a" content stop >/dev/null || fail STORAGE_LISTENER_STOP_FAILED
    private_storage_peer_usage | jq -e '{explicit_listener_stop:true,same_owned_store_reopened:true,
        durable_committed_bytes:.committed_bytes,durable_reserved_bytes:.reserved_bytes,durable_leases:.leases,
        agent_restart_claimed:false}' >"$WORK/private-storage-peer-reopen.json" || fail STORAGE_REOPEN_USAGE_FAILED
    private_storage_peer_serve yes || fail STORAGE_REOPEN_FAILED
    PHASE=private-storage-peer-restore
    private_storage_peer_private download "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$storage_provider_key" \
        >"$WORK/private-storage-peer-download.json" || fail STORAGE_RESTORE_DELETE_FAILED
    content_custody_cli "$provider_node_a" content stop >/dev/null || fail STORAGE_FINAL_STOP_FAILED
    private_storage_peer_usage | jq -e '{reserved_bytes,committed_bytes,leases}' \
        >"$WORK/private-storage-peer-deleted_usage.json" || fail STORAGE_DELETE_USAGE_FAILED
    benchmark_capture_paths private-storage-peer-live mptcp || fail STORAGE_LIVE_ROUTE_UNAVAILABLE
    stop_privacy_observers || fail STORAGE_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail STORAGE_CONTROL_CAPTURE_INCOMPLETE
    storage_poll=0
    while [ "$storage_poll" -lt 50 ]; do
        capture_product_logs
        storage_flows=$(content_provider_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        [ "$storage_flows" -lt 16 ] || break
        sleep 0.1
        storage_poll=$((storage_poll + 1))
    done
    jq -n --argjson baseline "$provider_baseline_ms" --argjson count "$storage_flows" \
        '{event_baseline_unix_ms:$baseline,exit_mptcp_tls_completed:$count}' >"$WORK/private-storage-peer-gates.json"
    [ "$storage_flows" -ge 16 ] || fail STORAGE_PROTECTED_FLOW_INCOMPLETE
    benchmark_disconnect_route private-storage-peer || fail STORAGE_ROUTE_CLEANUP_FAILED
    private_storage_peer_cleanup || fail STORAGE_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/private-storage-peer-smoke.py" evidence "$WORK" \
        "$WORK/private-storage-peer-evidence.json" >/dev/null || fail STORAGE_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=private-storage-peer-complete
}

private_storage_peer_finalize_report() {
    storage_status=$1
    # Exact allowlist: never export grants, owner keys, archive state, store files or CLI stderr.
    for storage_name in evidence prepare upload download reopen deleted_usage private_cleanup isolation layout gates live-selection \
        privacy-client privacy-relay0 privacy-relay1 privacy-relay2 privacy-exit; do
        storage_artifact=$WORK/private-storage-peer-$storage_name.json
        [ ! -f "$storage_artifact" ] || [ -L "$storage_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$(basename -- "$storage_artifact")"
    done
    storage_artifact=$WORK/content-provider-private-storage-control.json
    [ ! -f "$storage_artifact" ] || [ -L "$storage_artifact" ] || \
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$(basename -- "$storage_artifact")"
    optional_json_evidence "$WORK/private-storage-peer-evidence.json" >"$WORK/storage-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/storage-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/storage-report-evidence.part" \
        --slurpfile host "$WORK/storage-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-storage-peer",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,storage:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"one private provider over the real protected route; explicit bounded grant, multi-chunk upload, committed retry, store reopen, two non-consuming restores, renewal and deletion; synthetic opaque bytes only"}' \
        >"$WORK/private-storage-peer-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/private-storage-peer-smoke.json" "$output_directory/private-storage-peer-smoke.json"
    python3 -B "$source_directory/tests/integration/private-storage-peer-smoke.py" report "$WORK/private-storage-peer-smoke.json" "$expected_commit"
}
