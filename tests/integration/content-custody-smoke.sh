#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the explicitly approved disposable KVM content-custody scenario.
# shellcheck disable=SC2154,SC2034

content_custody_endpoint() {
    case $1 in
        relay3) custody_address=48.164.4.1; custody_hostname=provider-c.volparossa.test; custody_interface=r3x ;;
        relay4) custody_address=49.165.5.1; custody_hostname=provider-a.volparossa.test; custody_interface=r4x ;;
        relay5) custody_address=50.166.6.1; custody_hostname=provider-b.volparossa.test; custody_interface=r5x ;;
        *) return 1 ;;
    esac
}

content_custody_config() {
    if [ "${scenario:-}" = content-custody ] && [ "$node" = client ]; then
        # Real existing Client underlay interfaces; optional background work observes
        # these configured owner-first budgets, not fictional spare capacity.
        printf 'sharing:\n  enabled: true\n  interface: cr0\n'
        printf '  total_upload_mbps: 100\n  contribution_upload_ceiling_mbps: 1\n'
        printf 'download_sharing:\n  enabled: true\n  interface: cr2\n'
        printf '  total_download_mbps: 100\n  contribution_download_ceiling_mbps: 1\n'
        return 0
    fi
    case $node in relay3|relay4|relay5) ;; *) return 0 ;; esac
    content_custody_endpoint "$node" || return 1
    printf 'sharing:\n  enabled: true\n  interface: %s\n' "$custody_interface"
    printf '  total_upload_mbps: 100\n  contribution_upload_ceiling_mbps: 90\n'
    printf 'download_sharing:\n  enabled: true\n  interface: %s\n' "$custody_interface"
    printf '  total_download_mbps: 100\n  contribution_download_ceiling_mbps: 90\n'
    printf 'content_contribution:\n  enabled: true\n  bind_address: "%s:18080"\n' "$custody_address"
    printf '  advertised_hostname: %s\n  cache: "%s/state-%s/custody-cache"\n' "$custody_hostname" "$WORK" "$node"
    printf '  quota_bytes: 16777216\n  max_entries: 64\n  min_free_bytes: 268435456\n'
    printf '  max_bytes: 1048576\n  max_chunks: 4\n'
}

content_custody_cli() {
    custody_cli_node=$1
    shift
    timeout --signal=TERM --kill-after=5s 240s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$custody_cli_node/control/agent.sock" "$@"
}

content_custody_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-custody-smoke.py" "$@"
}

content_custody_cleanup() {
    [ -f "$WORK/bin/content-custody-smoke.py" ] || return 0
    custody_cleanup_status=0
    if [ -n "${CUSTODY_OWNER_PID:-}" ]; then
        content_custody_owner_stop || custody_cleanup_status=1
    fi
    # A failed product may already be reaped. Preserve that failure, but do not leave
    # its private fixture files behind. An unverified/maybe-live owner is different.
    [ -z "${CUSTODY_OWNER_PID:-}" ] || return 1
    if [ "${CUSTODY_AUTOMATIC:-no}" = yes ]; then
        content_custody_retain_private cleanup "$WORK/client-fixtures/custody-user" \
            >"$WORK/content-custody-private-cleanup.json" || custody_cleanup_status=1
        return "$custody_cleanup_status"
    fi
    content_custody_private cleanup "$WORK/client-fixtures/custody-user" \
        >"$WORK/content-custody-private-cleanup.json"
}

content_custody_status() {
    custody_status_node=$1; custody_status_label=$2; custody_status_count=$3
    custody_status_attempt=0
    while [ "$custody_status_attempt" -lt 60 ]; do
        if content_custody_cli "$custody_status_node" content status \
            >"$WORK/content-custody-$custody_status_node-$custody_status_label.json" \
            2>"$WORK/content-custody-$custody_status_node-$custody_status_label.err" \
            && jq -e --argjson count "$custody_status_count" \
                '.serving == true and .replication_enabled == true and .publications == $count
                 and .replica_publications == $count' \
                "$WORK/content-custody-$custody_status_node-$custody_status_label.json" >/dev/null; then return 0; fi
        sleep 0.5
        custody_status_attempt=$((custody_status_attempt + 1))
    done
    return 1
}

content_custody_phase_start() {
    custody_phase=$1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail CUSTODY_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers "content-custody-$custody_phase-privacy" || fail CUSTODY_CAPTURE_UNAVAILABLE
    if [ "${CUSTODY_AUTOMATIC:-no}" = yes ]; then
        content_provider_adaptive_start_control_observer "content-provider-adaptive-custody-$custody_phase-control" \
            || fail CUSTODY_CONTROL_CAPTURE_UNAVAILABLE
    else
        content_provider_start_control_observer "content-provider-custody-$custody_phase-control" \
            || fail CUSTODY_CONTROL_CAPTURE_UNAVAILABLE
    fi
}

content_custody_phase_finish() {
    custody_expected_flows=$1
    benchmark_capture_paths "content-custody-$custody_phase-live" mptcp || fail CUSTODY_LIVE_ROUTE_UNAVAILABLE
    jq -e --arg context "$custody_context" '.route_context_id == $context' \
        "$WORK/content-custody-$custody_phase-live-selection.json" >/dev/null || fail CUSTODY_ROUTE_CHANGED
    stop_privacy_observers || fail CUSTODY_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail CUSTODY_CONTROL_CAPTURE_INCOMPLETE
    custody_gate_poll=0
    while [ "$custody_gate_poll" -lt 50 ]; do
        capture_product_logs
        custody_exit_count=$(content_provider_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        [ "$custody_exit_count" -lt "$custody_expected_flows" ] || break
        sleep 0.1
        custody_gate_poll=$((custody_gate_poll + 1))
    done
    jq -n --argjson baseline "$provider_baseline_ms" --argjson count "$custody_exit_count" \
        '{event_baseline_unix_ms:$baseline,exit_mptcp_tls_completed:$count}' \
        >"$WORK/content-custody-$custody_phase-gates.json"
    [ "$custody_exit_count" -ge "$custody_expected_flows" ] || fail CUSTODY_PROTECTED_FLOW_INCOMPLETE
}

content_custody_restart() {
    custody_restart_node=$1
    custody_restart_unit=volparossa-alpha-agent@$custody_restart_node.service
    case " $AGENT_UNITS " in *" $custody_restart_unit "*) ;; *) return 1 ;; esac
    custody_restart_root=$WORK/state-$custody_restart_node/custody-cache
    custody_old_pid=$(systemctl show --property=MainPID --value "$custody_restart_unit") || return 1
    case $custody_old_pid in ''|0|*[!0-9]*) return 1 ;; esac
    custody_old_cache=$(stat -Lc '%d:%i' "$custody_restart_root") || return 1
    systemctl restart "$custody_restart_unit" || return 1
    custody_restart_attempt=0
    while [ "$custody_restart_attempt" -lt 300 ]; do
        custody_new_pid=$(systemctl show --property=MainPID --value "$custody_restart_unit") || return 1
        case $custody_new_pid in ''|0|*[!0-9]*) custody_new_pid=0 ;; esac
        if [ "$custody_new_pid" != 0 ] && [ "$custody_new_pid" != "$custody_old_pid" ] \
            && [ "$(systemctl show --property=ActiveState --value "$custody_restart_unit")" = active ] \
            && [ -S "$WORK/runtime-$custody_restart_node/control/agent.sock" ]; then break; fi
        sleep 0.1
        custody_restart_attempt=$((custody_restart_attempt + 1))
    done
    [ "$custody_restart_attempt" -lt 300 ] || return 1
    content_provider_node "$custody_restart_node" || return 1
    custody_new_net=$(stat -Lc '%d:%i' "/proc/$custody_new_pid/ns/net") || return 1
    [ "$custody_new_net" = "$(stat -Lc '%d:%i' "/run/netns/$provider_ns")" ] || return 1
    [ "$(readlink -f -- "/proc/$custody_new_pid/exe")" = "$binary_directory/volparossa-agent" ] || return 1
    content_custody_status "$custody_restart_node" restored 1 || return 1
    custody_new_cache=$(stat -Lc '%d:%i' "$custody_restart_root") || return 1
    [ "$custody_old_cache" = "$custody_new_cache" ] || return 1
    jq -n --arg node "$custody_restart_node" --argjson before "$custody_old_pid" --argjson after "$custody_new_pid" \
        --arg first "$custody_old_cache" --arg second "$custody_new_cache" --arg net "$custody_new_net" \
        '{node:$node,pid_before:$before,pid_after:$after,cache_before:$first,cache_after:$second,
          namespace_identity:$net,executable_verified:true,automatic_reopen:true}' \
        >"$WORK/content-custody-$custody_restart_node-restart.json"
}

content_custody_manual_run() {
    PHASE=content-custody-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail CUSTODY_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail CUSTODY_CONTROL_GROUP_INVALID
    custody_user=$WORK/client-fixtures/custody-user
    [ ! -e "$custody_user" ] && [ ! -L "$custody_user" ] || fail CUSTODY_USER_NOT_NEW
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$custody_user"
    content_custody_private init "$custody_user" >"$WORK/content-custody-input.json" || fail CUSTODY_INPUT_FAILED
    content_custody_cli client init --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        >"$WORK/content-custody-init.log" 2>"$WORK/content-custody-init.err" || fail CUSTODY_IDENTITY_FAILED
    content_custody_cli client content publish --input "$custody_user/input.bin" \
        --name disposable-public-custody --revision 1 --content-type application/octet-stream \
        --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        --cache "$custody_user/source-cache" --manifest "$custody_user/manifest.bin" --lifetime-seconds 7200 \
        >"$WORK/content-custody-publish.json" 2>"$WORK/content-custody-publish.err" || fail CUSTODY_PUBLISH_FAILED
    custody_publisher=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' "$WORK/content-custody-publish.json")
    custody_manifest=$(sha256sum "$custody_user/manifest.bin" | awk '{print $1}')
    benchmark_select_route content-custody mptcp || fail CUSTODY_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-custody-selection.json" || fail CUSTODY_ROUTE_INVALID
    custody_context=$(jq -er '.route_context_id' "$WORK/content-custody-selection.json")
    content_custody_cli client content status >"$WORK/content-custody-client-status.json" || fail CUSTODY_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' "$WORK/content-custody-client-status.json")
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '. as $p | ["relay4","relay5","relay3"]
        | map(select($p[.] != $control)) | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") \
        || fail CUSTODY_PROVIDERS_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    content_provider_control_underlay
    custody_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $custody_client_pid in ''|0|*[!0-9]*) fail CUSTODY_CLIENT_PID_INVALID ;; esac
    nsenter --target "$custody_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CUSTODY_POSITIVE_ISOLATION_FAILED
    for custody_node in "$provider_node_a" "$provider_node_b"; do
        content_custody_status "$custody_node" empty 0 || fail CUSTODY_EMPTY_SERVICE_UNAVAILABLE
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" content recipient-key \
            --identity "$WORK/state-$custody_node/identity.key" --passphrase-file "$WORK/credential-$custody_node/identity-passphrase" \
            >"$WORK/content-custody-$custody_node-public.json" 2>"$WORK/content-custody-$custody_node-public.err" || fail CUSTODY_PROVIDER_KEY_FAILED
        [ "$(stat -Lc '%a:%u:%g' "$WORK/state-$custody_node/custody-cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
            || fail CUSTODY_PROVIDER_CACHE_OWNERSHIP
        if nsenter --target "$custody_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$custody_node/custody-cache"; then fail CUSTODY_LOCAL_PROVIDER_SHORTCUT; fi
    done
    if nsenter --target "$custody_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$custody_user"; then fail CUSTODY_USER_STATE_EXPOSED; fi
    custody_key_a=$(jq -er '.identity_public_key_hex' "$WORK/content-custody-$provider_node_a-public.json")
    custody_key_b=$(jq -er '.identity_public_key_hex' "$WORK/content-custody-$provider_node_b-public.json")
    jq -n --argjson nodes "$provider_nodes" --arg a "$provider_node_a" --arg b "$provider_node_b" \
        --arg ka "$custody_key_a" --arg kb "$custody_key_b" --arg control "$provider_control_peer" \
        --arg context "$custody_context" --arg manifest "$custody_manifest" \
        '{provider_nodes:$nodes,provider_keys:{($a):$ka,($b):$kb},control_relay_peer_id:$control,
          route_context_id:$context,manifest_id:$manifest}' >"$WORK/content-custody-layout.json"

    PHASE=content-custody-deposit
    content_custody_phase_start deposit
    custody_missing_status=0
    content_custody_cli client content custody inspect --manifest "$custody_user/manifest.bin" \
        --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        --provider-key "$custody_key_a" --provider-key "$custody_key_b" \
        >"$WORK/content-custody-missing.json" 2>"$WORK/content-custody-missing.err" || custody_missing_status=$?
    [ "$custody_missing_status" = 1 ] || fail CUSTODY_MISSING_INSPECT_EXIT_INVALID
    jq -e '.complete == false and .failed_providers == 0 and .confirmed_complete_providers == 0
        and (.observations | length == 2 and all(.[]; .state == "missing" and .agent_handoff_complete == true))' \
        "$WORK/content-custody-missing.json" >/dev/null || fail CUSTODY_INITIAL_NOT_MISSING
    content_custody_cli client content custody deposit --manifest "$custody_user/manifest.bin" \
        --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        --cache "$custody_user/source-cache" --provider-key "$custody_key_a" --provider-key "$custody_key_b" \
        >"$WORK/content-custody-deposit.json" 2>"$WORK/content-custody-deposit.err" || fail CUSTODY_DEPOSIT_FAILED
    content_custody_phase_finish 4
    content_custody_private drop-source "$custody_user" >"$WORK/content-custody-source-removed.json" || fail CUSTODY_SOURCE_REMOVAL_FAILED
    PHASE=content-custody-provider-restart
    content_custody_restart "$provider_node_a" || fail CUSTODY_PROVIDER_A_RESTART_FAILED
    content_custody_restart "$provider_node_b" || fail CUSTODY_PROVIDER_B_RESTART_FAILED
    PHASE=content-custody-inspect
    content_custody_phase_start inspect
    content_custody_cli client content custody inspect --manifest "$custody_user/manifest.bin" \
        --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        --provider-key "$custody_key_a" --provider-key "$custody_key_b" \
        >"$WORK/content-custody-inspect.json" 2>"$WORK/content-custody-inspect.err" || fail CUSTODY_RESTART_INSPECT_FAILED
    content_custody_phase_finish 2
    PHASE=content-custody-fetch
    custody_fetch_cache=$WORK/state-client/custody-fetch-cache
    [ ! -e "$custody_fetch_cache" ] && [ ! -L "$custody_fetch_cache" ] || fail CUSTODY_FETCH_CACHE_NOT_FRESH
    [ ! -e "$custody_user/output.bin" ] && [ ! -L "$custody_user/output.bin" ] || fail CUSTODY_FETCH_OUTPUT_NOT_FRESH
    content_custody_phase_start fetch
    content_custody_cli client content fetch-name --publisher-key "$custody_publisher" \
        --name disposable-public-custody --min-revision 1 --cache "$custody_fetch_cache" \
        --local-output "$custody_user/output.bin" >"$WORK/content-custody-fetch.json" \
        2>"$WORK/content-custody-fetch.err" || fail CUSTODY_NORMAL_FETCH_FAILED
    content_custody_phase_finish 1
    content_custody_private output "$custody_user" >"$WORK/content-custody-output.json" || fail CUSTODY_REASSEMBLY_INVALID
    [ "$(stat -Lc '%a:%u:%g' "$custody_fetch_cache")" = "700:$AGENT_UID:$AGENT_GID" ] || fail CUSTODY_FETCH_CACHE_OWNERSHIP
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$custody_fetch_cache"; then fail CUSTODY_AGENT_CACHE_EXPOSED; fi
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson agent_group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$agent_group,
          agent_mount_positive_control:true,agent_cannot_read_user_state:true,client_cannot_read_provider_stores:true,
          user_cannot_read_agent_cache:true,fresh_consumer_cache:true,cache_mode:"0700",output_mode:"0600"}' \
        >"$WORK/content-custody-isolation.json"
    for custody_node in "$provider_node_a" "$provider_node_b"; do
        content_custody_cli "$custody_node" content stop >"$WORK/content-custody-$custody_node-stop.json" \
            2>"$WORK/content-custody-$custody_node-stop.err" || fail CUSTODY_PROVIDER_STOP_FAILED
    done
    benchmark_disconnect_route content-custody || fail CUSTODY_ROUTE_CLEANUP_FAILED
    content_custody_cleanup || fail CUSTODY_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-custody-smoke.py" evidence "$WORK" \
        "$WORK/content-custody-evidence.json" || fail CUSTODY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-custody-complete
}

content_custody_retain_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-retain-smoke.py" "$@"
}

content_custody_owner_stop() {
    [ -n "${CUSTODY_OWNER_PID:-}" ] || return 0
    custody_owner_pid=$CUSTODY_OWNER_PID
    custody_term_sent=false
    custody_killed=false
    if [ -d "/proc/$custody_owner_pid" ]; then
        custody_start_ticks=$(jq -er '.start_ticks' "$WORK/content-custody-process-start.json") || return 1
        [ "$(awk '{print $22}' "/proc/$custody_owner_pid/stat")" = "$custody_start_ticks" ] || return 1
        if [ "$(awk '{print $3}' "/proc/$custody_owner_pid/stat")" != Z ]; then
            [ "$(readlink -f -- "/proc/$custody_owner_pid/exe")" = "$binary_directory/volparossa" ] || return 1
            kill -TERM "$custody_owner_pid" || return 1
            custody_term_sent=true
            custody_stop_wait=0
            while kill -0 "$custody_owner_pid" 2>/dev/null && [ "$custody_stop_wait" -lt 150 ]; do
                [ "$(awk '{print $3}' "/proc/$custody_owner_pid/stat" 2>/dev/null)" != Z ] || break
                sleep 0.1
                custody_stop_wait=$((custody_stop_wait + 1))
            done
            if kill -0 "$custody_owner_pid" 2>/dev/null \
                && [ "$(awk '{print $3}' "/proc/$custody_owner_pid/stat" 2>/dev/null)" != Z ]; then
                # Recheck identity before escalation; never signal a recycled PID.
                [ "$(awk '{print $22}' "/proc/$custody_owner_pid/stat")" = "$custody_start_ticks" ] || return 1
                [ "$(readlink -f -- "/proc/$custody_owner_pid/exe")" = "$binary_directory/volparossa" ] || return 1
                kill -KILL "$custody_owner_pid" || return 1
                custody_killed=true
            fi
        fi
    fi
    # This PID comes only from our own retained background child. With no live proc,
    # or its matching zombie, wait retrieves the actual exit, including early failures.
    custody_exit=0
    wait "$custody_owner_pid" || custody_exit=$?
    CUSTODY_OWNER_PID=
    custody_start_json=$(optional_json_evidence "$WORK/content-custody-process-start.json")
    jq -n --argjson start "$custody_start_json" --argjson pid "$custody_owner_pid" \
        --argjson code "$custody_exit" --argjson forced "$custody_killed" \
        --argjson term "$custody_term_sent" \
        --argjson ended "$(date +%s%3N)" \
        '($start // {pid:$pid,executable_verified:false}) +
          {exit_status:$code,forced_kill:$forced,term_sent:$term,reaped:true,ended_unix_ms:$ended}' \
        >"$WORK/content-custody-process.json" || return 1
    [ "$custody_exit" = 0 ] && [ "$custody_killed" = false ] && [ "$custody_term_sent" = true ]
}

content_custody_run() {
    CUSTODY_AUTOMATIC=yes
    CUSTODY_OWNER_PID=
    PHASE=content-custody-prepare
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail CUSTODY_CONTROL_GROUP_INVALID ;; esac
    [ "$custody_control_gid" != "$AGENT_GID" ] || fail CUSTODY_CONTROL_GROUP_INVALID
    custody_user=$WORK/client-fixtures/custody-user
    [ ! -e "$custody_user" ] && [ ! -L "$custody_user" ] || fail CUSTODY_USER_NOT_NEW
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$custody_user"
    content_custody_private init "$custody_user" >"$WORK/content-custody-input.json" || fail CUSTODY_INPUT_FAILED
    content_custody_cli client init --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        >"$WORK/content-custody-init.log" 2>"$WORK/content-custody-init.err" || fail CUSTODY_IDENTITY_FAILED
    content_custody_cli client content publish --input "$custody_user/input.bin" \
        --name disposable-public-custody --revision 1 --content-type application/octet-stream \
        --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        --cache "$custody_user/source-cache" --manifest "$custody_user/manifest.bin" --lifetime-seconds 7200 \
        >"$WORK/content-custody-publish.json" 2>"$WORK/content-custody-publish.err" || fail CUSTODY_PUBLISH_FAILED
    custody_publisher=$(jq -er '.publisher_key_hex' "$WORK/content-custody-publish.json")
    custody_manifest=$(sha256sum "$custody_user/manifest.bin" | awk '{print $1}')
    benchmark_select_route content-custody mptcp || fail CUSTODY_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-custody-selection.json" || fail CUSTODY_ROUTE_INVALID
    custody_context=$(jq -er '.route_context_id' "$WORK/content-custody-selection.json")
    content_custody_cli client content status >"$WORK/content-custody-client-status.json" || fail CUSTODY_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id' "$WORK/content-custody-client-status.json")
    jq -e --arg control "$provider_control_peer" '[.relay0,.relay1,.relay2] | index($control) != null' \
        "$WORK/a01-expected-peers.json" >/dev/null || fail CUSTODY_CONTROL_NOT_ROUTE_DISTINCT
    content_provider_adaptive_control_underlay "$provider_control_peer" || fail CUSTODY_CONTROL_UNDERLAY_FAILED
    custody_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $custody_client_pid in ''|0|*[!0-9]*) fail CUSTODY_CLIENT_PID_INVALID ;; esac
    nsenter --target "$custody_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CUSTODY_POSITIVE_ISOLATION_FAILED
    for custody_node in relay3 relay4 relay5; do
        content_custody_status "$custody_node" empty 0 || fail CUSTODY_EMPTY_SERVICE_UNAVAILABLE
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" content recipient-key \
            --identity "$WORK/state-$custody_node/identity.key" --passphrase-file "$WORK/credential-$custody_node/identity-passphrase" \
            >"$WORK/content-custody-$custody_node-public.json" || fail CUSTODY_PROVIDER_KEY_FAILED
        if nsenter --target "$custody_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$custody_node/custody-cache"; then fail CUSTODY_LOCAL_PROVIDER_SHORTCUT; fi
    done
    if nsenter --target "$custody_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$custody_user"; then fail CUSTODY_USER_STATE_EXPOSED; fi
    jq -n --slurpfile a "$WORK/content-custody-relay3-public.json" \
        --slurpfile b "$WORK/content-custody-relay4-public.json" --slurpfile c "$WORK/content-custody-relay5-public.json" \
        --arg control "$provider_control_peer" --arg context "$custody_context" --arg manifest "$custody_manifest" \
        '{provider_nodes:["relay3","relay4","relay5"],provider_keys:{relay3:$a[0].identity_public_key_hex,
          relay4:$b[0].identity_public_key_hex,relay5:$c[0].identity_public_key_hex},
          control_relay_peer_id:$control,route_context_id:$context,manifest_id:$manifest}' \
        >"$WORK/content-custody-layout.json"

    PHASE=content-custody-automatic-initial
    content_custody_phase_start initial
    custody_upload_budget=$(jq -er '.bytes * 4' "$WORK/content-custody-publish.json")
    # No explicit provider identities: the real owner discovers and selects the holders.
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content retain --manifest "$custody_user/manifest.bin" --cache "$custody_user/source-cache" \
        --identity "$custody_user/identity.key" --passphrase-file "$custody_user/passphrase" \
        --directory "$custody_user/retain-owner" --copies 2 --poll-seconds 10 --max-seconds 1600 \
        --max-upload-bytes "$custody_upload_budget" --execute \
        >"$WORK/content-custody-stopped.json" 2>"$WORK/content-custody-owner.err" &
    CUSTODY_OWNER_PID=$!
    python3 -B "$WORK/bin/content-retain-smoke.py" process "$CUSTODY_OWNER_PID" "$binary_directory/volparossa" \
        >"$WORK/content-custody-process-start.json" || fail CUSTODY_OWNER_PROCESS_INVALID
    content_custody_retain_private observe "$custody_user" initial \
        >"$WORK/content-custody-initial.json" || fail CUSTODY_AUTOMATIC_INITIAL_FAILED
    content_custody_phase_finish 4
    custody_lost_key=$(jq -er '.state.confirmed_holders[0]' "$WORK/content-custody-initial.json")
    custody_lost_node=$(jq -er --arg key "$custody_lost_key" \
        '.provider_keys | to_entries[] | select(.value == $key) | .key' "$WORK/content-custody-layout.json")
    PHASE=content-custody-automatic-replacement
    content_custody_phase_start replacement
    content_custody_cli "$custody_lost_node" content stop >"$WORK/content-custody-withdrawn-service.json" \
        2>"$WORK/content-custody-withdrawn-service.err" || fail CUSTODY_WITHDRAWAL_FAILED
    jq -n --arg node "$custody_lost_node" --arg key "$custody_lost_key" --argjson at "$(date +%s)" \
        --slurpfile receipt "$WORK/content-custody-withdrawn-service.json" \
        '{node:$node,provider_key:$key,withdrawn_unix_seconds:$at,receipt:$receipt[0]}' >"$WORK/content-custody-withdrawal.json"
    # The private user can read only this public snapshot copy, not root's WORK reports.
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0600 "$WORK/content-custody-initial.json" \
        "$custody_user/initial-observation.json"
    content_custody_retain_private observe "$custody_user" replacement "$custody_user/initial-observation.json" \
        >"$WORK/content-custody-replacement.json" || fail CUSTODY_AUTOMATIC_REPLACEMENT_FAILED
    content_custody_owner_stop || fail CUSTODY_OWNER_STOP_FAILED
    content_custody_phase_finish 3
    content_custody_retain_private snapshot "$custody_user" >"$WORK/content-custody-final-state.json" \
        || fail CUSTODY_FINAL_ORIGINAL_STATE_MISSING
    content_custody_private drop-source "$custody_user" >"$WORK/content-custody-source-removed.json" \
        || fail CUSTODY_SOURCE_REMOVAL_FAILED
    PHASE=content-custody-fetch
    custody_fetch_cache=$WORK/state-client/custody-fetch-cache
    [ ! -e "$custody_fetch_cache" ] && [ ! -L "$custody_fetch_cache" ] || fail CUSTODY_FETCH_CACHE_NOT_FRESH
    [ ! -e "$custody_user/output.bin" ] || fail CUSTODY_FETCH_OUTPUT_NOT_FRESH
    content_custody_phase_start fetch
    jq -n --argjson now "$(date +%s%3N)" '{unix_ms:$now}' >"$WORK/content-custody-fetch-start.json"
    content_custody_cli client content fetch-name --publisher-key "$custody_publisher" \
        --name disposable-public-custody --min-revision 1 --cache "$custody_fetch_cache" \
        --local-output "$custody_user/output.bin" >"$WORK/content-custody-fetch.json" \
        2>"$WORK/content-custody-fetch.err" || fail CUSTODY_NORMAL_FETCH_FAILED
    content_custody_phase_finish 1
    content_custody_private output "$custody_user" >"$WORK/content-custody-output.json" || fail CUSTODY_REASSEMBLY_INVALID
    [ "$(stat -Lc '%a:%u:%g' "$custody_fetch_cache")" = "700:$AGENT_UID:$AGENT_GID" ] || fail CUSTODY_FETCH_CACHE_OWNERSHIP
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$custody_fetch_cache"; then fail CUSTODY_AGENT_CACHE_EXPOSED; fi
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" --argjson control "$custody_control_gid" \
        --argjson agent_group "$AGENT_GID" '{user_uid:$user,agent_uid:$agent,control_gid:$control,agent_gid:$agent_group,
          agent_mount_positive_control:true,agent_cannot_read_user_state:true,client_cannot_read_provider_stores:true,
          user_cannot_read_agent_cache:true,fresh_consumer_cache:true,cache_mode:"0700",output_mode:"0600"}' \
        >"$WORK/content-custody-isolation.json"
    for custody_node in relay3 relay4 relay5; do
        content_custody_cli "$custody_node" content stop >"$WORK/content-custody-$custody_node-stop.json" \
            2>"$WORK/content-custody-$custody_node-stop.err" || fail CUSTODY_PROVIDER_STOP_FAILED
    done
    benchmark_disconnect_route content-custody || fail CUSTODY_ROUTE_CLEANUP_FAILED
    content_custody_cleanup || fail CUSTODY_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-retain-smoke.py" evidence "$WORK" \
        "$WORK/content-custody-evidence.json" || fail CUSTODY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-custody-complete
}

content_custody_finalize_report() {
    custody_status=$1
    for custody_artifact in "$WORK"/content-custody-*.json "$WORK"/content-custody-*.txt \
        "$WORK"/content-custody-*.log "$WORK"/content-custody-*.err "$WORK"/content-custody-*.out \
        "$WORK"/content-provider-custody-*.json "$WORK"/content-provider-custody-*.log "$WORK"/content-provider-control-*.json \
        "$WORK"/content-provider-adaptive-custody-*.json "$WORK"/content-provider-adaptive-custody-*.log \
        "$WORK"/content-provider-adaptive-control-*.json; do
        [ ! -f "$custody_artifact" ] || [ -L "$custody_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$custody_artifact" "$output_directory/$(basename -- "$custody_artifact")"
    done
    optional_json_evidence "$WORK/content-custody-evidence.json" >"$WORK/custody-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/custody-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$custody_status" --slurpfile evidence "$WORK/custody-report-evidence.part" \
        --slurpfile host "$WORK/custody-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-public-custody",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,custody:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"automatic owner selects two independent custody holders, detects a stopped service and restores redundancy on a third; owner application stopped/reaped and original source removed before fresh name retrieval on a protected two-path MPTCP route; Client node remains online",
       independent_publisher_node_offline_claimed:false,future_availability_guaranteed:false,full_alpha_acceptance_claimed:false}' \
        >"$WORK/content-custody-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/content-custody-smoke.json" "$output_directory/content-custody-smoke.json"
    python3 -B "$source_directory/tests/integration/content-custody-smoke.py" report "$WORK/content-custody-smoke.json" "$expected_commit"
}
