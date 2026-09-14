#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the guarded disposable KVM runner; seed placement is explicit setup.
# shellcheck disable=SC2154,SC2034

content_repair_config() {
    case $node in
        relay4)
            repair_address=49.165.5.1; repair_hostname=provider-a.volparossa.test
            repair_upload=ar0; repair_download=ar2 ;;
        relay5)
            repair_address=50.166.6.1; repair_hostname=provider-b.volparossa.test
            repair_upload=r5x; repair_download=r5x ;;
        *) return 0 ;;
    esac
    printf 'sharing:\n  enabled: true\n  interface: %s\n' "$repair_upload"
    printf '  total_upload_mbps: 100\n  contribution_upload_ceiling_mbps: 1\n'
    printf 'download_sharing:\n  enabled: true\n  interface: %s\n' "$repair_download"
    printf '  total_download_mbps: 100\n  contribution_download_ceiling_mbps: 1\n'
    printf 'content_contribution:\n  enabled: true\n  bind_address: "%s:18080"\n' "$repair_address"
    printf '  advertised_hostname: %s\n  cache: "%s/state-%s/repair-cache"\n' "$repair_hostname" "$WORK" "$node"
    printf '  quota_bytes: 16777216\n  max_entries: 64\n  min_free_bytes: 268435456\n'
    printf '  max_bytes: 1048576\n  max_chunks: 4\n'
}

content_repair_status() {
    repair_status_node=$1; repair_status_label=$2; repair_status_chunks=$3
    repair_status_deadline=$(($(date +%s) + 240))
    while [ "$(date +%s)" -lt "$repair_status_deadline" ]; do
        if CONTENT_REPLICATION_COMMAND_TIMEOUT=2s content_replication_cli "$repair_status_node" content status \
            >"$WORK/content-repair-$repair_status_label.json" 2>"$WORK/content-repair-$repair_status_label.err" \
            && jq -e --argjson chunks "$repair_status_chunks" '
              .serving == true and .replication_enabled == true
              and .publications == (if $chunks == 0 then 0 else 1 end)
              and .replica_publications == (if $chunks == 0 then 0 else 1 end)
              and .replica_chunks == $chunks and .replica_bytes == (262144 * $chunks)' \
                "$WORK/content-repair-$repair_status_label.json" >/dev/null; then
            if [ "$repair_status_label" != receiver-status ]; then return 0; fi
            if CONTENT_REPLICATION_COMMAND_TIMEOUT=2s content_replication_cli relay4 logs --limit 400 \
                >"$WORK/content-repair-receiver-events.txt" \
                && grep -Eq '^[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+event=CONTENT_REPAIR_COMPLETE([[:space:]]|$)' \
                    "$WORK/content-repair-receiver-events.txt"; then return 0; fi
        fi
        sleep 0.25
    done
    return 1
}

content_repair_cache_snapshot() {
    # Root opens only the report output; the bounded checker validates and locks the cache
    # as its actual unprivileged owner. /dev/null avoids double serialization to stdout.
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-repair-smoke.py" cache "$1" /dev/null >"$2"
}

content_repair_stop_node() {
    repair_stop_node=$1; repair_stop_label=$2
    case $repair_stop_node in relay4) repair_stop_ns=$R4 ;; relay5) repair_stop_ns=$R5 ;; *) return 1 ;; esac
    repair_stop_unit=volparossa-alpha-agent@$repair_stop_node.service
    case " $AGENT_UNITS " in *" $repair_stop_unit "*) ;; *) return 1 ;; esac
    repair_before_pid=$(systemctl show --property=MainPID --value "$repair_stop_unit") || return 1
    case $repair_before_pid in ''|0|*[!0-9]*) return 1 ;; esac
    repair_cache_identity=$(stat -Lc '%d:%i' "$WORK/state-$repair_stop_node/repair-cache") || return 1
    systemctl stop "$repair_stop_unit" || return 1
    repair_stop_deadline=$(($(date +%s) + 30))
    while [ "$(unit_load_state "$repair_stop_unit")" != not-found ]; do
        [ "$(date +%s)" -lt "$repair_stop_deadline" ] || return 1
        sleep 0.1
    done
    [ ! -e "/proc/$repair_before_pid" ] || return 1
    ip netns exec "$repair_stop_ns" ss -H -ltn 'sport = :18080' \
        >"$WORK/content-repair-$repair_stop_label-listeners.txt" || return 1
    [ ! -s "$WORK/content-repair-$repair_stop_label-listeners.txt" ] || return 1
    jq -cn --arg unit "$repair_stop_unit" --argjson before "$repair_before_pid" \
        --arg cache "$repair_cache_identity" '
      {unit:$unit,pid_before:$before,main_pid:0,active_state:"inactive",unit_collected:true,
       listener_absent:true,cache_identity:$cache}' >"$WORK/content-repair-$repair_stop_label.json"
}

content_repair_launch_node() {
    repair_launch_node=$1
    case $repair_launch_node in relay4) repair_launch_ns=$R4 ;; relay5) repair_launch_ns=$R5 ;; *) return 1 ;; esac
    repair_launch_unit=volparossa-alpha-agent@$repair_launch_node.service
    case " $AGENT_UNITS " in *" $repair_launch_unit "*) ;; *) return 1 ;; esac
    [ "$(unit_load_state "$repair_launch_unit")" = not-found ] || return 1
    repair_owned_units=$AGENT_UNITS
    launch_agent "$repair_launch_node" "$repair_launch_ns"
    AGENT_UNITS=$repair_owned_units
}

content_repair_restart_record() {
    repair_restart_node=$1
    case $repair_restart_node in relay4) repair_restart_ns=$R4 ;; relay5) repair_restart_ns=$R5 ;; *) return 1 ;; esac
    repair_restart_unit=volparossa-alpha-agent@$repair_restart_node.service
    repair_restart_deadline=$(($(date +%s) + 30))
    while :; do
        repair_pid=$(systemctl show --property=MainPID --value "$repair_restart_unit" 2>/dev/null || true)
        case $repair_pid in ''|0|*[!0-9]*) repair_pid=0 ;; esac
        if [ "$repair_pid" != 0 ] && [ -S "$WORK/runtime-$repair_restart_node/control/agent.sock" ]; then break; fi
        [ "$(date +%s)" -lt "$repair_restart_deadline" ] || return 1
        sleep 0.1
    done
    repair_old_pid=$(jq -er '.pid_before' "$WORK/content-repair-stopped-$repair_restart_node.json") || return 1
    [ "$repair_pid" != "$repair_old_pid" ] || return 1
    [ "$(systemctl show --property=ActiveState --value "$repair_restart_unit")" = active ] || return 1
    repair_net=$(stat -Lc '%d:%i' "/proc/$repair_pid/ns/net") || return 1
    [ "$repair_net" = "$(stat -Lc '%d:%i' "/run/netns/$repair_restart_ns")" ] || return 1
    [ "$(readlink -f -- "/proc/$repair_pid/exe")" = "$binary_directory/volparossa-agent" ] || return 1
    repair_cache_identity=$(stat -Lc '%d:%i' "$WORK/state-$repair_restart_node/repair-cache") || return 1
    [ "$repair_cache_identity" = "$(jq -er '.cache_identity' "$WORK/content-repair-stopped-$repair_restart_node.json")" ] || return 1
    jq -cn --arg unit "$repair_restart_unit" --argjson before "$repair_old_pid" --argjson after "$repair_pid" \
        --arg cache "$repair_cache_identity" --arg net "$repair_net" '
      {unit:$unit,pid_before:$before,pid_after:$after,active_state:"active",cache_identity:$cache,
       original_cache_identity_preserved:true,network_namespace_identity:$net,executable_verified:true}' \
        >"$WORK/content-repair-restarted-$repair_restart_node.json"
}

content_repair_isolation() {
    repair_iso_node=$1
    repair_iso_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$repair_iso_node.service") || return 1
    case $repair_iso_pid in ''|0|*[!0-9]*) return 1 ;; esac
    nsenter --target "$repair_iso_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-$repair_iso_node/identity.key" || return 1
    set -- "$WORK/state-relay5" "$WORK/content-repair-seed"
    if [ "$repair_iso_node" = client ]; then set -- "$@" "$WORK/state-relay4"; fi
    for repair_private in "$@"; do
        if nsenter --target "$repair_iso_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$repair_private"; then return 1; fi
    done
}

content_repair_capture() {
    [ -z "${CONTENT_REPAIR_CAPTURE_PIDS:-}" ] || return 1
    jq -cn '{phase:"repair-uptake",client:{node:"relay4",ip:"49.165.5.1"},
       relays:{relay0:"42.158.0.1",relay1:"44.160.1.1",relay2:"45.161.2.1"},
       exit:{node:"exit",ip:"46.162.3.1"},provider:{node:"relay5",ip:"50.166.6.1"}}' \
        >"$WORK/content-repair-uptake-layout.json"
    for repair_capture_role in receiver relay0 relay1 relay2 exit provider; do
        case $repair_capture_role in
            receiver) repair_capture_node=relay4; repair_capture_ns=$R4 ;;
            relay0) repair_capture_node=relay0; repair_capture_ns=$R0 ;;
            relay1) repair_capture_node=relay1; repair_capture_ns=$R1 ;;
            relay2) repair_capture_node=relay2; repair_capture_ns=$R2 ;;
            exit) repair_capture_node='exit'; repair_capture_ns=$EXIT_NODE ;;
            provider) repair_capture_node=relay5; repair_capture_ns=$R5 ;;
        esac
        repair_interfaces=$(ip -n "$repair_capture_ns" -j link show | jq -er '
          [.[] | .ifname | select(test("^(underlay|[a-z][a-z0-9]{1,5})$"))
           | select(. != "lo" and (startswith("vp") | not))] | join(" ")') || return 1
        [ -n "$repair_interfaces" ] || return 1
        # shellcheck disable=SC2086 # Split only fixed, strictly filtered physical interface names.
        ip netns exec "$repair_capture_ns" python3 -B \
            "$source_directory/tests/integration/content-replication-capture.py" capture \
            "$WORK/content-repair-uptake-layout.json" "$WORK/content-repair-uptake-$repair_capture_role.json" \
            "$WORK/content-repair-uptake-$repair_capture_role.ready" "$repair_capture_node" \
            $repair_interfaces >"$WORK/content-repair-uptake-$repair_capture_role.log" 2>&1 &
        repair_capture_pid=$!
        CONTENT_REPAIR_CAPTURE_PIDS="${CONTENT_REPAIR_CAPTURE_PIDS:-} $repair_capture_pid"
        wait_observer "$repair_capture_pid" "$WORK/content-repair-uptake-$repair_capture_role.ready" || return 1
    done
}

content_repair_stop_captures() {
    repair_capture_status=0
    for repair_capture_pid in ${CONTENT_REPAIR_CAPTURE_PIDS:-}; do
        kill -TERM "$repair_capture_pid" 2>/dev/null || true
    done
    for repair_capture_pid in ${CONTENT_REPAIR_CAPTURE_PIDS:-}; do
        wait "$repair_capture_pid" || repair_capture_status=1
    done
    CONTENT_REPAIR_CAPTURE_PIDS=
    return "$repair_capture_status"
}

content_repair_run() {
    PHASE=content-repair-initial-empty
    for repair_node in relay4 relay5; do
        content_repair_status "$repair_node" "before-$repair_node" 0 || fail CONTENT_REPAIR_NOT_INITIALLY_EMPTY
    done
    content_replication_cli relay4 status >"$WORK/content-repair-receiver-before-status.txt" || fail CONTENT_REPAIR_INITIAL_ROUTE_UNKNOWN
    if ! grep -Fx 'connected: false' "$WORK/content-repair-receiver-before-status.txt" >/dev/null \
        || ! grep -Fx 'active contexts: 0' "$WORK/content-repair-receiver-before-status.txt" >/dev/null; then
        fail CONTENT_REPAIR_INITIAL_ROUTE_EXISTS
    fi
    content_repair_stop_node relay4 stopped-relay4 || fail CONTENT_REPAIR_RECEIVER_STOP_FAILED
    content_repair_stop_node relay5 stopped-relay5 || fail CONTENT_REPAIR_HOLDER_STOP_FAILED

    PHASE=content-repair-explicit-seed
    repair_seed=$WORK/content-repair-seed/publication
    if [ -e "$repair_seed" ] || [ -L "$repair_seed" ]; then fail CONTENT_REPAIR_SEED_NOT_FRESH; fi
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/examples/content-acceptance-fixture" seed-public-repair "$repair_seed" \
        "$WORK/state-relay5/repair-cache" "$WORK/state-relay4/repair-cache" \
        >"$WORK/content-repair-seed.out" 2>"$WORK/content-repair-seed.err" || fail CONTENT_REPAIR_SEED_FAILED
    install -o root -g root -m 0600 "$repair_seed/publication.json" "$WORK/content-repair-publication.json"
    for repair_seeded in holder receiver; do
        if [ "$repair_seeded" = holder ]; then repair_seeded_node=relay5; else repair_seeded_node=relay4; fi
        content_repair_cache_snapshot \
            "$WORK/state-$repair_seeded_node/repair-cache" "$WORK/content-repair-seeded-$repair_seeded-cache.json" \
            || fail CONTENT_REPAIR_SEEDED_CACHE_INVALID
    done

    PHASE=content-repair-autonomous-uptake
    content_repair_capture || fail CONTENT_REPAIR_CAPTURE_UNAVAILABLE
    repair_start_ms=$(date +%s%3N)
    jq -cn --argjson baseline "$repair_start_ms" '
      {event_baseline_unix_ms:$baseline,captures_ready_before_restart:true,
       initial_active_contexts:0,foreground_fetch_issued:false,manual_connect_issued:false,
       initial_placement_over_network:false,publisher_source_and_key_removed_by_fixture:true}' \
        >"$WORK/content-repair-startup.json"
    # Start both without first waiting on provider discovery: no sleeping cold receiver is
    # required for this test. No connect/fetch/serve/import RPC is issued to the receiver.
    content_repair_launch_node relay5 || fail CONTENT_REPAIR_HOLDER_RELAUNCH_FAILED
    content_repair_launch_node relay4 || fail CONTENT_REPAIR_RECEIVER_RELAUNCH_FAILED
    content_repair_restart_record relay5 || fail CONTENT_REPAIR_HOLDER_RESTART_INVALID
    content_repair_restart_record relay4 || fail CONTENT_REPAIR_RECEIVER_RESTART_INVALID
    content_repair_isolation relay4 || fail CONTENT_REPAIR_RECEIVER_LOCAL_SHORTCUT
    content_repair_isolation client || fail CONTENT_REPAIR_CLIENT_LOCAL_SHORTCUT
    content_repair_status relay5 holder-status 3 || fail CONTENT_REPAIR_HOLDER_NOT_RESTORED
    content_repair_status relay4 receiver-status 3 || fail CONTENT_REPAIR_AUTONOMOUS_TRANSFER_INCOMPLETE
    content_replication_snapshot relay4 content-repair-repaired-live || fail CONTENT_REPAIR_LIVE_PATHS_MISSING
    content_repair_cache_snapshot \
        "$WORK/state-relay4/repair-cache" "$WORK/content-repair-repaired-receiver-cache.json" \
        || fail CONTENT_REPAIR_REPAIRED_CACHE_INVALID
    content_repair_stop_captures || fail CONTENT_REPAIR_CAPTURE_INCOMPLETE
    content_replication_disconnect relay4 content-repair-repaired || fail CONTENT_REPAIR_RECEIVER_ROUTE_CLEANUP

    PHASE=content-repair-holder-offline
    content_repair_stop_node relay5 holder-offline || fail CONTENT_REPAIR_HOLDER_STILL_ONLINE
    content_repair_status relay4 receiver-serving 3 || fail CONTENT_REPAIR_RECEIVER_NOT_SERVING
    repair_download=$WORK/state-client/content/repair-download
    repair_output=$WORK/state-client/content/repair-output.bin
    for repair_fresh in "$repair_download" "$repair_output"; do
        if [ -e "$repair_fresh" ] || [ -L "$repair_fresh" ]; then fail CONTENT_REPAIR_CONSUMER_NOT_FRESH; fi
    done
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$WORK/state-client/content"
    repair_publisher=$(jq -er '.publisher_hex' "$WORK/content-repair-publication.json") || fail CONTENT_REPAIR_PUBLISHER_INVALID
    content_repair_isolation client || fail CONTENT_REPAIR_CONSUMER_LOCAL_SHORTCUT
    repair_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $repair_client_pid in ''|0|*[!0-9]*) fail CONTENT_REPAIR_CLIENT_NOT_RUNNING ;; esac
    jq -cn --argjson uid "$AGENT_UID" --argjson gid "$AGENT_GID" '
      {consumer_uid:$uid,consumer_gid:$gid,capabilities_dropped:true,
       client_mount_positive_control:true,receiver_mount_positive_control:true,
       client_cannot_read_holder_cache:true,client_cannot_read_receiver_cache:true,
       receiver_cannot_read_holder_cache:true,publisher_seed_inaccessible:true,
       fresh_consumer_cache:true,fetch_input_is_publisher_and_name_only:true}' >"$WORK/content-repair-isolation.json"

    PHASE=content-repair-independent-fetch
    content_replication_select client content-repair-final || fail CONTENT_REPAIR_CONSUMER_ROUTE_UNAVAILABLE
    content_replication_capture reserve-fetch content-repair-final-fetch "$WORK/content-repair-final-selection.json" \
        || fail CONTENT_REPAIR_FETCH_CAPTURE_UNAVAILABLE
    timeout --signal=TERM --kill-after=5s 180s nsenter --target "$repair_client_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch-name --publisher-key "$repair_publisher" --name disposable-public-repair \
        --min-revision 1 --cache "$repair_download" --local-output "$repair_output" \
        >"$WORK/content-repair-final-fetch.json" 2>"$WORK/content-repair-final-fetch.err" \
        || fail CONTENT_REPAIR_NAMED_FETCH_FAILED
    python3 -B "$source_directory/tests/integration/content-repair-smoke.py" output \
        "$repair_output" "$WORK/content-repair-final-output.json" \
        >"$WORK/content-repair-final-output.out" || fail CONTENT_REPAIR_OUTPUT_INVALID
    content_replication_snapshot client content-repair-final-live || fail CONTENT_REPAIR_FINAL_PATHS_MISSING
    stop_privacy_observers || fail CONTENT_REPAIR_FETCH_CAPTURE_INCOMPLETE
    content_replication_disconnect client content-repair-final || fail CONTENT_REPAIR_CONSUMER_ROUTE_CLEANUP
    content_replication_cli relay4 content stop >"$WORK/content-repair-receiver-stop.json" \
        2>"$WORK/content-repair-receiver-stop.err" || fail CONTENT_REPAIR_RECEIVER_SERVICE_CLEANUP
    capture_product_logs
    repair_exit_deadline=$(($(date +%s) + 15))
    while :; do
        content_replication_cli exit logs --limit 400 >"$WORK/content-repair-exit-events.txt" \
            || fail CONTENT_REPAIR_EXIT_EVENTS_UNAVAILABLE
        repair_exit_completed=$(awk -v baseline="$repair_start_ms" '
          $1 + 0 >= baseline && /event=MPTCP_EXIT_FLOW_COMPLETED([[:space:]]|$)/ {count++}
          END {print count + 0}' "$WORK/content-repair-exit-events.txt")
        [ "$repair_exit_completed" -lt 2 ] || break
        [ "$(date +%s)" -lt "$repair_exit_deadline" ] || fail CONTENT_REPAIR_PROTECTED_FLOW_INCOMPLETE
        sleep 0.1
    done
    python3 -B "$source_directory/tests/integration/content-repair-smoke.py" evidence "$WORK" \
        "$WORK/content-repair-evidence.json" || fail CONTENT_REPAIR_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-repair-complete
}

content_repair_finalize_report() {
    repair_final_status=$1
    for repair_artifact in "$WORK"/content-repair-*.json "$WORK"/content-repair-*.txt \
        "$WORK"/content-repair-*.log "$WORK"/content-repair-*.err "$WORK"/content-repair-*.out; do
        [ ! -f "$repair_artifact" ] || [ -L "$repair_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$repair_artifact" "$output_directory/$(basename -- "$repair_artifact")"
    done
    optional_json_evidence "$WORK/content-repair-evidence.json" >"$WORK/repair-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/repair-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$repair_final_status" --slurpfile evidence "$WORK/repair-report-evidence.part" \
        --slurpfile host "$WORK/repair-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-content-repair",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,repair:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"healthy one-of-three-chunk public journal repaired autonomously over protected MPTCP after restart; complete original holder then stopped; independent fresh publisher/name retrieval from repaired receiver",
       initial_placement_over_network:false,independent_publisher_node_offline_claimed:false,
       future_availability_guaranteed:false,full_alpha_acceptance_claimed:false}' \
        >"$WORK/content-repair-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/content-repair-smoke.json" "$output_directory/content-repair-smoke.json"
    python3 -B "$source_directory/tests/integration/content-repair-smoke.py" report "$WORK/content-repair-smoke.json" "$expected_commit"
}
