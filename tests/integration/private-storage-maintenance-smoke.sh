#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicit disposable KVM topology; no host operation.
# shellcheck disable=SC2154,SC2034
MAINTENANCE_OWNER_PID=

private_storage_maintenance_join() {
    if [ -n "$MAINTENANCE_OWNER_PID" ]; then
        kill -TERM "$MAINTENANCE_OWNER_PID" 2>/dev/null || true
        maintenance_join_status=0
        wait "$MAINTENANCE_OWNER_PID" || maintenance_join_status=$?
        MAINTENANCE_OWNER_PID=
        # timeout forwards TERM and has its own KILL deadline; failures never
        # become successful lifecycle evidence.
        [ "$maintenance_join_status" -eq 0 ] || [ "$maintenance_join_status" -eq 143 ] || return 1
    fi
    if [ -d "$WORK/maintenance-coordinator" ] && [ ! -L "$WORK/maintenance-coordinator" ]; then
        rm -f -- "$WORK/maintenance-coordinator/ready.json" "$WORK/maintenance-coordinator/ready.part"
        rmdir -- "$WORK/maintenance-coordinator" || return 1
    fi
}

private_storage_maintenance_publish_ready() {
    # The fresh coordinator directory is root-owned and not worker-writable.
    # Publish only after install has completed both bytes and final metadata.
    install -o root -g "$WORKER_GID" -m 0640 "$WORK/maintenance-coordinator-ready.private" \
        "$WORK/maintenance-coordinator/ready.part" || return 1
    mv -- "$WORK/maintenance-coordinator/ready.part" "$WORK/maintenance-coordinator/ready.json"
}

private_storage_maintenance_wait_marker() {
    maintenance_poll=0
    while [ "$maintenance_poll" -lt 900 ]; do
        kill -0 "$MAINTENANCE_OWNER_PID" 2>/dev/null || return 1
        if private_storage_fragments_private lifecycle-check "$storage_user" "$1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
        maintenance_poll=$((maintenance_poll + 1))
    done
    return 1
}

private_storage_maintenance_supervisor_record() {
    # Fixed metadata only, written before owner cleanup can emit a secondary
    # cancellation. Diagnostic failure never changes the operation's outcome.
    if (umask 077
        python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" supervisor-record \
            "$maintenance_supervisor_stage" "$1" "$2" "$maintenance_control_relation" \
            >"$WORK/maintenance-supervisor.part") \
        && mv -- "$WORK/maintenance-supervisor.part" "$WORK/private-storage-maintenance-supervisor.json"; then
        return 0
    fi
    rm -f -- "$WORK/maintenance-supervisor.part" || true
    return 0
}

private_storage_maintenance_supervisor_stage() {
    maintenance_supervisor_stage=$1
    private_storage_maintenance_supervisor_record pending null
}

private_storage_maintenance_control_snapshot() {
    case $1 in before|detached|after) ;; *) return 1 ;; esac
    maintenance_snapshot_stage=$1
    : >"$WORK/maintenance-control-nodes.private"
    for maintenance_node in relay0 relay1 relay2 relay3 relay4 relay5; do
        content_provider_node "$maintenance_node" || return 1
        ip -n "$provider_ns" -j -d link show >"$WORK/maintenance-control-raw.private" || return 1
        [ "$(wc -c <"$WORK/maintenance-control-raw.private")" -le 65536 ] || return 1
        jq -ce '[.[] | select(.ifname | test("^(ac|ap)[012]$")) |
            {ifindex,ifname,link_index,flags,kind:.linkinfo.info_kind}]' \
            "$WORK/maintenance-control-raw.private" >"$WORK/maintenance-control-links.private" || return 1
        # Details retain explicit boot/global defaults for the closed validator.
        ip -n "$provider_ns" -j -d -4 route show >"$WORK/maintenance-control-raw.private" || return 1
        [ "$(wc -c <"$WORK/maintenance-control-raw.private")" -le 65536 ] || return 1
        jq -ce '[.[] | select((.dev // "") | test("^(ac|ap)[012]$")) |
            {dst,dev,gateway,prefsrc,scope,protocol}]' \
            "$WORK/maintenance-control-raw.private" >"$WORK/maintenance-control-routes.private" || return 1
        ip netns exec "$provider_ns" nft -j list tables >"$WORK/maintenance-control-tables.private" || return 1
        [ "$(wc -c <"$WORK/maintenance-control-tables.private")" -le 65536 ] || return 1
        jq -e '.nftables | type == "array"' "$WORK/maintenance-control-tables.private" >/dev/null || return 1
        printf '{}\n' >"$WORK/maintenance-control-table-rows.private"
        for maintenance_slot in 0 1 2; do
            maintenance_table=vpa_content_control_adaptive_$maintenance_slot
            if jq -e --arg name "$maintenance_table" 'any(.nftables[];
                .table.family == "inet" and .table.name == $name)' \
                "$WORK/maintenance-control-tables.private" >/dev/null; then
                ip netns exec "$provider_ns" nft -j list table inet "$maintenance_table" \
                    >"$WORK/maintenance-control-raw.private" || return 1
                [ "$(wc -c <"$WORK/maintenance-control-raw.private")" -le 16384 ] || return 1
                jq -cn --arg name "$maintenance_table" --slurpfile table "$WORK/maintenance-control-raw.private" \
                    '{($name):$table[0]}' >>"$WORK/maintenance-control-table-rows.private" || return 1
            fi
        done
        jq -s 'add' "$WORK/maintenance-control-table-rows.private" >"$WORK/maintenance-control-filter.private" || return 1
        jq -cn --arg node "$maintenance_node" --slurpfile links "$WORK/maintenance-control-links.private" \
            --slurpfile routes "$WORK/maintenance-control-routes.private" \
            --slurpfile tables "$WORK/maintenance-control-filter.private" \
            '{($node):{links:$links[0],routes:$routes[0],tables:$tables[0]}}' \
            >>"$WORK/maintenance-control-nodes.private" || return 1
    done
    jq -s 'add' "$WORK/maintenance-control-nodes.private" >"$WORK/maintenance-control-inventory.private" || return 1
    printf 'null\n' >"$WORK/maintenance-control-checks.private"
    if [ "$maintenance_snapshot_stage" = after ]; then
        : >"$WORK/maintenance-control-check-rows.private"
        for maintenance_node in relay3 relay4 relay5; do
            content_provider_node "$maintenance_node" || return 1
            ip -n "$provider_control_ns" -j route get "$provider_ip" >"$WORK/maintenance-control-raw.private" || return 1
            [ "$(wc -c <"$WORK/maintenance-control-raw.private")" -le 8192 ] || return 1
            jq -ce '[.[] | {dst,dev,gateway,prefsrc}]' "$WORK/maintenance-control-raw.private" \
                >"$WORK/maintenance-control-out.private" || return 1
            ip -n "$provider_ns" -j route get "$provider_control_ip" >"$WORK/maintenance-control-raw.private" || return 1
            [ "$(wc -c <"$WORK/maintenance-control-raw.private")" -le 8192 ] || return 1
            jq -ce '[.[] | {dst,dev,gateway,prefsrc}]' "$WORK/maintenance-control-raw.private" \
                >"$WORK/maintenance-control-back.private" || return 1
            jq -cn --arg node "$maintenance_node" --slurpfile out "$WORK/maintenance-control-out.private" \
                --slurpfile back "$WORK/maintenance-control-back.private" '{($node):{out:$out[0],back:$back[0]}}' \
                >>"$WORK/maintenance-control-check-rows.private" || return 1
        done
        jq -s 'add' "$WORK/maintenance-control-check-rows.private" >"$WORK/maintenance-control-checks.private" || return 1
    fi
    jq -cn --slurpfile nodes "$WORK/maintenance-control-inventory.private" \
        --slurpfile checks "$WORK/maintenance-control-checks.private" \
        '{nodes:$nodes[0],route_checks:$checks[0]}' >"$WORK/maintenance-control-$maintenance_snapshot_stage.private" || return 1
}

private_storage_maintenance_control_current() {
    maintenance_observed_peer=$(content_custody_cli client content status | jq -er \
        '.control_relay_peer_id | select(type == "string" and length > 0)') || return 1
    [ "$maintenance_observed_peer" = "$provider_control_peer" ]
}

private_storage_maintenance_phase_layout() {
    private_storage_maintenance_control_current || return 1
    if [ "$1" = upload ]; then
        jq -cn --argjson scope "$storage_route_scope" '{route_scope:$scope}'
    else
        maintenance_transition_sha=$(sha256sum "$WORK/private-storage-maintenance-control-transition.json" | awk '{print $1}') || return 1
        jq -cn --argjson scope "$storage_route_scope" --arg sha "$maintenance_transition_sha" \
            '{route_scope:$scope,control_transition_sha256:$sha}'
    fi
}

private_storage_maintenance_control_transition() {
    umask 077
    [ -z "$PROVIDER_CONTROL_PID" ] || return 1
    maintenance_previous_peer=$provider_control_peer
    maintenance_previous_ns=$provider_control_ns
    private_storage_maintenance_supervisor_stage broker_validated
    jq -e --arg peer "$maintenance_control_peer" '[.relay0,.relay1,.relay2] | index($peer) != null' \
        "$WORK/a01-expected-peers.json" >/dev/null || return 1
    private_storage_maintenance_supervisor_stage control_snapshot
    private_storage_maintenance_control_snapshot before || return 1
    maintenance_layout_sha=$(sha256sum "$WORK/private-storage-fragments-layout.json" | awk '{print $1}') || return 1
    maintenance_canonical_sha=$(jq -cSj '.' "$WORK/private-storage-fragments-layout.json" | sha256sum | awk '{print $1}') || return 1
    jq -cn --arg raw "$maintenance_layout_sha" --arg canonical "$maintenance_canonical_sha" \
        --arg previous "$maintenance_previous_peer" --arg current "$maintenance_control_peer" \
        --arg relation "$maintenance_control_relation" --slurpfile before "$WORK/maintenance-control-before.private" \
        '{schema_version:1,kind:"storage-maintenance-control-transition",original_layout_sha256:$raw,
          original_layout_canonical_sha256:$canonical,previous_control_relay_peer_id:$previous,
          current_control_relay_peer_id:$current,relation:$relation,before:$before[0],detached:null,after:null}' \
        >"$WORK/maintenance-control-transition.private" || return 1
    private_storage_maintenance_supervisor_stage control_validate_before
    python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" control-transition-check \
        "$WORK" "$WORK/maintenance-control-transition.private" before || return 1
    private_storage_maintenance_supervisor_stage control_rebind
    if [ "$maintenance_control_relation" = different ]; then
        # Only validated owned veths are removed; peer deletion also removes
        # their kernel routes. Filters survive until every old link is gone.
        for maintenance_slot in 0 1 2; do
            ip -n "$maintenance_previous_ns" link delete "ac$maintenance_slot" || return 1
        done
        for maintenance_node in relay0 relay1 relay2 relay3 relay4 relay5; do
            content_provider_node "$maintenance_node" || return 1
            ip -n "$provider_ns" -j link show >"$WORK/maintenance-control-raw.private" || return 1
            [ "$(wc -c <"$WORK/maintenance-control-raw.private")" -le 65536 ] || return 1
            jq -e 'all(.[]; (.ifname | test("^(ac|ap)[012]$")) | not)' \
                "$WORK/maintenance-control-raw.private" >/dev/null || return 1
        done
        for maintenance_slot in 0 1 2; do
            ip netns exec "$maintenance_previous_ns" nft delete table inet \
                "vpa_content_control_adaptive_$maintenance_slot" || return 1
            content_provider_node "relay$((3 + maintenance_slot))" || return 1
            ip netns exec "$provider_ns" nft delete table inet \
                "vpa_content_control_adaptive_$maintenance_slot" || return 1
        done
        private_storage_maintenance_control_snapshot detached || return 1
        jq --slurpfile detached "$WORK/maintenance-control-detached.private" '.detached=$detached[0]' \
            "$WORK/maintenance-control-transition.private" >"$WORK/maintenance-control-next.private" || return 1
        mv -- "$WORK/maintenance-control-next.private" "$WORK/maintenance-control-transition.private" || return 1
        python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" control-transition-check \
            "$WORK" "$WORK/maintenance-control-transition.private" detached || return 1
        content_provider_adaptive_control_underlay "$maintenance_control_peer" \
            private-storage-maintenance-current-control || return 1
    fi
    private_storage_maintenance_supervisor_stage control_verified
    private_storage_maintenance_control_current || return 1
    private_storage_maintenance_control_snapshot after || return 1
    jq -cSj --slurpfile after "$WORK/maintenance-control-after.private" '.after=$after[0]' \
        "$WORK/maintenance-control-transition.private" >"$WORK/maintenance-control-next.private" || return 1
    [ "$(wc -c <"$WORK/maintenance-control-next.private")" -le 131072 ] || return 1
    python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" control-transition-check \
        "$WORK" "$WORK/maintenance-control-next.private" complete || return 1
    mv -- "$WORK/maintenance-control-next.private" "$WORK/private-storage-maintenance-control-transition.json"
}

private_storage_maintenance_post_reconnect() {
    maintenance_control_relation=unobserved
    private_storage_maintenance_supervisor_stage bind_slots
    benchmark_bind_slots "$WORK/private-storage-maintenance-reconnect-selection.json" || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    # A fresh agent may choose a different ordinary broker. Preserve the old
    # upload proof, then move only the exact owned, UDP-only control links.
    private_storage_maintenance_supervisor_stage control_query
    maintenance_control_peer=$(content_custody_cli client content status | jq -er '.control_relay_peer_id') || {
        # This is the original pipeline's status, not a claimed CLI-only status.
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    if [ -z "$maintenance_control_peer" ]; then maintenance_control_relation=empty
    elif [ "$maintenance_control_peer" = "$provider_control_peer" ]; then maintenance_control_relation=same
    else maintenance_control_relation=different; fi
    private_storage_maintenance_control_transition || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage route_scope
    storage_route_scope=$(jq -ce '{exit_peer_id:.exact_selected_exit,paths:[.paths[]|{path_id,relay_peer_id}]}' \
        "$WORK/private-storage-maintenance-reconnect-selection.json") || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage start_observers
    private_storage_fragments_phase_start lifecycle || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage ready_payload
    jq -cn --argjson baseline "$provider_baseline_ms" --argjson scope "$storage_route_scope" \
        '{baseline:$baseline,scope:$scope}' >"$WORK/maintenance-coordinator-ready.private" || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage publish_ready
    private_storage_maintenance_publish_ready || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage join_owner
    maintenance_status=0
    wait "$MAINTENANCE_OWNER_PID" || maintenance_status=$?
    MAINTENANCE_OWNER_PID=
    if [ "$maintenance_status" -ne 0 ]; then
        private_storage_maintenance_supervisor_record failed "$maintenance_status"; return 1
    fi
    private_storage_maintenance_supervisor_stage lifecycle_receipt
    jq -ce '. + {guest_core_pid_changed:true,guest_core_namespace_preserved:true}' \
        "$WORK/maintenance-owner-lifecycle.private" >"$WORK/private-storage-maintenance-lifecycle.json" || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage finish_observers
    private_storage_fragments_phase_finish 1 || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_stage coordinator_cleanup
    private_storage_maintenance_join || {
        private_storage_maintenance_supervisor_record failed "$?"; return 1;
    }
    private_storage_maintenance_supervisor_record complete 0
}

private_storage_maintenance_lifecycle() {
    PHASE=private-storage-maintenance-core-restart
    [ ! -e "$WORK/maintenance-coordinator" ] && [ ! -L "$WORK/maintenance-coordinator" ] || return 1
    install -d -o root -g "$WORKER_GID" -m 0750 "$WORK/maintenance-coordinator"
    timeout --signal=TERM --kill-after=15s 1800s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" lifecycle "$storage_user" \
        "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" >"$WORK/maintenance-owner-lifecycle.private" &
    MAINTENANCE_OWNER_PID=$!
    private_storage_maintenance_wait_marker working || return 1
    maintenance_old_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $maintenance_old_pid in ''|0|*[!0-9]*) return 1 ;; esac
    maintenance_namespace=$(stat -Lc '%d:%i' "/run/netns/$CLIENT") || return 1
    [ "$(stat -Lc '%d:%i' "/proc/$maintenance_old_pid/ns/net")" = "$maintenance_namespace" ] || return 1
    [ "$(readlink -f "/proc/$maintenance_old_pid/exe")" = "$binary_directory/volparossa-agent" ] || return 1
    # Only this already-owned disposable unit is stopped, never a caller-selected service.
    retire_unit volparossa-alpha-agent@client.service || return 1
    private_storage_maintenance_wait_marker unavailable || return 1
    maintenance_poll=0
    while [ "$(unit_load_state volparossa-alpha-agent@client.service)" != not-found ]; do
        [ "$maintenance_poll" -lt 100 ] || return 1
        sleep 0.1
        maintenance_poll=$((maintenance_poll + 1))
    done
    launch_agent client "$CLIENT"
    maintenance_poll=0
    while [ "$maintenance_poll" -lt 300 ]; do
        maintenance_new_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
        case $maintenance_new_pid in ''|0|*[!0-9]*) ;;
            *) [ -S "$WORK/runtime-client/control/agent.sock" ] && break ;;
        esac
        sleep 0.1
        maintenance_poll=$((maintenance_poll + 1))
    done
    [ "$maintenance_poll" -lt 300 ] && [ "$maintenance_new_pid" != "$maintenance_old_pid" ] || return 1
    [ "$(stat -Lc '%d:%i' "/proc/$maintenance_new_pid/ns/net")" = "$maintenance_namespace" ] || return 1
    [ "$(readlink -f "/proc/$maintenance_new_pid/exe")" = "$binary_directory/volparossa-agent" ] || return 1
    # Reuse current read-only inventory and ordinary protected selection barriers.
    python3 -I -B "$WORK/bin/content-provider-readiness.py" "$WORK" \
        >"$WORK/maintenance-inventory.private" || return 1
    benchmark_select_route private-storage-maintenance-reconnect mptcp || return 1
    private_storage_maintenance_post_reconnect
}

private_storage_maintenance_initial_inventory() {
    PHASE=private-storage-maintenance-inventory
    maintenance_inventory_status=0
    # This content-custody shortcut skips A01. Its Client deliberately cannot
    # see custody peers relay3/4/5; reuse the same relay0/1/2 + primary Exit
    # barrier as reconnect, not the six-relay discovered-compute fixture.
    (umask 077
     python3 -I -B "$WORK/bin/content-provider-readiness.py" "$WORK" \
        >"$WORK/maintenance-initial-inventory.part") || maintenance_inventory_status=$?
    if python3 -B "$WORK/bin/private-storage-maintenance-smoke.py" inventory-check \
        "$WORK/maintenance-initial-inventory.part" "$maintenance_inventory_status"; then
        mv -- "$WORK/maintenance-initial-inventory.part" \
            "$WORK/private-storage-maintenance-inventory.json" || fail MAINTENANCE_INVENTORY_INVALID
    else
        rm -f -- "$WORK/maintenance-initial-inventory.part"
        fail MAINTENANCE_INVENTORY_INVALID
    fi
    [ "$maintenance_inventory_status" -eq 0 ] || fail MAINTENANCE_INVENTORY_UNAVAILABLE
}

private_storage_maintenance_run() {
    storage_fixture_driver=private-storage-maintenance-smoke.py
    # Preserve all core exchange/turn deadlines. The fixture includes real daemon
    # ticks, quiet-link cooldown and bounded attempts against stopped provider A.
    storage_phase_timeout_seconds=2400
    ip -n "$CLIENT" -j -d link show cr0 | jq -e 'length == 1 and .[0].linkinfo.info_kind == "veth"
        and (.[0].flags | index("UP")) != null' >/dev/null || fail MAINTENANCE_GUEST_LINK_MISSING
    private_storage_maintenance_initial_inventory
    private_storage_fragments_run
}

private_storage_maintenance_finalize_report() {
    maintenance_status=$1
    # The explicit new trial selects v9; default/historical v7 remains unchanged.
    case ${storage_consumer_profile_version-7} in
        7) maintenance_diagnostic_command=route-diagnostic; maintenance_schema=6; maintenance_report_command=report-consumer-v7 ;;
        8) maintenance_diagnostic_command=route-diagnostic-v3; maintenance_schema=7; maintenance_report_command=report-consumer-v8 ;;
        9) maintenance_diagnostic_command=route-diagnostic-v3; maintenance_schema=8; maintenance_report_command=report-consumer-v9 ;;
        *) return 1 ;;
    esac
    # Already published at the original supervisor gate, before TERM/cleanup.
    # Reject malformed private metadata rather than exporting it as evidence.
    if [ -e "$WORK/private-storage-maintenance-supervisor.json" ] \
        || [ -L "$WORK/private-storage-maintenance-supervisor.json" ]; then
        if ! python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" supervisor-check \
            "$WORK/private-storage-maintenance-supervisor.json" >/dev/null 2>&1; then
            rm -f -- "$WORK/private-storage-maintenance-supervisor.json" || return 1
        fi
    fi
    # Cleanup has already captured the bounded client event ring before stopping
    # agents. Export only closed categories/counts; diagnostic failure is not a
    # replacement for the original outcome and never changes acceptance.
    # The same Python process independently publishes a closed provider-event
    # sidecar from the existing pre-agent-stop captures; no additional RPC.
    if python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" "$maintenance_diagnostic_command" \
        "$WORK" "$PHASE" "${provider_baseline_ms:-0}" >"$WORK/maintenance-route-diagnostic.part" 2>/dev/null; then
        mv -- "$WORK/maintenance-route-diagnostic.part" "$WORK/private-storage-maintenance-route-diagnostic.json" || true
    else
        rm -f -- "$WORK/maintenance-route-diagnostic.part" || true
    fi
    # The owner emits a closed failure receipt, not raw stderr. Preserve it only
    # after strict bounded schema validation, including on lifecycle failure.
    if [ "$maintenance_status" -ne 0 ] && [ -f "$WORK/maintenance-owner-lifecycle.private" ]; then
        if python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" lifecycle-failure \
            "$WORK/maintenance-owner-lifecycle.private" >"$WORK/maintenance-lifecycle-failure.part" 2>/dev/null; then
            mv -- "$WORK/maintenance-lifecycle-failure.part" "$WORK/private-storage-maintenance-lifecycle-failure.json"
        else
            rm -f -- "$WORK/maintenance-lifecycle-failure.part"
        fi
    fi
    optional_json_evidence "$WORK/private-storage-maintenance-evidence.json" >"$WORK/handoff-report-evidence.part"
    optional_json_evidence "$WORK/storage-consumer-evidence.json" >"$WORK/handoff-report-consumers.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/handoff-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$maintenance_status" --slurpfile evidence "$WORK/handoff-report-evidence.part" \
        --slurpfile consumers "$WORK/handoff-report-consumers.part" \
        --slurpfile host "$WORK/handoff-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" --argjson schema "$maintenance_schema" '
      {schema_version:$schema,report_kind:"volparossa-private-storage-maintenance",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,maintenance:$evidence[0],consumers:$consumers[0],
       success:($status == 0 and $evidence[0].success == true and $consumers[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"Finite owner enrollment and protected renewal/repair across core restart, SIGTERM/resume and foreground revocation. Separate pinned Image encrypted snapshot and Cloud authenticated DAV-body restoration after A withdrawal, with retained original authority, actual replacement custody and independent zero provider usage. Synthetic inputs only; no running Immich/OpenCloud account server, independent-device availability, reciprocal credit, contribution resizing or full-alpha proof."}' \
        >"$WORK/private-storage-maintenance-smoke.json" || return 1
    maintenance_exports=$(python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" export-names "$WORK") || return 1
    for maintenance_name in $maintenance_exports; do
        maintenance_artifact=$WORK/$maintenance_name
        if [ -f "$maintenance_artifact" ] && [ ! -L "$maintenance_artifact" ]; then
            [ "$(wc -c <"$maintenance_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$maintenance_artifact" "$output_directory/$maintenance_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" "$maintenance_report_command" \
        "$WORK/private-storage-maintenance-smoke.json" "$expected_commit"
}
