#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only inside the disposable KVM topology; never a host radio entrypoint.
# shellcheck disable=SC2154,SC2034 # Shared state is consumed by the guarded parent.

wifi_link_prepare() {
    if [ "$(systemd-detect-virt)" != kvm ] || [ "$(hostname)" != volparossa-alpha ] \
        || [ "$(uname -r)" != 6.12.107+deb13-amd64 ]; then fail WIFI_LINK_GUEST_GUARD; fi
    if ! command -v iw >/dev/null || ! command -v modprobe >/dev/null; then
        fail WIFI_LINK_TOOLS_MISSING
    fi
    [ ! -d /sys/module/mac80211_hwsim ] || fail WIFI_LINK_PREEXISTING_HWSIM
    [ -z "$(find /sys/class/ieee80211 -mindepth 1 -maxdepth 1 -print 2>/dev/null)" ] \
        || fail WIFI_LINK_PREEXISTING_RADIO
    WIFI_LINK_MODULE_OWNED=yes
    modprobe mac80211_hwsim radios=2 || fail WIFI_LINK_HWSIM_UNAVAILABLE
    set -- /sys/class/ieee80211/phy*
    [ "$#" -eq 2 ] || fail WIFI_LINK_RADIO_COUNT
    for wifi_link_phy in "$1" "$2"; do
        [ "$(basename "$(readlink -f "$wifi_link_phy/device/subsystem")")" = mac80211_hwsim ] \
            || fail WIFI_LINK_RADIO_NOT_SIMULATED
    done
    iw phy "${1##*/}" set netns name "$CLIENT"
    iw phy "${2##*/}" set netns name "$R0"
    WIFI_LINK_CLIENT_PARENT=$(ip netns exec "$CLIENT" iw dev | awk '$1 == "Interface" {print $2}')
    WIFI_LINK_RELAY_PARENT=$(ip netns exec "$R0" iw dev | awk '$1 == "Interface" {print $2}')
    case $WIFI_LINK_CLIENT_PARENT:$WIFI_LINK_RELAY_PARENT in
        wlan[0-9]*:wlan[0-9]*) ;; *) fail WIFI_LINK_PARENT_INVALID ;;
    esac
    ip -n "$CLIENT" link set dev "$WIFI_LINK_CLIENT_PARENT" down
    ip -n "$R0" link set dev "$WIFI_LINK_RELAY_PARENT" down
    # Delete just this previously-created veth pair. The agents create/address/join its mesh
    # replacement through the real typed helper API; no fixture-created mesh association.
    ip -n "$CLIENT" link del cr0
    install -o root -g root -m 0555 "$source_directory/tests/integration/wifi-link-smoke.py" \
        "$WORK/bin/wifi-link-smoke.py"
}

wifi_link_config() {
    case $node in
        client) wifi_link_parent=$WIFI_LINK_CLIENT_PARENT; wifi_link_address=10.241.10.1 ;;
        relay0) wifi_link_parent=$WIFI_LINK_RELAY_PARENT; wifi_link_address=10.241.10.2 ;;
        *) return 0 ;;
    esac
    printf 'wifi_mesh:\n  enabled: true\n  acknowledge_open_underlay: true\n'
    printf '  parent_interface: %s\n  mesh_id: volparossa-wifi-link\n' "$wifi_link_parent"
    printf '  frequency_mhz: 2412\n  local_address: %s\n' "$wifi_link_address"
    printf '  prefix_len: 30\n  maximum_peers: 8\n'
}

wifi_link_observe_start() {
    ip netns exec "$CLIENT" python3 "$WORK/bin/wifi-link-smoke.py" mdns "$WORK" \
        "$R0_PEER" >"$WORK/wifi-link-mdns.log" 2>&1 &
    WIFI_LINK_MDNS_PID=$!
    reciprocity_wait_file "$WORK/wifi-link-mdns.ready" "$WIFI_LINK_MDNS_PID" \
        || fail WIFI_LINK_MDNS_OBSERVER_UNAVAILABLE
}

wifi_link_snapshot() {
    wifi_link_stage=$1
    for wifi_link_node in client relay0; do
        wifi_link_ns=$(reciprocity_namespace "$wifi_link_node")
        ip -n "$wifi_link_ns" -j -details link show >"$WORK/wifi-link-links-$wifi_link_node-$wifi_link_stage.json"
        wifi_link_interface=$(jq -er '[.[] | select((.ifalias // "") | startswith("volparossa-mesh:"))] |
            if length == 1 then .[0].ifname else error("one owned mesh required") end' \
            "$WORK/wifi-link-links-$wifi_link_node-$wifi_link_stage.json") || return 1
        case $wifi_link_interface in vw?????????????) ;; *) return 1 ;; esac
        ip netns exec "$wifi_link_ns" iw dev "$wifi_link_interface" info \
            >"$WORK/wifi-link-info-$wifi_link_node-$wifi_link_stage.txt" || return 1
        ip netns exec "$wifi_link_ns" iw dev "$wifi_link_interface" station dump \
            >"$WORK/wifi-link-stations-$wifi_link_node-$wifi_link_stage.txt" || return 1
        python3 "$WORK/bin/wifi-link-smoke.py" snapshot "$WORK" "$wifi_link_node" "$wifi_link_stage" \
            || return 1
    done
}

wifi_link_wait_mdns() {
    PHASE=wifi-link-mdns-only
    [ "$(printf '%s\n' "$AGENT_UNITS" | awk '{print NF}')" -eq 2 ] \
        || fail WIFI_LINK_OTHER_AGENTS_STARTED_EARLY
    for wifi_link_unit in $AGENT_UNITS; do
        case $wifi_link_unit in volparossa-alpha-agent@client.service|volparossa-alpha-agent@relay0.service) ;;
            *) fail WIFI_LINK_OTHER_AGENTS_STARTED_EARLY ;; esac
    done
    # Association is asynchronous. Retain the actual kernel station/link snapshots even if
    # discovery later fails, instead of withholding radio evidence behind the auth gate.
    wifi_link_peering_deadline=$(($(date +%s) + 25))
    while ! wifi_link_snapshot pre-auth 2>"$WORK/wifi-link-pre-auth.log"; do
        [ "$(date +%s)" -lt "$wifi_link_peering_deadline" ] || fail WIFI_LINK_PRE_AUTH_PEERING_UNAVAILABLE
        sleep 0.2
    done
    wifi_link_deadline=$(($(date +%s) + 90))
    while [ "$(date +%s)" -lt "$wifi_link_deadline" ]; do
        wifi_link_ready=yes
        for wifi_link_node in client relay0; do
            "$binary_directory/volparossa" --control-socket "$WORK/runtime-$wifi_link_node/control/agent.sock" \
                status >"$WORK/wifi-link-mdns-status-$wifi_link_node.txt" 2>/dev/null \
                || wifi_link_ready=no
        done
        if [ "$wifi_link_ready" = yes ] && python3 "$WORK/bin/wifi-link-smoke.py" authenticate \
            "$WORK" 2>"$WORK/wifi-link-authentication.log" \
            && [ -s "$WORK/wifi-link-mdns-seen.json" ]; then break; fi
        wifi_link_ready=no
        sleep 0.2
    done
    [ "$wifi_link_ready" = yes ] || fail WIFI_LINK_MDNS_AUTHENTICATION_UNAVAILABLE
    kill -TERM "$WIFI_LINK_MDNS_PID"
    wait "$WIFI_LINK_MDNS_PID" || fail WIFI_LINK_MDNS_OBSERVER_FAILED
    WIFI_LINK_MDNS_PID=
    wifi_link_snapshot associated || fail WIFI_LINK_ASSOCIATION_UNAVAILABLE
    python3 "$WORK/bin/wifi-link-smoke.py" association "$WORK" || fail WIFI_LINK_MDNS_EVIDENCE_INVALID
    # Refresh the local-link baseline after the *agent* has supplied the removed LAN address.
    ip -n "$CLIENT" -j address show >"$WORK/local-link-addresses-before.json"
    ip -n "$CLIENT" -j route show table main >"$WORK/local-link-routes-before.json"
}

wifi_link_after_payload() {
    wifi_link_snapshot payload-after || fail WIFI_LINK_PAYLOAD_COUNTERS_UNAVAILABLE
    # Route cleanup must not destroy runtime-long Wi-Fi ownership.
    for wifi_link_node in client relay0; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$wifi_link_node/control/agent.sock" \
            disconnect >"$WORK/wifi-link-disconnect-$wifi_link_node.txt" 2>&1 \
            || fail WIFI_LINK_DISCONNECT_FAILED
    done
    wifi_link_snapshot disconnected || fail WIFI_LINK_ROUTE_CLEANUP_DESTROYED_MESH
}

wifi_link_agents_stopped() {
    [ "${WIFI_LINK_MODULE_OWNED:-no}" = yes ] || return 0
    wifi_link_remaining=0
    for wifi_link_ns in "$CLIENT" "$R0"; do
        wifi_link_count=$(ip -n "$wifi_link_ns" -j link show | jq '[.[] |
            select((.ifalias // "") | startswith("volparossa-mesh:"))] | length') || return 1
        wifi_link_remaining=$((wifi_link_remaining + wifi_link_count))
    done
    jq -cn --argjson remaining "$wifi_link_remaining" \
        '{remaining_mesh_interfaces:$remaining,agents_stopped_before_helpers:true}' \
        >"$WORK/wifi-link-shutdown.json"
    [ "$wifi_link_remaining" -eq 0 ]
}

wifi_link_module_cleanup() {
    if [ -n "${WIFI_LINK_MDNS_PID:-}" ]; then
        kill -TERM "$WIFI_LINK_MDNS_PID" 2>/dev/null || true
        wait "$WIFI_LINK_MDNS_PID" 2>/dev/null || true
        WIFI_LINK_MDNS_PID=
    fi
    [ "${WIFI_LINK_MODULE_OWNED:-no}" = yes ] || return 0
    wifi_link_attempt=0
    while ! modprobe -r mac80211_hwsim; do
        [ "$wifi_link_attempt" -lt 50 ] || return 1
        sleep 0.1
        wifi_link_attempt=$((wifi_link_attempt + 1))
    done
    WIFI_LINK_MODULE_OWNED=no
    [ ! -d /sys/module/mac80211_hwsim ] || return 1
    wifi_link_radios=$(find /sys/class/ieee80211 -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l)
    jq -cn --argjson remaining "$wifi_link_radios" \
        '{hwsim_module_unloaded:true,remaining_radios:$remaining}' >"$WORK/wifi-link-radio-cleanup.json"
    [ "$wifi_link_radios" -eq 0 ]
}

wifi_link_finalize_report() {
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        '{schema_version:1,source_revision:$revision,run_id:$run,success:false,flows:[],nodes:[],
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:{unchanged:false}}' \
        >"$WORK/wifi-link-runner.json"
    python3 "$source_directory/tests/integration/wifi-link-smoke.py" report "$WORK" "$1" \
        || return 1
    for wifi_link_artifact in "$WORK"/wifi-link-*.json "$WORK"/wifi-link-*.txt "$WORK"/wifi-link-*.log; do
        if [ ! -f "$wifi_link_artifact" ] || [ -L "$wifi_link_artifact" ]; then continue; fi
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$wifi_link_artifact" \
            "$output_directory/$(basename "$wifi_link_artifact")"
    done
    jq -e '.success == true' "$WORK/wifi-link-smoke.json" >/dev/null
}
