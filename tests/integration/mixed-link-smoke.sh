#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the exact-build, disposable Debian KVM runner.
# shellcheck disable=SC2154 # Identities, paths and ownership come from the guarded parent.

mixed_link_extend_network() {
    # These exact objects exist only in the namespaces just created by the guarded runner.
    ip -n "$CLIENT" route del 44.160.1.1/32
    ip -n "$EXIT_NODE" route del 44.160.1.1/32
    ip -n "$B1" route del 44.160.1.1/32
    ip -n "$B2" route del 44.160.1.1/32
    for mixed_peer in 43.159.1.1 40.156.1.1 41.157.2.1 46.162.3.1; do
        ip -n "$R1" route del "$mixed_peer/32"
    done
    for mixed_interface in r1b1 r1b2 underlay; do
        ip -n "$R1" link del "$mixed_interface"
    done
    mixed_link_snapshot_local_relay before
}

mixed_link_snapshot_local_relay() {
    mixed_stage=$1
    ip -n "$R1" -j address show >"$WORK/mixed-link-relay1-addresses-$mixed_stage.json"
    ip -n "$R1" -j route show table main >"$WORK/mixed-link-relay1-routes-$mixed_stage.json"
    jq -en --slurpfile addresses "$WORK/mixed-link-relay1-addresses-$mixed_stage.json" \
        --slurpfile routes "$WORK/mixed-link-relay1-routes-$mixed_stage.json" '
        ([$addresses[0][].addr_info[] | select(.scope == "global") | .local] | sort)
          == ["10.241.11.2", "10.241.21.1"] and
        all($routes[0][]; .dst != "default")
    ' >/dev/null || fail MIXED_LINK_LOCAL_RELAY_HAS_PUBLIC_UPLINK
}

# shellcheck disable=SC2034 # These exact config values are consumed by the parent write_config.
mixed_link_configure_node() {
    # Bootstrap addresses are actual adjacent authenticated contacts, never role/Exit overrides.
    case $node in
        client)
            extra_listen=10.241.11.1
            bootstrap_one="/ip4/42.158.0.1/udp/41000/quic-v1/p2p/$R0_PEER"
            bootstrap_two="/ip4/10.241.11.2/udp/41000/quic-v1/p2p/$R1_PEER"
            bootstrap_three="/ip4/45.161.2.1/udp/41000/quic-v1/p2p/$R2_PEER"
            ;;
        relay0|relay2)
            bootstrap_one="/ip4/43.159.1.1/udp/41000/quic-v1/p2p/$CLIENT_PEER"
            bootstrap_two="/ip4/46.162.3.1/udp/41000/quic-v1/p2p/$EXIT_PEER"
            bootstrap_three=none
            ;;
        relay1)
            uplink=local_only; advertised_asn=0; advertised_prefix=null
            client_role=false; relay_role=true; exit_role=false; exit_capacity=0
            listen_ip=10.241.11.2; extra_listen=10.241.21.1
            bootstrap_one="/ip4/10.241.11.1/udp/41000/quic-v1/p2p/$CLIENT_PEER"
            bootstrap_two="/ip4/10.241.21.2/udp/41000/quic-v1/p2p/$EXIT_PEER"
            bootstrap_three=none
            ;;
        exit)
            extra_listen=10.241.21.2
            bootstrap_one="/ip4/42.158.0.1/udp/41000/quic-v1/p2p/$R0_PEER"
            bootstrap_two="/ip4/10.241.21.1/udp/41000/quic-v1/p2p/$R1_PEER"
            bootstrap_three="/ip4/45.161.2.1/udp/41000/quic-v1/p2p/$R2_PEER"
            ;;
        *)
            client_role=false; relay_role=false; exit_role=false
            relay_capacity=0; exit_capacity=0
            bootstrap_one=none; bootstrap_two=none; bootstrap_three=none
            ;;
    esac
}

mixed_link_wait_discovery() {
    PHASE=mixed-link-discovery
    mixed_deadline=$(($(date +%s) + 120))
    while [ "$(date +%s)" -lt "$mixed_deadline" ]; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" peers \
            >"$WORK/mixed-link-peers-client.txt" || return 1
        mixed_ready=yes
        for mixed_peer in "$R0_PEER" "$R1_PEER" "$R2_PEER"; do
            awk -v peer="$mixed_peer" '$1 == peer && $2 == "roles=0b010" { found=1 }
                END { exit !found }' "$WORK/mixed-link-peers-client.txt" || mixed_ready=no
        done
        awk -v peer="$EXIT_PEER" '$1 == peer && $2 == "roles=0b100" { found=1 }
            END { exit !found }' "$WORK/mixed-link-peers-client.txt" || mixed_ready=no
        if [ "$mixed_ready" = yes ]; then
            "$binary_directory/volparossa" \
                --control-socket "$WORK/runtime-relay1/control/agent.sock" role show \
                >"$WORK/mixed-link-roles-relay1.txt" || return 1
            for mixed_role in 'client: false' 'relay: true' 'exit: false'; do
                grep -Fx "$mixed_role" "$WORK/mixed-link-roles-relay1.txt" >/dev/null || return 1
            done
            return 0
        fi
        sleep 0.2
    done
    return 1
}

mixed_link_transient_connect_unavailable() {
    grep -Eq '^Error: agent rejected request: (PRESELECTION_UNAVAILABLE|NATIVE_PERMIT_UNAVAILABLE|NATIVE_RELAY_READY_UNAVAILABLE|NATIVE_HELPER_COMMIT_UNAVAILABLE|NATIVE_PROBE_START_UNAVAILABLE|NATIVE_PROBE_PROOF_UNAVAILABLE|ROUTE_ADMISSION_UNAVAILABLE) \(Unavailable\)$' "$1"
}

mixed_link_select_paths() {
    # All three authenticated Relays remain eligible; draw before the application starts.
    benchmark_select_route mixed-link multipath-quic \
        && wait_active_native_mpquic_paths a06-preconnect-native-paths
}

mixed_link_validate_evidence() {
    mixed_link_snapshot_local_relay after
    jq -S -cn --slurpfile transfer "$WORK/a06-evidence.json" \
        --slurpfile client "$WORK/privacy-client.json" \
        --slurpfile lan "$WORK/privacy-relay1.json" \
        --slurpfile wan "$WORK/privacy-relay2.json" \
        --slurpfile exit "$WORK/privacy-exit.json" \
        --arg relay1 "$R1_PEER" --arg relay2 "$R2_PEER" --arg exit_peer "$EXIT_PEER" '
        ($transfer[0] | del(.acceptance_id)) as $transfer |
        ([$client[0],$lan[0],$wan[0],$exit[0]]) as $captures |
        ($transfer.success and
          ($transfer.native_mpquic.paths | length) == 2 and
          ([$transfer.native_mpquic.paths[].relay_peer_id] | sort) == ([$relay1,$relay2] | sort) and
          all($transfer.native_mpquic.paths[];
            .exit_peer_id == $exit_peer and .state == 3) and
          all($transfer.path_evidence[];
            .relay1_wireguard_data_bytes > 1048576 and .relay2_wireguard_data_bytes > 1048576) and
          all($captures[]; .truncated == false and .observed_frames > 0 and
            .expected_link_down_notifications == 0 and .unexpected_outer_packets == 0) and
          $client[0].direct_client_exit_packets == 0 and
          $client[0].internet_destination_outer_packets == 0 and
          $lan[0].internet_destination_outer_packets == 0 and
          $wan[0].internet_destination_outer_packets == 0 and
          $exit[0].client_public_packets == 0 and $exit[0].direct_client_exit_packets == 0 and
          $lan[0].client_leg_wireguard_data_datagrams > 0 and
          $lan[0].exit_leg_wireguard_data_datagrams > 0 and
          $wan[0].client_leg_wireguard_data_datagrams > 0 and
          $wan[0].exit_leg_wireguard_data_datagrams > 0) as $success |
        {success:$success,transfer:$transfer,
          local_only_relay:{node:"relay1",peer_id:$relay1,exit_enabled:false,
            independent_internet:false,asn:null,public_prefix:null,physical_default_routes:0},
          paths:[
            {relay_peer_id:$relay1,exit_peer_id:$exit_peer,
             client_relay_scope:"DirectLocalLan",relay_exit_scope:"DirectLocalLan",
             client_relay_endpoints:["10.241.11.1","10.241.11.2"],
             relay_exit_endpoints:["10.241.21.1","10.241.21.2"],
             wireguard_both_legs:[$lan[0].client_leg_wireguard_data_datagrams,
               $lan[0].exit_leg_wireguard_data_datagrams]},
            {relay_peer_id:$relay2,exit_peer_id:$exit_peer,
             client_relay_scope:"PublicInternet",relay_exit_scope:"PublicInternet",
             client_relay_endpoints:["43.159.1.1","45.161.2.1"],
             relay_exit_endpoints:["45.161.2.1","46.162.3.1"],
             wireguard_both_legs:[$wan[0].client_leg_wireguard_data_datagrams,
               $wan[0].exit_leg_wireguard_data_datagrams]}],
          privacy:{client:$client[0],local_relay:$lan[0],public_relay:$wan[0],exit:$exit[0]},
          bandwidth_aggregation_claimed:false,ordinary_quic_fallback_allowed:false}
    ' >"$WORK/mixed-link-evidence.json" || return 1
    jq -e '.success == true' "$WORK/mixed-link-evidence.json" >/dev/null
}

mixed_link_finalize_report() {
    mixed_status=$1
    mixed_evidence='{"success":false,"paths":[]}'
    [ ! -s "$WORK/mixed-link-evidence.json" ] \
        || mixed_evidence=$(cat "$WORK/mixed-link-evidence.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$mixed_status" --argjson evidence "$mixed_evidence" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" '
        $evidence + {schema_version:1,report_kind:"volparossa-mixed-link-runtime",
          source_revision:$revision,run_id:$run_id,phase:$phase,
          success:($status == 0 and $evidence.success and $complete and
            $remaining == 0 and $host[0].unchanged),
          observed_blocker:(if $blocker == "" then null else $blocker end),
          cleanup:{complete:$complete,remaining_owned_objects:$remaining},
          host_state:($host[0] | del(.acceptance_id)),
          scope:"real HTTP/3 over two native MPQUIC paths, one LAN Relay and one public Relay; no bandwidth aggregation, radio or A01-A15 claim"}
    ' >"$WORK/mixed-link-smoke.json" || return 1
    for mixed_artifact in "$WORK"/mixed-link-*.json "$WORK"/mixed-link-*.txt \
        "$WORK"/mixed-link-*.out "$WORK"/mixed-link-*.err; do
        [ ! -f "$mixed_artifact" ] || [ -L "$mixed_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$mixed_artifact" \
                "$output_directory/$(basename -- "$mixed_artifact")"
    done
    jq -e '.success == true' "$WORK/mixed-link-smoke.json" >/dev/null
}
