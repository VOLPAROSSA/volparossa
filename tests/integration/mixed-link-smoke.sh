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

# shellcheck disable=SC2034 # Parent cleanup/stop_privacy_observers owns these four process slots.
mixed_link_bandwidth_privacy_start() {
    mixed_privacy_dir="$WORK/$mixed_prefix-privacy"
    install -d -o root -g root -m 0700 "$mixed_privacy_dir"
    for mixed_capture_node in client relay1 relay2 exit; do
        case $mixed_capture_node in
            client) mixed_capture_ns=$CLIENT; set -- cr0 cr1 cr2 cr3 cr4 cr5 cb1 cb2 underlay ;;
            relay1) mixed_capture_ns=$R1; set -- r1c r1x ;;
            relay2) mixed_capture_ns=$R2; set -- r2c r2x underlay ;;
            exit) mixed_capture_ns=$EXIT_NODE; set -- xr0 xr1 xr2 xr3 xr4 xr5 xd underlay ;;
        esac
        ip netns exec "$mixed_capture_ns" python3 -B "$WORK/bin/privacy-observer.py" \
            "$mixed_capture_node" "$mixed_privacy_dir/$mixed_capture_node.json" \
            "$mixed_privacy_dir/$mixed_capture_node.ready" --direct-lan-relay1 "$@" \
            >"$mixed_privacy_dir/$mixed_capture_node.log" 2>&1 &
        mixed_capture_pid=$!
        case $mixed_capture_node in
            client) PRIVACY_CLIENT_PID=$mixed_capture_pid ;;
            relay1) PRIVACY_RELAY1_PID=$mixed_capture_pid ;;
            relay2) PRIVACY_RELAY2_PID=$mixed_capture_pid ;;
            exit) PRIVACY_EXIT_PID=$mixed_capture_pid ;;
        esac
        wait_observer "$mixed_capture_pid" "$mixed_privacy_dir/$mixed_capture_node.ready" || return 1
    done
}

mixed_link_bandwidth_prepare_route() {
    case $1 in
        mixed-single)
            # A06 left this real two-path route running. Start a new HTTP/3 flow on it;
            # normal ingress still checks signed route/policy expiry, without renewal.
            ;;
        mixed-aggregate)
            benchmark_disconnect_route "$2" || return 1
            benchmark_select_route "$2" multipath-quic || return 1
            ;;
        *) return 1 ;;
    esac
    wait_active_native_mpquic_paths "$2-before" || return 1
    [ "$1" = mixed-single ] || return 0
    jq -en --slurpfile initial "$WORK/mixed-link-evidence.json" \
        --slurpfile current "$WORK/$2-before.json" \
        --arg r1 "$R1_PEER" --arg r2 "$R2_PEER" --arg exit "$EXIT_PEER" '
        def identity: {route_context_id, paths:([.paths[] |
          {path_id,relay_peer_id,exit_peer_id}] | sort_by(.path_id))};
        def active: (.route_context_id | test("^[0-9a-f]{32}$")) and
          (.paths|length)==2 and ([.paths[].relay_peer_id]|sort)==([$r1,$r2]|sort) and
          ([.paths[].path_id]|unique|length)==2 and all(.paths[]; .state==3 and .exit_peer_id==$exit);
        $initial[0].transfer.native_mpquic as $prior |
        $initial[0].success==true and ($prior|active) and ($current[0]|active) and
          ($prior|identity)==($current[0]|identity)
    ' >/dev/null
}

mixed_link_bandwidth_case() {
    mixed_case=$1; mixed_port=$2
    mixed_prefix="mixed-link-${mixed_case#mixed-}"
    PHASE="$mixed_prefix-selection"
    mixed_link_bandwidth_prepare_route "$mixed_case" "$mixed_prefix" || return 1
    mixed_link_bandwidth_privacy_start || return 1
    start_http3_observers "$mixed_prefix" "$WORK/$mixed_prefix-response.marker" || return 1
    PHASE="$mixed_prefix-request"
    timeout --signal=TERM --kill-after=5s 200s \
        ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        "$WORK/bin/examples/http3-acceptance-fixture" client "$mixed_case" \
        "43.159.1.1:$mixed_port" 47.163.4.2:443 "$WORK/client-fixtures/http3-cert.der" \
        "$RUN_ID" "$WORK/client-fixtures/$mixed_case.json" \
        >"$WORK/$mixed_prefix-client.log" 2>"$WORK/$mixed_prefix-client.err" &
    HTTP3_CLIENT_PID=$!
    mixed_ready_attempt=0
    while [ "$mixed_ready_attempt" -lt 300 ]; do
        [ ! -s "$WORK/destination/$mixed_case-active.ready" ] || break
        kill -0 "$HTTP3_CLIENT_PID" 2>/dev/null || return 1
        sleep 0.1
        mixed_ready_attempt=$((mixed_ready_attempt + 1))
    done
    [ -s "$WORK/destination/$mixed_case-active.ready" ] || return 1
    kill -0 "$HTTP3_CLIENT_PID" || return 1
    wait_active_native_mpquic_paths "$mixed_prefix-request-active" || return 1
    if [ "$mixed_case" = mixed-single ]; then
        # Gate the same active application, not a replacement one-path QUIC connection.
        install -o root -g root -m 0600 /dev/null "$mixed_privacy_dir/a07-privacy-link-down.marker"
        ip -n "$R1" link set r1c down
    fi
    ip -n "$R1" -j link show dev r1c >"$WORK/$mixed_prefix-r1c-release.json"
    ip -n "$R1" -j link show dev r1x >"$WORK/$mixed_prefix-r1x-release.json"
    mixed_before_r1=$(tc_sent_bytes "$R1" r1c) || return 1
    mixed_before_r2=$(tc_sent_bytes "$R2" r2c) || return 1
    install -o root -g root -m 0600 /dev/null "$WORK/$mixed_prefix-response.marker"
    # Observers poll at 200ms; open the response gate only after the marker can be consumed.
    sleep 0.3
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 /dev/null "$WORK/destination/$mixed_case.release"
    PHASE="$mixed_prefix-response"
    mixed_client_status=0
    wait "$HTTP3_CLIENT_PID" || mixed_client_status=$?
    HTTP3_CLIENT_PID=
    if [ "$mixed_client_status" -ne 0 ]; then
        capture_failed_native_mpquic_paths "$mixed_prefix"
    fi
    mixed_after_r1=$(tc_sent_bytes "$R1" r1c) || return 1
    mixed_after_r2=$(tc_sent_bytes "$R2" r2c) || return 1
    stop_observers || return 1
    stop_privacy_observers || return 1
    [ "$mixed_client_status" -eq 0 ] || return 1
    mixed_requirement=both
    [ "$mixed_case" != mixed-single ] || mixed_requirement=relay2
    wait_native_mpquic_paths "$mixed_prefix-after" "$mixed_requirement" || return 1
    mixed_server_attempt=0
    while [ ! -s "$WORK/destination/server-$mixed_case.json" ] && [ "$mixed_server_attempt" -lt 100 ]; do
        sleep 0.1
        mixed_server_attempt=$((mixed_server_attempt + 1))
    done
    install -o root -g root -m 0600 "$WORK/client-fixtures/$mixed_case.json" \
        "$WORK/$mixed_prefix-client.json" || return 1
    install -o root -g root -m 0600 "$WORK/destination/server-$mixed_case.json" \
        "$WORK/$mixed_prefix-destination.json" || return 1
    jq -cn --argjson before_r1 "$mixed_before_r1" --argjson after_r1 "$mixed_after_r1" \
        --argjson before_r2 "$mixed_before_r2" --argjson after_r2 "$mixed_after_r2" \
        '{relay1:($after_r1-$before_r1),relay2:($after_r2-$before_r2)}' \
        >"$WORK/$mixed_prefix-response-qdisc-bytes.json" || return 1
    for mixed_capture_node in client relay1 relay2 exit; do
        install -o root -g root -m 0600 "$mixed_privacy_dir/$mixed_capture_node.json" \
            "$WORK/$mixed_prefix-privacy-$mixed_capture_node.json" || return 1
    done
    if [ "$mixed_case" = mixed-single ]; then
        ip -n "$R1" link set r1c up
        mixed_link_snapshot_local_relay bandwidth-restored
    fi
}

mixed_link_bandwidth_validate() {
    jq -S -cn \
        --slurpfile initial "$WORK/mixed-link-evidence.json" \
        --slurpfile sc "$WORK/mixed-link-single-client.json" --slurpfile sd "$WORK/mixed-link-single-destination.json" \
        --slurpfile ac "$WORK/mixed-link-aggregate-client.json" --slurpfile ad "$WORK/mixed-link-aggregate-destination.json" \
        --slurpfile sb "$WORK/mixed-link-single-before.json" --slurpfile sr "$WORK/mixed-link-single-request-active.json" \
        --slurpfile sa "$WORK/mixed-link-single-after.json" --slurpfile ab "$WORK/mixed-link-aggregate-before.json" \
        --slurpfile ar "$WORK/mixed-link-aggregate-request-active.json" --slurpfile aa "$WORK/mixed-link-aggregate-after.json" \
        --slurpfile spc "$WORK/mixed-link-single-client-capture.json" --slurpfile spe "$WORK/mixed-link-single-exit-capture.json" \
        --slurpfile apc "$WORK/mixed-link-aggregate-client-capture.json" --slurpfile ape "$WORK/mixed-link-aggregate-exit-capture.json" \
        --slurpfile sq "$WORK/mixed-link-single-response-qdisc-bytes.json" --slurpfile aq "$WORK/mixed-link-aggregate-response-qdisc-bytes.json" \
        --slurpfile slc "$WORK/mixed-link-single-r1c-release.json" --slurpfile slx "$WORK/mixed-link-single-r1x-release.json" \
        --slurpfile alc "$WORK/mixed-link-aggregate-r1c-release.json" --slurpfile alx "$WORK/mixed-link-aggregate-r1x-release.json" \
        --slurpfile shape1 "$WORK/mixed-link-shape-r1c.json" --slurpfile shape2 "$WORK/mixed-link-shape-r2c.json" \
        --slurpfile privacy "$WORK/mixed-link-bandwidth-privacy.json" \
        --arg r1 "$R1_PEER" --arg r2 "$R2_PEER" --arg exit "$EXIT_PEER" '
        def app($app;$dest;$case;$port):
          $app.case == $case and $dest.case == $case and
          $app.protocol == "HTTP/3" and $app.http_version == "HTTP/3" and $app.negotiated_alpn == "h3" and
          $app.application == {ip:"43.159.1.1",port:$port} and $app.destination == {ip:"47.163.4.2",port:443} and
          $app.request_bytes == 4194304 and $dest.request_bytes == 4194304 and
          $app.response_bytes == 33554432 and $dest.response_bytes == 33554432 and
          $app.request_sha256 == $dest.request_sha256 and $app.response_sha256 == $dest.response_sha256 and
          ($app.request_sha256 | test("^[0-9a-f]{64}$")) and ($app.response_sha256 | test("^[0-9a-f]{64}$")) and
          $dest.source.ip == "47.163.4.1" and $dest.release_observed and $dest.peer_completion_observed and
          $app.response_duration_ns > 0;
        def two($native): ($native.paths|length)==2 and
          ([$native.paths[].relay_peer_id]|sort)==([$r1,$r2]|sort) and
          ([$native.paths[].path_id]|unique|length)==2 and
          all($native.paths[]; .state==3 and .exit_peer_id==$exit);
        def identity: {route_context_id, paths:([.paths[] |
          {path_id,relay_peer_id,exit_peer_id}] | sort_by(.path_id))};
        def complete($capture): $capture.truncated==false and $capture.packet_socket_drops==0 and
          $capture.observed_frames>0 and $capture.marker_observed;
        def both_payload($capture): $capture.after_marker.relay1_wireguard_data_bytes>1048576 and
          $capture.after_marker.relay2_wireguard_data_bytes>1048576;
        ($sc[0].response_duration_ns / $ac[0].response_duration_ns) as $ratio |
        ($initial[0].success==true and two($initial[0].transfer.native_mpquic) and
          ($initial[0].transfer.native_mpquic|identity)==($sb[0]|identity) and
          app($sc[0];$sd[0];"mixed-single";52016) and app($ac[0];$ad[0];"mixed-aggregate";52017) and
          $sc[0].response_sha256!=$ac[0].response_sha256 and
          two($sb[0]) and two($sr[0]) and two($ab[0]) and two($ar[0]) and two($aa[0]) and
          $sb[0].route_context_id==$sr[0].route_context_id and $sb[0].route_context_id==$sa[0].route_context_id and
          $ab[0].route_context_id==$ar[0].route_context_id and $ab[0].route_context_id==$aa[0].route_context_id and
          $sb[0].route_context_id!=$ab[0].route_context_id and
          any($sa[0].paths[]; .relay_peer_id==$r2 and .exit_peer_id==$exit and .state==3) and
          ([$sb[0].paths[]|select(.relay_peer_id==$r2)|.path_id])==([$sa[0].paths[]|select(.relay_peer_id==$r2)|.path_id]) and
          all([$shape1[0],$shape2[0]][]; any(.[]; .kind=="tbf" and .root==true and .options.rate==1000000)) and
          ($slc[0]|length)==1 and ($slx[0]|length)==1 and ($alc[0]|length)==1 and ($alx[0]|length)==1 and
          $slc[0][0].ifname=="r1c" and ($slc[0][0].flags|index("UP"))==null and
          ($slx[0][0].flags|index("UP"))!=null and ($alc[0][0].flags|index("UP"))!=null and
          ($alx[0][0].flags|index("UP"))!=null and $slc[0][0].ifindex==$alc[0][0].ifindex and
          all([$spc[0],$spe[0],$apc[0],$ape[0]][]; complete(.)) and
          $spc[0].after_marker.relay1_received_wireguard_data_bytes==0 and
          $spc[0].after_marker.relay2_received_wireguard_data_bytes>1048576 and
          $spe[0].after_marker.relay2_wireguard_data_bytes>1048576 and both_payload($apc[0]) and both_payload($ape[0]) and
          $apc[0].after_marker.relay1_received_wireguard_data_bytes>1048576 and
          $apc[0].after_marker.relay2_received_wireguard_data_bytes>1048576 and
          $sq[0].relay1==0 and $sq[0].relay2>33554432 and $aq[0].relay1>1048576 and $aq[0].relay2>1048576 and
          ($privacy[0]|length)==8 and
          all(["mixed-single","mixed-aggregate"][]; . as $case |
            ([$privacy[0][]|select(.benchmark==$case)|.capture_role]|sort)==["client","exit","relay1","relay2"]) and
          all($privacy[0][]; .truncated==false and .packet_socket_drops==0 and .observed_frames>0 and
            .unexpected_outer_packets==0 and .direct_client_exit_packets==0) and
          all($privacy[0][]|select(.capture_role!="exit"); .internet_destination_outer_packets==0) and
          all($privacy[0][]|select(.capture_role=="exit"); .client_public_packets==0) and
          all($privacy[0][]|select(.benchmark=="mixed-aggregate"); .expected_link_down_notifications==0) and
          all($privacy[0][]|select(.expected_link_down_notifications>0);
            .benchmark=="mixed-single" and .capture_role=="relay1" and (.expected_link_down_interfaces|keys)==["r1c"]) and
          $ratio>1.25) as $success |
        {success:$success,minimum_ratio_exclusive:1.25,aggregate_to_wan_only_ratio:$ratio,
          single_wan_only:{application:$sc[0],destination:$sd[0],native_before:$sb[0],native_after:$sa[0],
            reused_a06_route_context_id:$initial[0].transfer.native_mpquic.route_context_id,
            application_response_mbps:($sc[0].response_bytes*8000/$sc[0].response_duration_ns),
            response_qdisc_bytes:$sq[0],client_capture:$spc[0],exit_capture:$spe[0],lan_link_at_release:$slc[0][0]},
          lan_plus_wan:{application:$ac[0],destination:$ad[0],native_before:$ab[0],native_after:$aa[0],
            application_response_mbps:($ac[0].response_bytes*8000/$ac[0].response_duration_ns),
            response_qdisc_bytes:$aq[0],client_capture:$apc[0],exit_capture:$ape[0],lan_link_at_release:$alc[0][0]},
          shape:{relay1_client_egress_mbps:8,relay2_client_egress_mbps:8,
            relay1_qdisc:$shape1[0],relay2_qdisc:$shape2[0]},privacy:$privacy[0],
          ordinary_quic_fallback_allowed:false,application_pacing:false,
          scope:"same 32MiB HTTP/3 response size on genuine native MPQUIC; WAN-only on the verified A06 route after deliberate LAN loss versus a fresh LAN+WAN route"}
    ' >"$WORK/mixed-link-bandwidth.json" || return 1
    jq -e '.success == true' "$WORK/mixed-link-bandwidth.json" >/dev/null
}

mixed_link_bandwidth_run() {
    PHASE=mixed-link-bandwidth-shaping
    for mixed_shape in "$R1:r1c" "$R2:r2c"; do
        mixed_ns=${mixed_shape%:*}; mixed_interface=${mixed_shape#*:}
        ip netns exec "$mixed_ns" tc qdisc replace dev "$mixed_interface" root tbf \
            rate 8mbit burst 128kb latency 250ms
        ip netns exec "$mixed_ns" tc -j -s qdisc show dev "$mixed_interface" \
            >"$WORK/mixed-link-shape-$mixed_interface.json"
        jq -e 'any(.[]; .kind=="tbf" and .root==true and .options.rate==1000000)' \
            "$WORK/mixed-link-shape-$mixed_interface.json" >/dev/null || return 1
    done
    mixed_link_bandwidth_case mixed-single 52016 || return 1
    mixed_link_bandwidth_case mixed-aggregate 52017 || return 1
    wait "$HTTP3_SERVER_PID" || return 1
    HTTP3_SERVER_PID=
    # Keep the case identity separate from the observer role, without rewriting its counters.
    jq -s '[to_entries[] | .value + {benchmark:(if .key<4 then "mixed-single" else "mixed-aggregate" end)}]' \
        "$WORK"/mixed-link-single-privacy-*.json "$WORK"/mixed-link-aggregate-privacy-*.json \
        >"$WORK/mixed-link-bandwidth-privacy.json"
    mixed_link_bandwidth_validate || return 1
    ip netns exec "$R1" tc qdisc del dev r1c root
    ip netns exec "$R2" tc qdisc del dev r2c root
    jq -c --slurpfile bandwidth "$WORK/mixed-link-bandwidth.json" \
        '. + {bandwidth_aggregation_claimed:$bandwidth[0].success,bandwidth_comparison:$bandwidth[0]}' \
        "$WORK/mixed-link-evidence.json" >"$WORK/mixed-link-combined-evidence.json"
    # The report reads the combined file only after both independent functional gates passed.
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
    [ ! -s "$WORK/mixed-link-combined-evidence.json" ] \
        || mixed_evidence=$(cat "$WORK/mixed-link-combined-evidence.json")
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
          scope:"real HTTP/3 over LAN+WAN native MPQUIC paths plus bounded 8+8Mbps response comparison; no radio or A01-A15 claim"}
    ' >"$WORK/mixed-link-smoke.json" || return 1
    for mixed_artifact in "$WORK"/mixed-link-*.json "$WORK"/mixed-link-*.txt \
        "$WORK"/mixed-link-*.out "$WORK"/mixed-link-*.err; do
        [ ! -f "$mixed_artifact" ] || [ -L "$mixed_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$mixed_artifact" \
                "$output_directory/$(basename -- "$mixed_artifact")"
    done
    jq -e '.success == true' "$WORK/mixed-link-smoke.json" >/dev/null
}
