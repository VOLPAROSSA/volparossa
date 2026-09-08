#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicitly approved disposable Debian KVM topology.
# shellcheck disable=SC2154,SC2034

dns_cache_extend_network() {
    link_nodes "$EXIT_NODE" xc0 10.241.96.1/30 "$EXIT2_NODE" xc1 10.241.96.2/30
    ip -n "$EXIT_NODE" route add 51.167.7.1/32 via 10.241.96.2 dev xc0 src 46.162.3.1
    ip -n "$EXIT2_NODE" route add 46.162.3.1/32 via 10.241.96.1 dev xc1 src 51.167.7.1
    for dc_side in exit exit2; do
        if [ "$dc_side" = exit ]; then
            dc_ns=$EXIT_NODE; dc_dev=xc0; dc_local=46.162.3.1; dc_remote=51.167.7.1
        else
            dc_ns=$EXIT2_NODE; dc_dev=xc1; dc_local=51.167.7.1; dc_remote=46.162.3.1
        fi
        ip netns exec "$dc_ns" nft -f - <<RULES
table inet vpa_dns_peer_control {
 chain input { type filter hook input priority -20; policy accept;
  iifname "$dc_dev" ip saddr $dc_remote ip daddr $dc_local udp sport 41000 accept
  iifname "$dc_dev" ip saddr $dc_remote ip daddr $dc_local udp dport 41000 accept
  iifname "$dc_dev" drop
 }
 chain output { type filter hook output priority -20; policy accept;
  oifname "$dc_dev" ip saddr $dc_local ip daddr $dc_remote udp sport 41000 accept
  oifname "$dc_dev" ip saddr $dc_local ip daddr $dc_remote udp dport 41000 accept
  oifname "$dc_dev" drop
 }
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "$dc_dev" drop
  oifname "$dc_dev" drop
 }
}
RULES
    done
}

dns_cache_configure_node() {
    dc_enabled=false; dc_upstream=null; dc_metrics=false
    case $node in
        exit)
            dc_enabled=true; dc_upstream='47.163.4.2:53'; dc_metrics=true
            bootstrap_two="/ip4/51.167.7.1/udp/41000/quic-v1/p2p/$EXIT2_PEER"
            ;;
        exit2)
            dc_enabled=true; dc_metrics=true; exit_capacity=32
            bootstrap_two="/ip4/46.162.3.1/udp/41000/quic-v1/p2p/$EXIT_PEER"
            ;;
    esac
}

dns_cache_cli() {
    timeout --signal=TERM --kill-after=2s 60s "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

dns_cache_select() {
    dc_label=$1; dc_wanted=$2
    dc_draw=0; dc_attempt=0; dc_deadline=$(($(date +%s) + 180))
    while [ "$dc_draw" -lt 32 ] && [ "$dc_attempt" -lt 120 ] && [ "$(date +%s)" -lt "$dc_deadline" ]; do
        dc_attempt=$((dc_attempt + 1))
        dc_attempt_prefix=$WORK/$dc_label-draw-$dc_attempt
        if dns_cache_cli connect --transport single-path-udp \
            >"$dc_attempt_prefix.out" 2>"$dc_attempt_prefix.err"; then
            dc_poll=0; dc_status=1
            while [ "$dc_poll" -lt 50 ]; do
                dns_cache_cli paths >"$dc_attempt_prefix-paths.txt" || return 1
                dc_status=0
                python3 -B "$source_directory/tests/integration/dns-cache-smoke.py" select \
                    "$dc_attempt_prefix-paths.txt" "$WORK/a01-expected-peers.json" "$dc_wanted" \
                    "$dc_attempt_prefix-selection.json" || dc_status=$?
                [ "$dc_status" -eq 1 ] || break
                dc_poll=$((dc_poll + 1)); sleep 0.1
            done
            case $dc_status in
                0)
                    install -m 0600 "$dc_attempt_prefix-selection.json" "$WORK/$dc_label-selection.json"
                    install -m 0600 "$dc_attempt_prefix-paths.txt" "$WORK/$dc_label-paths.txt"
                    return 0 ;;
                2)
                    # A valid different Exit is a normal unused draw, not a failed DNS retry.
                    benchmark_disconnect_route "$dc_label-unused-$dc_attempt" || return 1
                    dc_draw=$((dc_draw + 1)) ;;
                *) return 1 ;;
            esac
        else
            a01_transient_connect_unavailable "$dc_attempt_prefix.err" || return 1
        fi
        sleep 0.25
    done
    return 1
}

dns_cache_metrics() (
    dc_metrics_output=$1
    for dc_metrics_node in exit exit2; do
        if [ "$dc_metrics_node" = exit ]; then dc_metrics_ns=$EXIT_NODE; else dc_metrics_ns=$EXIT2_NODE; fi
        if [ "$dc_metrics_node" = exit ] && [ "$DNS_CACHE_PEER_STOPPED" = yes ]; then
            printf 'null\n' >"$dc_metrics_output-$dc_metrics_node.part"
        else
            ip netns exec "$dc_metrics_ns" env \
                VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS="$DNS_CACHE_PARENT_NETNS" \
                python3 -B "$source_directory/tests/integration/dns-cache-smoke.py" metrics \
                >"$dc_metrics_output-$dc_metrics_node.part" || return 1
        fi
    done
    jq -cn --slurpfile first "$dc_metrics_output-exit.part" --slurpfile second "$dc_metrics_output-exit2.part" \
        '{exit:$first[0],exit2:$second[0]}' >"$dc_metrics_output"
)

dns_cache_start_capture() {
    dc_phase=$1; dc_prefix=dns-cache-$dc_phase
    dc_relay=$(jq -er '.relay_node' "$WORK/$dc_prefix-selection.json") || return 1
    dc_exit=$(jq -er '.exit_node' "$WORK/$dc_prefix-selection.json") || return 1
    case $dc_relay in
        relay0) dc_relay_ns=$R0; dc_relay_ip=42.158.0.1 ;;
        relay1) dc_relay_ns=$R1; dc_relay_ip=44.160.1.1 ;;
        relay2) dc_relay_ns=$R2; dc_relay_ip=45.161.2.1 ;;
        *) return 1 ;;
    esac
    jq -cn --arg phase "$dc_phase" --arg exit "$dc_exit" --arg relay "$dc_relay" --arg ip "$dc_relay_ip" \
        '{phase:$phase,exit_node:$exit,relays:{($relay):$ip}}' >"$WORK/$dc_prefix-layout.json"
    for dc_role in client "$dc_relay" exit exit2 destination; do
        case $dc_role in
            client) dc_capture_ns=$CLIENT ;;
            relay*) dc_capture_ns=$dc_relay_ns ;;
            exit) dc_capture_ns=$EXIT_NODE ;;
            exit2) dc_capture_ns=$EXIT2_NODE ;;
            destination) dc_capture_ns=$DEST ;;
        esac
        # Every actual physical fixture interface, including both Exit links and the extra
        # control link. Never observe decrypted route-worker veth/TUN/interfaces or loopback.
        dc_interfaces=$(ip -n "$dc_capture_ns" -j link show | jq -er '
          [.[] | .ifname | select(test("^(underlay|[a-z][a-z0-9]{1,5})$"))
           | select(. != "lo" and (startswith("vp") | not))] | join(" ")') || return 1
        [ -n "$dc_interfaces" ] || return 1
        # shellcheck disable=SC2086 # The exact filtered interface list is deliberately split.
        ip netns exec "$dc_capture_ns" python3 -B "$source_directory/tests/integration/dns-cache-capture.py" capture \
            "$WORK/$dc_prefix-layout.json" "$WORK/$dc_prefix-capture-$dc_role.json" \
            "$WORK/$dc_prefix-capture-$dc_role.ready" "$dc_role" $dc_interfaces \
            >"$WORK/$dc_prefix-capture-$dc_role.log" 2>&1 &
        dc_capture_pid=$!
        case $dc_role in
            client) PRIVACY_CLIENT_PID=$dc_capture_pid ;;
            relay*) PRIVACY_RELAY0_PID=$dc_capture_pid ;;
            exit) PRIVACY_EXIT_PID=$dc_capture_pid ;;
            exit2) PRIVACY_RELAY1_PID=$dc_capture_pid ;;
            destination) PRIVACY_RELAY2_PID=$dc_capture_pid ;;
        esac
        wait_observer "$dc_capture_pid" "$WORK/$dc_prefix-capture-$dc_role.ready" || return 1
    done
}

dns_cache_stop_server() {
    [ -n "$DNS_CACHE_SERVER_PID" ] || return 0
    kill -TERM "$DNS_CACHE_SERVER_PID" 2>/dev/null || true
    dc_stop_attempt=0
    while kill -0 "$DNS_CACHE_SERVER_PID" 2>/dev/null && [ "$dc_stop_attempt" -lt 50 ]; do
        dc_stop_attempt=$((dc_stop_attempt + 1)); sleep 0.1
    done
    dc_server_status=0
    if kill -0 "$DNS_CACHE_SERVER_PID" 2>/dev/null; then
        kill -KILL "$DNS_CACHE_SERVER_PID" 2>/dev/null || true
        dc_server_status=1
    fi
    wait "$DNS_CACHE_SERVER_PID" || dc_server_status=1
    DNS_CACHE_SERVER_PID=
    return "$dc_server_status"
}

dns_cache_phase() {
    dc_phase=$1; dc_wanted=$2; dc_family=$3; dc_mode=$4
    dc_prefix=dns-cache-$dc_phase
    PHASE=$dc_prefix
    [ "$dc_phase" = warm-a-a ] || dns_cache_select "$dc_prefix" "$dc_wanted" \
        || fail DNS_CACHE_NORMAL_ROUTE_UNAVAILABLE
    # A fresh bounded listener per phase uses the SAME original signed recording and
    # decreases original TTLs. This does not recollect/refresh evidence or retry queries.
    ip netns exec "$DEST" env VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS="$DNS_CACHE_PARENT_NETNS" \
        python3 -B "$source_directory/tests/integration/dns-cache-fixture.py" serve \
        "$WORK/dns-cache-fixture" 47.163.4.2:53 "$WORK/$dc_prefix-upstream.json" \
        "$WORK/$dc_prefix-upstream.ready" --max-seconds 120 \
        >"$WORK/$dc_prefix-upstream.log" 2>&1 &
    DNS_CACHE_SERVER_PID=$!
    wait_observer "$DNS_CACHE_SERVER_PID" "$WORK/$dc_prefix-upstream.ready" || fail DNS_CACHE_UPSTREAM_UNAVAILABLE
    dns_cache_start_capture "$dc_phase" || fail DNS_CACHE_CAPTURE_UNAVAILABLE
    dns_cache_metrics "$WORK/$dc_prefix-metrics-before.json" || fail DNS_CACHE_METRICS_UNAVAILABLE
    dc_query_name=iana.org
    [ "$dc_phase" != unsigned-b ] || dc_query_name=destination.volparossa.test
    ip netns exec "$CLIENT" env VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS="$DNS_CACHE_PARENT_NETNS" \
        setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 -B "$WORK/bin/dns-cache-smoke.py" query "$dc_query_name" "$dc_family" \
        >"$WORK/$dc_prefix-application.json" 2>"$WORK/$dc_prefix-application.err" \
        || fail DNS_CACHE_PROTECTED_APPLICATION_FAILED
    # Normal DNS ingress retires its exact route after each response; no reused context
    # can let an old Exit answer the next explicitly inspected route.
    wait_disconnected || fail DNS_CACHE_ROUTE_NOT_RETIRED
    dc_metric_attempt=0; dc_metric_ready=no
    while [ "$dc_metric_attempt" -lt 100 ]; do
        dns_cache_metrics "$WORK/$dc_prefix-metrics-after.json" || fail DNS_CACHE_METRICS_UNAVAILABLE
        if jq -en --arg node "$dc_wanted" --arg metric "volparossa_dns_${dc_mode}_total" \
            --slurpfile before "$WORK/$dc_prefix-metrics-before.json" \
            --slurpfile after "$WORK/$dc_prefix-metrics-after.json" \
            '$after[0][$node][$metric] - $before[0][$node][$metric] == 1' >/dev/null; then
            dc_metric_ready=yes; break
        fi
        dc_metric_attempt=$((dc_metric_attempt + 1)); sleep 0.1
    done
    [ "$dc_metric_ready" = yes ] || fail DNS_CACHE_EXPECTED_SOURCE_NOT_OBSERVED
    kill -0 "$DNS_CACHE_SERVER_PID" 2>/dev/null || fail DNS_CACHE_UPSTREAM_ENDED_EARLY
    stop_privacy_observers || fail DNS_CACHE_CAPTURE_INCOMPLETE
    dns_cache_stop_server || fail DNS_CACHE_UPSTREAM_CLEANUP_FAILED
}

dns_cache_run() {
    DNS_CACHE_PARENT_NETNS=$(readlink /proc/self/ns/net)
    DNS_CACHE_PEER_STOPPED=no
    PHASE=dns-cache-prepare
    dns_cache_select dns-cache-warm-a-a exit || fail DNS_CACHE_NORMAL_ROUTE_UNAVAILABLE
    # Explicit public wire DATA download only, after build/bootstrap/first route setup.
    # No code/binary download, custom anchor, rewritten public answer or /etc/hosts shortcut.
    if grep -Eq '(^|[[:space:]])iana\.org([[:space:]]|$)' /etc/hosts; then fail DNS_CACHE_PUBLIC_HOSTS_SHORTCUT; fi
    python3 -B "$source_directory/tests/integration/dns-cache-fixture.py" collect "$WORK/dns-cache-fixture" \
        >"$WORK/dns-cache-collect.log" 2>&1 || fail DNS_CACHE_FRESH_PUBLIC_CHAIN_UNAVAILABLE
    sh "$WORK/dns-preflight-tools/tests/integration/dns-cache-proof.sh" --execute --yes \
        --fixture "$WORK/dns-cache-fixture" --binary "$binary_directory/examples/dns-cache-proof" \
        --output "$WORK/dns-cache-preflight" >"$WORK/dns-cache-preflight.log" 2>&1 \
        || fail DNS_CACHE_BUILTIN_ANCHOR_VALIDATION_FAILED
    install -m 0600 "$WORK/dns-cache-preflight/proof.json" "$WORK/dns-cache-core-proof.json"
    install -m 0600 "$WORK/dns-cache-fixture/recording.json" "$WORK/dns-cache-recording.json"
    jq -ce '[.core[] | {key:.family,value:(.addresses | sort)}] | from_entries' \
        "$WORK/dns-cache-core-proof.json" >"$WORK/dns-cache-expected.json"
    jq -cn '{exit_upstream:"47.163.4.2:53",exit2_upstream:null,positive_name_in_hosts:false,
      other_nodes_cache_disabled:true,production_root_anchors_unchanged:true}' >"$WORK/dns-cache-config.json"
    dns_cache_phase warm-a-a exit A upstream_validated
    dns_cache_phase warm-a-aaaa exit AAAA upstream_validated
    # Both caches begin cold and must not advertise an empty service. Wait for the actual
    # successful availability publication after A's genuine validation, without refreshing TTLs.
    dc_available=no; dc_availability_deadline=$(($(date +%s) + 30))
    while [ "$(date +%s)" -lt "$dc_availability_deadline" ]; do
        if timeout --signal=TERM --kill-after=1s 2s "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-exit/control/agent.sock" logs --limit 400 \
            >"$WORK/dns-cache-provider-availability.txt" \
            && grep -F 'event=DNS_CACHE_PROVIDER_AVAILABLE' "$WORK/dns-cache-provider-availability.txt" >/dev/null; then
            dc_available=yes; break
        fi
        sleep 0.1
    done
    [ "$dc_available" = yes ] || fail DNS_CACHE_PROVIDER_PUBLICATION_UNAVAILABLE
    dns_cache_phase peer-b-a exit2 A peer_validated
    dns_cache_phase peer-b-aaaa exit2 AAAA peer_validated
    dns_cache_phase unsigned-b exit2 A trusted_fallback
    PHASE=dns-cache-peer-offline
    systemctl stop volparossa-alpha-agent@exit.service || fail DNS_CACHE_PEER_STOP_FAILED
    dc_peer_active=$(systemctl show --property=ActiveState --value volparossa-alpha-agent@exit.service)
    dc_peer_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@exit.service)
    if [ "$dc_peer_active" != inactive ] || [ "$dc_peer_pid" != 0 ]; then fail DNS_CACHE_PEER_STILL_ACTIVE; fi
    DNS_CACHE_PEER_STOPPED=yes
    jq -cn '{node:"exit",agent_active:false,main_pid:0}' >"$WORK/dns-cache-peer-stopped.json"
    dns_cache_phase local-b-a exit2 A local_validated
    dns_cache_phase local-b-aaaa exit2 AAAA local_validated
    python3 -B "$source_directory/tests/integration/dns-cache-smoke.py" evidence \
        "$WORK" "$WORK/dns-cache-evidence.json" || fail DNS_CACHE_EVIDENCE_INVALID
    PHASE=dns-cache-complete
    OBSERVED_BLOCKER=NONE
}

dns_cache_finalize_report() {
    dc_final_status=$1
    # Keep the actual validator/namespace error even when preflight fails before
    # its success-only receipts are copied. These fixed files contain public DNS
    # wire data or bounded fixture diagnostics, never agent identities or traffic.
    for dc_diagnostic in namespace.stdout namespace.stderr core.jsonl core.stderr \
        replay.stdout replay.stderr replay.json replay-ready.json proof.json; do
        dc_source=$WORK/dns-cache-preflight/$dc_diagnostic
        if [ -f "$dc_source" ] && [ ! -L "$dc_source" ]; then
            [ "$(stat -c '%s' "$dc_source")" -le 131072 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$dc_source" \
                "$output_directory/dns-cache-preflight-$dc_diagnostic" || return 1
        fi
    done
    dc_source=$WORK/dns-cache-fixture/recording.json
    if [ -f "$dc_source" ] && [ ! -L "$dc_source" ]; then
        [ "$(stat -c '%s' "$dc_source")" -le 131072 ] || return 1
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$dc_source" \
            "$output_directory/dns-cache-recording.json" || return 1
    fi
    for dc_artifact in "$WORK"/dns-cache-*.json "$WORK"/dns-cache-*.txt \
        "$WORK"/dns-cache-*.out "$WORK"/dns-cache-*.err "$WORK"/dns-cache-*.log; do
        [ ! -f "$dc_artifact" ] || [ -L "$dc_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$dc_artifact" \
                "$output_directory/$(basename -- "$dc_artifact")"
    done
    optional_json_evidence "$WORK/dns-cache-evidence.json" >"$WORK/dns-cache-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/dns-cache-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$dc_final_status" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile evidence "$WORK/dns-cache-report-evidence.part" --slurpfile host "$WORK/dns-cache-report-host.part" '
      {schema_version:1,report_kind:"volparossa-dns-cache",source_revision:$revision,
       phase:$phase,runner_exit_status:$status,observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged),
       dns:$evidence[0],cleanup:{complete:$complete,remaining_owned_objects:$remaining},
       host_state:($host[0] | del(.acceptance_id)),
       scope:"normal protected A/AAAA requests, genuine root-validated upstream/peer/local cache and unsigned trusted fallback",
       full_c05_claimed:false,full_alpha_acceptance_claimed:false}' >"$WORK/dns-cache-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/dns-cache-smoke.json" "$output_directory/dns-cache-smoke.json"
    python3 -B "$source_directory/tests/integration/dns-cache-smoke.py" report "$WORK/dns-cache-smoke.json" "$expected_commit"
}
