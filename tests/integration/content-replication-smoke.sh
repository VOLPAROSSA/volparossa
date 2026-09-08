#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only inside the guarded disposable KVM guest; no production network defaults change.
# shellcheck disable=SC2154,SC2034

content_replication_configure_node() {
    case $node in
        client|relay4)
            bootstrap_one="/ip4/42.158.0.1/udp/41000/quic-v1/p2p/$R0_PEER"
            bootstrap_two="/ip4/45.161.2.1/udp/41000/quic-v1/p2p/$R2_PEER"
            bootstrap_three="/ip4/44.160.1.1/udp/41000/quic-v1/p2p/$R1_PEER"
            [ "$node" != relay4 ] || client_role=true
            ;;
    esac
}

content_replication_extend_network() {
    # Three candidates provide a distinct control relay plus two actual data relays.
    # The new client legs carry real WG/control packets; the supplier links permit only
    # generic UDP41000 discovery. All links and rules die with their registered namespaces.
    for cr_index in 0 1 2; do
        case $cr_index in
            0) cr_namespace=$R0; cr_public=42.158.0.1; cr_segment=90 ;;
            1) cr_namespace=$R1; cr_public=44.160.1.1; cr_segment=94 ;;
            2) cr_namespace=$R2; cr_public=45.161.2.1; cr_segment=92 ;;
        esac
        link_nodes "$R4" "ar$cr_index" "10.241.$cr_segment.1/30" \
            "$cr_namespace" "r${cr_index}a" "10.241.$cr_segment.2/30"
        ip -n "$R4" route add "$cr_public/32" via "10.241.$cr_segment.2" \
            dev "ar$cr_index" src 49.165.5.1
        ip -n "$cr_namespace" route add 49.165.5.1/32 via "10.241.$cr_segment.1" \
            dev "r${cr_index}a" src "$cr_public"
        cr_segment=$((cr_segment + 1))
        link_nodes "$cr_namespace" "rp$cr_index" "10.241.$cr_segment.1/30" \
            "$R5" "pr$cr_index" "10.241.$cr_segment.2/30"
        ip -n "$cr_namespace" route add 50.166.6.1/32 via "10.241.$cr_segment.2" \
            dev "rp$cr_index" src "$cr_public"
        ip -n "$R5" route add "$cr_public/32" via "10.241.$cr_segment.1" \
            dev "pr$cr_index" src 50.166.6.1
        for cr_side in broker provider; do
            if [ "$cr_side" = broker ]; then
                cr_ns=$cr_namespace; cr_dev=rp$cr_index; cr_local=$cr_public; cr_remote=50.166.6.1
            else
                cr_ns=$R5; cr_dev=pr$cr_index; cr_local=50.166.6.1; cr_remote=$cr_public
            fi
            ip netns exec "$cr_ns" nft -f - <<RULES
table inet vpa_replication_control_$cr_index {
 chain input { type filter hook input priority -20; policy accept;
  iifname "$cr_dev" ip saddr $cr_remote ip daddr $cr_local udp sport 41000 accept
  iifname "$cr_dev" ip saddr $cr_remote ip daddr $cr_local udp dport 41000 accept
  iifname "$cr_dev" drop
 }
 chain output { type filter hook output priority -20; policy accept;
  oifname "$cr_dev" ip saddr $cr_local ip daddr $cr_remote udp sport 41000 accept
  oifname "$cr_dev" ip saddr $cr_local ip daddr $cr_remote udp dport 41000 accept
  oifname "$cr_dev" drop
 }
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "$cr_dev" drop
  oifname "$cr_dev" drop
 }
}
RULES
    done
    done
    # Isolate this fixture's three-candidate graph before any agent starts. The primary Client
    # cannot use the later replica as its control relay or contact either supplier directly.
    ip netns exec "$CLIENT" nft -f - <<'RULES'
table inet vpa_replication_client {
 chain input { type filter hook input priority -20; policy accept;
  iifname { "cr3", "cr4", "cr5" } drop
 }
 chain output { type filter hook output priority -20; policy accept;
  oifname { "cr3", "cr4", "cr5" } drop
 }
}
RULES
    # R4 is also a content endpoint. Only Exit-originated TCP18080 may use its old direct
    # physical Exit link; no client tunnel, arbitrary transport, or forwarding is permitted.
    ip netns exec "$R4" nft -f - <<'RULES'
table inet vpa_replication_receiver {
 chain input { type filter hook input priority -20; policy accept;
  iifname "r4x" ip saddr 46.162.3.1 ip daddr 49.165.5.1 tcp dport 18080 accept
  iifname "r4x" drop
 }
 chain output { type filter hook output priority -20; policy accept;
  oifname "r4x" ip saddr 49.165.5.1 ip daddr 46.162.3.1 tcp sport 18080 accept
  oifname "r4x" drop
 }
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "r4x" drop
  oifname "r4x" drop
 }
}
RULES
}

content_replication_cli() {
    cr_cli_node=$1
    shift
    timeout --signal=TERM --kill-after=1s "${CONTENT_REPLICATION_COMMAND_TIMEOUT:-180s}" "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$cr_cli_node/control/agent.sock" "$@"
}

content_replication_select() (
    BENCHMARK_NODE=$1
    benchmark_select_route "$2" mptcp || exit 1
    jq -e '.transport == "mptcp" and (.benchmark_slots | length) == 2 and
        ([.benchmark_slots[].relay_node] | unique | length) == 2 and
        all(.benchmark_slots[].relay_node; . == "relay0" or . == "relay1" or . == "relay2")' \
        "$WORK/$2-selection.json" >/dev/null
)

content_replication_snapshot() (
    BENCHMARK_NODE=$1
    benchmark_capture_paths "$2" mptcp
)

content_replication_disconnect() (
    BENCHMARK_NODE=$1
    benchmark_disconnect_route "$2"
)

content_replication_cleanup() {
    cr_owner_remaining=0
    for cr_owner_pid in "${CONTENT_OWNER_SOURCE_PID:-}" "${CONTENT_OWNER_SINK_PID:-}"; do
        [ -n "$cr_owner_pid" ] || continue
        kill -TERM "$cr_owner_pid" 2>/dev/null || true
    done
    for cr_owner_pid in "${CONTENT_OWNER_SOURCE_PID:-}" "${CONTENT_OWNER_SINK_PID:-}"; do
        [ -n "$cr_owner_pid" ] || continue
        wait "$cr_owner_pid" 2>/dev/null || true
        if kill -0 "$cr_owner_pid" 2>/dev/null; then cr_owner_remaining=$((cr_owner_remaining + 1)); fi
    done
    CONTENT_OWNER_SOURCE_PID=
    CONTENT_OWNER_SINK_PID=
    jq -cn --argjson remaining "$cr_owner_remaining" \
        '{complete:($remaining == 0),remaining_processes:$remaining}' \
        >"$WORK/content-replication-owner-cleanup.json"
    [ "$cr_owner_remaining" -eq 0 ]
}

content_replication_start_owner_probe() {
    # Independent capless traffic uses an existing disposable local link, never Exit/provider
    # access. AGENT_UID is the fixture's trusted local owner class, not a new product bypass.
    printf '%s\n' 'C04 fixture: R4 ar0 10.241.90.1:19004 -> R0 r0a 10.241.90.2:19004 UDP, 3s bounded owner load; no host changes.'
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$WORK/content-replication-owner"
    for cr_owner_script in content-replication-smoke.py content-replication-capture.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$cr_owner_script" \
            "$WORK/bin/$cr_owner_script"
    done
    jq -cn --argjson uid "$AGENT_UID" --argjson gid "$AGENT_GID" \
        --argjson receiver "$(stat -Lc '%i' "/run/netns/$R4")" \
        --argjson sink "$(stat -Lc '%i' "/run/netns/$R0")" \
        --argjson parent "$(stat -Lc '%i' /proc/self/ns/net)" \
        '{uid:$uid,gid:$gid,relay4:$receiver,relay0:$sink,parent:$parent}' \
        >"$WORK/content-replication-owner-isolation.json" || return 1
    for cr_owner_mode in owner-sink owner-source; do
        if [ "$cr_owner_mode" = owner-sink ]; then cr_owner_ns=$R0; else cr_owner_ns=$R4; fi
        timeout --signal=TERM --kill-after=1s 50s ip netns exec "$cr_owner_ns" \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- python3 -B "$WORK/bin/content-replication-smoke.py" "$cr_owner_mode" \
            "$WORK" "$cr_replica/replicas" "$RUN_ID" \
            >"$WORK/content-replication-$cr_owner_mode.json" \
            2>"$WORK/content-replication-$cr_owner_mode.err" &
        cr_owner_pid=$!
        if [ "$cr_owner_mode" = owner-sink ]; then CONTENT_OWNER_SINK_PID=$cr_owner_pid
        else CONTENT_OWNER_SOURCE_PID=$cr_owner_pid; fi
        wait_observer "$cr_owner_pid" "$WORK/content-replication-owner/$cr_owner_mode.ready" || return 1
    done
}

content_replication_finish_owner_probe() {
    wait "$CONTENT_OWNER_SOURCE_PID" || return 1
    CONTENT_OWNER_SOURCE_PID=
    kill -TERM "$CONTENT_OWNER_SINK_PID" || return 1
    wait "$CONTENT_OWNER_SINK_PID" || return 1
    CONTENT_OWNER_SINK_PID=
    content_replication_cleanup
}

# Observe only the already-owned R4 parent namespace. Unlike the generic worker diagnostic,
# this includes ordinary provider TCP sockets and compares them across route/service teardown.
# No payload, key, configuration file, packet trace, or namespace mutation is collected.
content_replication_provider_network() (
    cr_network_stage=$1
    case $cr_network_stage in before-disconnect|after-reopen|final-fetch-failed) ;; *) return 1 ;; esac
    cr_network_output=$WORK/content-replication-provider-network.txt
    cr_network_part=$WORK/content-replication-provider-network-$cr_network_stage.part
    cr_network_status=0
    {
        printf 'snapshot=%s node=relay4 timestamp=%s\n' "$cr_network_stage" "$(date -u +%FT%T.%NZ)"
        timeout --signal=TERM --kill-after=1s 2s systemctl show \
            volparossa-alpha-agent@relay4.service \
            --property=MainPID --property=ActiveState --property=SubState \
            || printf 'agent_unit_observation_failed=true\n'
    } >>"$cr_network_output"
    # Limit each of the three observations independently; failure/truncation is recorded,
    # never treated as proof of an empty ruleset or absent listener. Child limits affect only
    # this diagnostic, and its timeout cannot terminate a product service or existing capture.
    (
        ulimit -f 256
        timeout --signal=TERM --kill-after=1s 5s ip netns exec "$R4" sh -c '
            observe() {
                "$@"
                printf "observation_command_status=%s\n" "$?"
            }
            printf "section=namespace\n"
            observe stat -Lc "netns=%d:%i" /proc/self/ns/net
            printf "section=tcp-listeners\n"
            observe ss -H -n -l -t -e -p "sport = :18080"
            printf "section=tcp-connections\n"
            observe ss -H -n -t -a -i -e -m -p "( sport = :18080 or dport = :18080 )"
            printf "section=links\n"
            observe ip -details -statistics link show
            printf "section=addresses\n"
            observe ip -4 address show
            observe ip -6 address show
            printf "section=rules-and-routes\n"
            observe ip -4 rule show
            observe ip -6 rule show
            observe ip -4 route show table all
            observe ip -6 route show table all
            printf "section=provider-reply-route\n"
            observe ip -4 route get 46.162.3.1 from 49.165.5.1 uid "$1"
            printf "section=nftables\n"
            observe nft list ruleset
            printf "section=reverse-path-settings\n"
            for setting in /proc/sys/net/ipv4/conf/*/rp_filter \
                /proc/sys/net/ipv4/conf/*/src_valid_mark; do
                printf "%s=" "$setting"
                observe cat "$setting"
            done
            printf "section=kernel-counters\n"
            observe cat /proc/net/netstat /proc/net/snmp
            printf "snapshot_body_complete=true\n"
        ' sh "$AGENT_UID"
    ) >"$cr_network_part" 2>&1 || cr_network_status=$?
    head -c 131072 "$cr_network_part" >>"$cr_network_output"
    cr_network_bytes=$(wc -c <"$cr_network_part")
    cr_network_truncated=false
    [ "$cr_network_bytes" -lt 131072 ] || cr_network_truncated=true
    printf '\nsnapshot_end=%s command_status=%s observed_bytes=%s byte_limit=131072 truncated=%s\n' \
        "$cr_network_stage" "$cr_network_status" "$cr_network_bytes" "$cr_network_truncated" \
        >>"$cr_network_output"
)

content_replication_isolation() {
    cr_iso_node=$1; cr_iso_manifest=$2
    cr_iso_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$cr_iso_node.service")
    case $cr_iso_pid in ''|0|*[!0-9]*) return 1 ;; esac
    nsenter --target "$cr_iso_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$cr_iso_manifest" || return 1
    for cr_iso_private in "$WORK/state-relay5" "$WORK/content-replication-seed"; do
        if nsenter --target "$cr_iso_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$cr_iso_private"; then return 1; fi
    done
    if [ "$cr_iso_node" = client ]; then
        if nsenter --target "$cr_iso_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-relay4"; then return 1; fi
    fi
}

content_replication_capture() {
    cr_phase=$1
    if [ "$cr_phase" = uptake ]; then
        cr_client=relay4; cr_client_ip=49.165.5.1; cr_client_ns=$R4
        cr_provider=relay5; cr_provider_ip=50.166.6.1; cr_provider_ns=$R5
        cr_selection=$WORK/content-replication-warm-selection.json
    else
        [ "$cr_phase" = reserve-fetch ] || return 1
        cr_client=client; cr_client_ip=43.159.1.1; cr_client_ns=$CLIENT
        cr_provider=relay4; cr_provider_ip=49.165.5.1; cr_provider_ns=$R4
        cr_selection=$WORK/content-replication-final-selection.json
    fi
    cr_selected_relays=$(jq -ce '[.benchmark_slots[].relay_node] | sort as $selected |
      {relay0:"42.158.0.1",relay1:"44.160.1.1",relay2:"45.161.2.1"} |
      with_entries(select(.key as $node | $selected | index($node)))' "$cr_selection") || return 1
    cr_relay_a=$(printf '%s\n' "$cr_selected_relays" | jq -er 'keys[0]') || return 1
    cr_relay_b=$(printf '%s\n' "$cr_selected_relays" | jq -er 'keys[1]') || return 1
    jq -cn --arg phase "$cr_phase" --arg client "$cr_client" --arg cip "$cr_client_ip" \
        --arg provider "$cr_provider" --arg pip "$cr_provider_ip" --argjson relays "$cr_selected_relays" '
      {phase:$phase,client:{node:$client,ip:$cip},
       relays:$relays,
       exit:{node:"exit",ip:"46.162.3.1"},provider:{node:$provider,ip:$pip}}' \
        >"$WORK/content-replication-$cr_phase-layout.json"
    for cr_role in receiver relay-a relay-b exit provider; do
        case $cr_role in
            receiver) cr_capture_node=$cr_client; cr_capture_ns=$cr_client_ns ;;
            relay-a) cr_capture_node=$cr_relay_a ;;
            relay-b) cr_capture_node=$cr_relay_b ;;
            exit) cr_capture_node='exit'; cr_capture_ns=$EXIT_NODE ;;
            provider) cr_capture_node=$cr_provider; cr_capture_ns=$cr_provider_ns ;;
        esac
        case $cr_capture_node in
            relay0) cr_capture_ns=$R0 ;;
            relay1) cr_capture_ns=$R1 ;;
            relay2) cr_capture_ns=$R2 ;;
        esac
        # Only fixture physical interfaces, never decrypted worker/TUN/veth interfaces.
        cr_interfaces=$(ip -n "$cr_capture_ns" -j link show | jq -er '
            [.[] | .ifname | select(test("^(underlay|[a-z][a-z0-9]{1,5})$"))
             | select(. != "lo" and (startswith("vp") | not))] | join(" ")') || return 1
        [ -n "$cr_interfaces" ] || return 1
        # shellcheck disable=SC2086 # Deliberately split strictly filtered interface names.
        ip netns exec "$cr_capture_ns" python3 -B \
            "$source_directory/tests/integration/content-replication-capture.py" capture \
            "$WORK/content-replication-$cr_phase-layout.json" \
            "$WORK/content-replication-$cr_phase-$cr_role.json" \
            "$WORK/content-replication-$cr_phase-$cr_role.ready" "$cr_capture_node" \
            $cr_interfaces >"$WORK/content-replication-$cr_phase-$cr_role.log" 2>&1 &
        cr_capture_pid=$!
        case $cr_role in
            receiver) PRIVACY_CLIENT_PID=$cr_capture_pid ;;
            relay-a) PRIVACY_RELAY0_PID=$cr_capture_pid ;;
            relay-b) PRIVACY_RELAY2_PID=$cr_capture_pid ;;
            exit) PRIVACY_EXIT_PID=$cr_capture_pid ;;
            provider) PRIVACY_RELAY1_PID=$cr_capture_pid ;;
        esac
        wait_observer "$cr_capture_pid" "$WORK/content-replication-$cr_phase-$cr_role.ready" || return 1
    done
}

content_replication_run() {
    PHASE=content-replication-seed
    cr_seed=$WORK/content-replication-seed/publication
    cr_origin=$WORK/state-relay5/content
    cr_replica=$WORK/state-relay4/content
    cr_final=$WORK/state-client/content
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$cr_origin" "$cr_replica" "$cr_final"
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/examples/content-acceptance-fixture" seed-replication \
        "$cr_seed" "$cr_origin/p" "$cr_origin/q" >"$WORK/content-replication-seed.log" 2>&1 \
        || fail CONTENT_REPLICATION_SEED_FAILED
    install -o root -g root -m 0600 "$cr_seed/replication.json" "$WORK/content-replication-publication.json"
    cr_key=$(jq -er '.foreground.publisher_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-replication-publication.json") || fail CONTENT_REPLICATION_PUBLICATION_INVALID
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$cr_seed/manifest-p.bin" "$cr_replica/p.bin"
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$cr_seed/manifest-q.bin" "$cr_final/q.bin"
    content_replication_isolation relay4 "$cr_replica/p.bin" || fail CONTENT_REPLICATION_ORIGIN_SHORTCUT
    content_replication_isolation client "$cr_final/q.bin" || fail CONTENT_REPLICATION_REPLICA_SHORTCUT
    if [ -e "$cr_replica/q.bin" ] || [ -e "$cr_replica/replicas" ] \
        || [ -e "$cr_final/cache" ]; then fail CONTENT_REPLICATION_PRESEEDED_CONSUMER; fi
    for cr_label in p q; do
        content_replication_cli relay5 content serve --manifest "$cr_seed/manifest-$cr_label.bin" \
            --publisher-key "$cr_key" --cache "$cr_origin/$cr_label" \
            --bind 50.166.6.1:18080 --advertised-hostname provider-b.volparossa.test \
            --replica-cache "$cr_origin/replicas" \
            >"$WORK/content-replication-origin-$cr_label-serve.json" \
            2>"$WORK/content-replication-origin-$cr_label-serve.err" || fail CONTENT_REPLICATION_ORIGIN_UNAVAILABLE
    done
    PHASE=content-replication-warmup
    content_replication_select relay4 content-replication-warm || fail CONTENT_REPLICATION_ROUTE_UNAVAILABLE
    content_replication_cli relay4 content fetch --manifest "$cr_replica/p.bin" --publisher-key "$cr_key" \
        --cache "$cr_replica/primary-p" --output "$cr_replica/primary-p.bin" \
        >"$WORK/content-replication-warm-fetch.json" 2>"$WORK/content-replication-warm-fetch.err" \
        || fail CONTENT_REPLICATION_WARM_FETCH_FAILED
    # The real foreground result becomes an explicit service seed. No Q file is copied here.
    content_replication_cli relay4 content serve --manifest "$cr_replica/p.bin" --publisher-key "$cr_key" \
        --cache "$cr_replica/primary-p" --bind 49.165.5.1:18080 \
        --advertised-hostname provider-a.volparossa.test --replica-cache "$cr_replica/replicas" \
        >"$WORK/content-replication-replica-serve.json" 2>"$WORK/content-replication-replica-serve.err" \
        || fail CONTENT_REPLICATION_SERVICE_UNAVAILABLE
    content_replication_cli relay4 content status >"$WORK/content-replication-before.json" \
        || fail CONTENT_REPLICATION_STATUS_UNAVAILABLE
    jq -e '.replication_enabled and .replica_chunks == 0 and .replica_bytes == 0 and .replica_publications == 0' \
        "$WORK/content-replication-before.json" >/dev/null || fail CONTENT_REPLICATION_NOT_EMPTY

    PHASE=content-replication-uptake
    content_replication_capture uptake || fail CONTENT_REPLICATION_CAPTURE_UNAVAILABLE
    content_replication_start_owner_probe || fail CONTENT_REPLICATION_OWNER_PROBE_UNAVAILABLE
    content_replication_cli relay4 content fetch --manifest "$cr_replica/p.bin" --publisher-key "$cr_key" \
        --cache "$cr_replica/foreground-p" --output "$cr_replica/foreground-p.bin" \
        >"$WORK/content-replication-foreground-fetch.json" 2>"$WORK/content-replication-foreground-fetch.err" \
        || fail CONTENT_REPLICATION_FOREGROUND_FAILED
    content_replication_finish_owner_probe || fail CONTENT_REPLICATION_OWNER_PAUSE_RESUME_FAILED
    cr_deadline=$(($(date +%s) + 45))
    cr_complete=no
    while [ "$(date +%s)" -lt "$cr_deadline" ]; do
        if CONTENT_REPLICATION_COMMAND_TIMEOUT=2s content_replication_cli relay4 content status \
            >"$WORK/content-replication-after.json" \
            2>"$WORK/content-replication-after.err" \
            && jq -e '.replica_chunks == 3 and .replica_bytes == 524411 and .replica_publications == 1' \
                "$WORK/content-replication-after.json" >/dev/null; then cr_complete=yes; break; fi
        sleep 0.25
    done
    [ "$cr_complete" = yes ] || fail CONTENT_REPLICATION_UPTAKE_NOT_OBSERVED
    content_replication_snapshot relay4 content-replication-uptake-live || fail CONTENT_REPLICATION_PATH_PROOF_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_REPLICATION_CAPTURE_INCOMPLETE
    content_replication_provider_network before-disconnect
    content_replication_disconnect relay4 content-replication-replicator || fail CONTENT_REPLICATION_ROUTE_CLEANUP_FAILED
    PHASE=content-replication-origin-offline
    content_replication_cli relay5 content stop >"$WORK/content-replication-origin-stop.json" \
        2>"$WORK/content-replication-origin-stop.err" || fail CONTENT_REPLICATION_ORIGIN_STOP_FAILED
    jq -e '.serving == false and .publications == 0' "$WORK/content-replication-origin-stop.json" \
        >/dev/null || fail CONTENT_REPLICATION_ORIGIN_STILL_SERVING
    # This exact unit was created by launch_agent and remains in AGENT_UNITS for idempotent
    # cleanup. R5 is neither selected data relay nor the discovery broker in this scenario.
    systemctl stop volparossa-alpha-agent@relay5.service || fail CONTENT_REPLICATION_ORIGIN_AGENT_STOP_FAILED
    cr_origin_active=$(systemctl show --property=ActiveState --value volparossa-alpha-agent@relay5.service)
    cr_origin_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay5.service)
    if [ "$cr_origin_active" != inactive ] || [ "$cr_origin_pid" != 0 ]; then
        fail CONTENT_REPLICATION_ORIGIN_AGENT_SURVIVED
    fi
    ip netns exec "$R5" ss -H -ltn 'sport = :18080' >"$WORK/content-replication-origin-listeners.txt"
    [ ! -s "$WORK/content-replication-origin-listeners.txt" ] || fail CONTENT_REPLICATION_ORIGIN_LISTENER_SURVIVED
    jq -cn --arg unit volparossa-alpha-agent@relay5.service --arg state "$cr_origin_active" \
        --argjson pid "$cr_origin_pid" '{unit:$unit,active_state:$state,main_pid:$pid,listener_absent:true}' \
        >"$WORK/content-replication-origin-offline.json"

    PHASE=content-replication-reopen
    # Stop drops the service registry and replication runtime. Recreate them explicitly from
    # the owned cache after R5 is offline; Q's manifest is still never supplied to R4.
    content_replication_cli relay4 content stop >"$WORK/content-replication-replica-pause.json" \
        2>"$WORK/content-replication-replica-pause.err" || fail CONTENT_REPLICATION_PAUSE_FAILED
    jq -e '.serving == false and .publications == 0 and .replication_enabled == false' \
        "$WORK/content-replication-replica-pause.json" >/dev/null || fail CONTENT_REPLICATION_PAUSE_INCOMPLETE
    ip netns exec "$R4" ss -H -ltn 'sport = :18080' >"$WORK/content-replication-paused-listeners.txt"
    [ ! -s "$WORK/content-replication-paused-listeners.txt" ] || fail CONTENT_REPLICATION_PAUSED_LISTENER_SURVIVED
    [ ! -e "$cr_replica/q.bin" ] || fail CONTENT_REPLICATION_MANIFEST_SHORTCUT
    content_replication_isolation relay4 "$cr_replica/p.bin" || fail CONTENT_REPLICATION_ORIGIN_SHORTCUT
    content_replication_cli relay4 content serve --manifest "$cr_replica/p.bin" --publisher-key "$cr_key" \
        --cache "$cr_replica/primary-p" --bind 49.165.5.1:18080 \
        --advertised-hostname provider-a.volparossa.test \
        --replica-cache "$cr_replica/replicas" --reuse-replica-cache \
        >"$WORK/content-replication-replica-resume.json" \
        2>"$WORK/content-replication-replica-resume.err" || fail CONTENT_REPLICATION_REOPEN_FAILED
    jq -e '.serving and .replication_enabled and .publications == 2 and .replica_publications == 1
        and .replica_chunks == 3 and .replica_bytes == 524411' \
        "$WORK/content-replication-replica-resume.json" >/dev/null || fail CONTENT_REPLICATION_RESTORE_INCOMPLETE
    content_replication_provider_network after-reopen

    PHASE=content-replication-reserve-fetch
    content_replication_select client content-replication-final || fail CONTENT_REPLICATION_FINAL_ROUTE_UNAVAILABLE
    content_replication_capture reserve-fetch || fail CONTENT_REPLICATION_FINAL_CAPTURE_UNAVAILABLE
    if ! content_replication_cli client content fetch --manifest "$cr_final/q.bin" --publisher-key "$cr_key" \
        --cache "$cr_final/cache" --output "$cr_final/q.bin.verified" \
        >"$WORK/content-replication-final-fetch.json" 2>"$WORK/content-replication-final-fetch.err"; then
        content_replication_provider_network final-fetch-failed
        fail CONTENT_REPLICATION_FINAL_FETCH_FAILED
    fi
    content_replication_snapshot client content-replication-final-live || fail CONTENT_REPLICATION_FINAL_PATHS_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_REPLICATION_FINAL_CAPTURE_INCOMPLETE
    content_replication_cli relay4 content stop >"$WORK/content-replication-replica-stop.json" \
        || fail CONTENT_REPLICATION_REPLICA_STOP_FAILED
    content_replication_disconnect client content-replication-final || fail CONTENT_REPLICATION_FINAL_CLEANUP_FAILED
    capture_product_logs
    jq -cn --arg psha "$(sha256sum "$cr_replica/foreground-p.bin" | awk '{print $1}')" \
        --arg qsha "$(sha256sum "$cr_final/q.bin.verified" | awk '{print $1}')" \
        --argjson pbytes "$(stat -Lc '%s' "$cr_replica/foreground-p.bin")" \
        --argjson qbytes "$(stat -Lc '%s' "$cr_final/q.bin.verified")" '
      {foreground:{sha256:$psha,bytes:$pbytes},reserve:{sha256:$qsha,bytes:$qbytes},
       replicator_cannot_read_original_cache:true,consumer_cannot_read_either_cache:true,
       reserve_manifest_not_supplied_to_replicator:true,replica_cache_initially_absent:true,
       final_cache_initially_absent:true,original_listener_absent_before_final_fetch:true,
       replica_listener_absent_before_reopen:true,replica_reopened_after_original_shutdown:true}' \
        >"$WORK/content-replication-output.json"
    python3 -B "$source_directory/tests/integration/content-replication-smoke.py" evidence \
        "$WORK" "$WORK/content-replication-evidence.json" || fail CONTENT_REPLICATION_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-replication-complete
}

content_replication_finalize_report() {
    cr_status=$1
    # Preserve raw inputs even if report serialization or validation fails. The ten physical
    # captures can exceed Linux's per-argument limit; JSON belongs in files, not argv.
    for cr_artifact in "$WORK"/content-replication-*.json "$WORK"/content-replication-*.txt \
        "$WORK"/content-replication-*.log "$WORK"/content-replication-*.err \
        "$WORK"/content-replication-*.out; do
        [ ! -f "$cr_artifact" ] || [ -L "$cr_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$cr_artifact" \
                "$output_directory/$(basename -- "$cr_artifact")"
    done
    optional_json_evidence "$WORK/content-replication-evidence.json" \
        >"$WORK/content-replication-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/content-replication-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$cr_status" \
        --slurpfile evidence_input "$WORK/content-replication-report-evidence.part" \
        --slurpfile host_input "$WORK/content-replication-report-host.part" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      $evidence_input[0] as $evidence | $host_input[0] as $host |
      {schema_version:1,report_kind:"volparossa-content-replication",source_revision:$revision,
       phase:$phase,runner_exit_status:$status,observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       success:($status == 0 and $evidence.success == true and $complete and $remaining == 0 and $host.unchanged),
       transfer:$evidence,cleanup:{complete:$complete,remaining_owned_objects:$remaining},
       host_state:($host | del(.acceptance_id)),
       scope:"explicit P/Q objects; bounded real owner traffic, one in-flight chunk allowance and same-flow replica resume; explicit service reopen and protected re-serving",
       full_c03_claimed:false,full_c04_claimed:false,speed_improvement_claimed:false,
       browser_integration_claimed:false,full_alpha_acceptance_claimed:false}' \
        >"$WORK/content-replication-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/content-replication-smoke.json" \
        "$output_directory/content-replication-smoke.json"
    python3 -B "$source_directory/tests/integration/content-replication-smoke.py" report \
        "$WORK/content-replication-smoke.json" "$expected_commit"
}
