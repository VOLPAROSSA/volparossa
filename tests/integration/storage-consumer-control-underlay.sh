#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the disposable topology supervisor. No standalone/root entry.
# Caller owns all six namespaces and must retain the existing trap/full cleanup.
# shellcheck disable=SC2154

storage_consumer_control_snapshot() {
    case $1 in before|detached|after) consumer_matrix_stage=$1 ;; *) return 1 ;; esac
    : >"$WORK/consumer-control-nodes.private"
    for consumer_node in relay0 relay1 relay2 relay3 relay4 relay5; do
        content_provider_node "$consumer_node" || return 1
        ip -n "$provider_ns" -j -d link show >"$WORK/consumer-control-raw.private" || return 1
        [ "$(wc -c <"$WORK/consumer-control-raw.private")" -le 65536 ] || return 1
        jq -ce '[.[] | select(.ifname | test("^(ac|ap|cc|pc)[0-9]+$")) |
            {ifindex,ifname,link_index,flags,kind:.linkinfo.info_kind}]' \
            "$WORK/consumer-control-raw.private" >"$WORK/consumer-control-links.private" || return 1
        ip -n "$provider_ns" -j -d -4 route show >"$WORK/consumer-control-raw.private" || return 1
        [ "$(wc -c <"$WORK/consumer-control-raw.private")" -le 65536 ] || return 1
        jq -ce '[.[] | select((.dev // "") | test("^(ac|ap|cc|pc)[0-9]+$")) |
            {dst,dev,gateway,prefsrc,scope,protocol}]' \
            "$WORK/consumer-control-raw.private" >"$WORK/consumer-control-routes.private" || return 1
        ip netns exec "$provider_ns" nft -j list tables >"$WORK/consumer-control-raw.private" || return 1
        [ "$(wc -c <"$WORK/consumer-control-raw.private")" -le 65536 ] || return 1
        jq -e '.nftables | type == "array"' "$WORK/consumer-control-raw.private" >/dev/null || return 1
        jq -e '[.nftables[] | .table // empty | select(.name |
            startswith("vpa_content_control_adaptive_") or startswith("vpa_content_control_consumer_")) |
            select(.family != "inet")] | length == 0' "$WORK/consumer-control-raw.private" >/dev/null || return 1
        jq -r '.nftables | [.[] | .table // empty |
            select(.name | startswith("vpa_content_control_adaptive_") or startswith("vpa_content_control_consumer_")) |
            select(.family == "inet") | .name] | .[]' "$WORK/consumer-control-raw.private" \
            >"$WORK/consumer-control-table-names.private" || return 1
        printf '{}\n' >"$WORK/consumer-control-tables.private"
        while IFS= read -r consumer_table; do
            case $consumer_table in
                vpa_content_control_adaptive_[012]|vpa_content_control_consumer_[012][012]) ;;
                *) return 1 ;;
            esac
            ip netns exec "$provider_ns" nft -j list table inet "$consumer_table" \
                >"$WORK/consumer-control-raw.private" || return 1
            [ "$(wc -c <"$WORK/consumer-control-raw.private")" -le 16384 ] || return 1
            jq -cn --arg name "$consumer_table" --slurpfile value "$WORK/consumer-control-raw.private" \
                '{($name):$value[0]}' >>"$WORK/consumer-control-tables.private" || return 1
        done <"$WORK/consumer-control-table-names.private"
        jq -s 'add' "$WORK/consumer-control-tables.private" >"$WORK/consumer-control-filter.private" || return 1
        jq -cn --arg node "$consumer_node" --slurpfile links "$WORK/consumer-control-links.private" \
            --slurpfile routes "$WORK/consumer-control-routes.private" --slurpfile tables "$WORK/consumer-control-filter.private" \
            '{($node):{links:$links[0],routes:$routes[0],tables:$tables[0]}}' \
            >>"$WORK/consumer-control-nodes.private" || return 1
    done
    jq -s 'add' "$WORK/consumer-control-nodes.private" >"$WORK/consumer-control-inventory.private" || return 1
    printf 'null\n' >"$WORK/consumer-control-checks.private"
    if [ "$consumer_matrix_stage" = before ]; then
        private_storage_maintenance_control_snapshot after || return 1
        jq -c '.route_checks' "$WORK/maintenance-control-after.private" >"$WORK/consumer-control-checks.private" || return 1
    elif [ "$consumer_matrix_stage" = after ]; then
        : >"$WORK/consumer-control-check-rows.private"
        for consumer_broker in relay0 relay1 relay2; do
            content_provider_node "$consumer_broker" || return 1
            consumer_broker_ns=$provider_ns; consumer_broker_ip=$provider_ip
            for consumer_provider in relay3 relay4 relay5; do
                content_provider_node "$consumer_provider" || return 1
                ip -n "$consumer_broker_ns" -j route get "$provider_ip" >"$WORK/consumer-control-raw.private" || return 1
                [ "$(wc -c <"$WORK/consumer-control-raw.private")" -le 8192 ] || return 1
                jq -ce '[.[] | {dst,dev,gateway,prefsrc}]' "$WORK/consumer-control-raw.private" \
                    >"$WORK/consumer-control-out.private" || return 1
                ip -n "$provider_ns" -j route get "$consumer_broker_ip" >"$WORK/consumer-control-raw.private" || return 1
                [ "$(wc -c <"$WORK/consumer-control-raw.private")" -le 8192 ] || return 1
                jq -ce '[.[] | {dst,dev,gateway,prefsrc}]' "$WORK/consumer-control-raw.private" \
                    >"$WORK/consumer-control-back.private" || return 1
                jq -cn --arg broker "$consumer_broker" --arg provider "$consumer_provider" \
                    --slurpfile out "$WORK/consumer-control-out.private" --slurpfile back "$WORK/consumer-control-back.private" \
                    '{($broker):{($provider):{out:$out[0],back:$back[0]}}}' \
                    >>"$WORK/consumer-control-check-rows.private" || return 1
            done
        done
        jq -s 'reduce .[] as $item ({}; . * $item)' "$WORK/consumer-control-check-rows.private" \
            >"$WORK/consumer-control-checks.private" || return 1
    fi
    jq -cSn --slurpfile nodes "$WORK/consumer-control-inventory.private" --slurpfile checks "$WORK/consumer-control-checks.private" \
        '{nodes:$nodes[0],route_checks:$checks[0]}' >"$WORK/consumer-control-$consumer_matrix_stage.private" || return 1
}

storage_consumer_control_check() {
    python3 -B "$WORK/bin/storage-consumer-control-underlay.py" check "$WORK" \
        "$WORK/consumer-control-candidate.private" "$1"
}

storage_consumer_control_prepare() {
    # No watchdog/retry: all three ordinary brokers get physical control reachability
    # before any consumer request, regardless of a later normal route reselection.
    umask 077
    [ "${private_storage_maintenance:-no}" = yes ] && [ -z "$PROVIDER_CONTROL_PID" ] || return 1
    [ ! -e "$WORK/storage-consumer-control-underlay.json" ] \
        && [ ! -L "$WORK/storage-consumer-control-underlay.json" ] || return 1
    consumer_previous_node=$(jq -er --slurpfile transition "$WORK/private-storage-maintenance-control-transition.json" \
        'to_entries[] | select(.value == $transition[0].current_control_relay_peer_id) | .key' \
        "$WORK/a01-expected-peers.json") || return 1
    case $consumer_previous_node in relay0|relay1|relay2) ;; *) return 1 ;; esac
    content_provider_node "$consumer_previous_node" || return 1
    consumer_previous_ns=$provider_ns
    [ "$provider_control_ns" = "$consumer_previous_ns" ] || return 1
    storage_consumer_control_snapshot before || return 1
    consumer_transition_sha=$(sha256sum "$WORK/private-storage-maintenance-control-transition.json" | awk '{print $1}') || return 1
    consumer_peers_sha=$(jq -cSj '.' "$WORK/a01-expected-peers.json" | sha256sum | awk '{print $1}') || return 1
    jq -cn --arg transition "$consumer_transition_sha" --arg peers "$consumer_peers_sha" \
        --slurpfile before "$WORK/consumer-control-before.private" \
        '{schema_version:1,kind:"storage-consumer-control-underlay",original_transition_sha256:$transition,
          original_peers_sha256:$peers,before:$before[0],detached:null,after:null,application_acceptance:false}' \
        >"$WORK/consumer-control-candidate.private" || return 1
    storage_consumer_control_check before || return 1
    # Exact previous three pairs have just been verified against their immutable
    # original kernel identities. Only these owned links/tables may be removed.
    for consumer_slot in 0 1 2; do
        ip -n "$consumer_previous_ns" link delete "ac$consumer_slot" || return 1
    done
    for consumer_slot in 0 1 2; do
        ip netns exec "$consumer_previous_ns" nft delete table inet "vpa_content_control_adaptive_$consumer_slot" || return 1
        content_provider_node "relay$((3 + consumer_slot))" || return 1
        ip netns exec "$provider_ns" nft delete table inet "vpa_content_control_adaptive_$consumer_slot" || return 1
    done
    storage_consumer_control_snapshot detached || return 1
    jq --slurpfile detached "$WORK/consumer-control-detached.private" '.detached=$detached[0]' \
        "$WORK/consumer-control-candidate.private" >"$WORK/consumer-control-next.private" || return 1
    mv -- "$WORK/consumer-control-next.private" "$WORK/consumer-control-candidate.private" || return 1
    storage_consumer_control_check detached || return 1
    for consumer_b in 0 1 2; do
        content_provider_node "relay$consumer_b" || return 1
        consumer_broker_ns=$provider_ns; consumer_broker_ip=$provider_ip
        for consumer_p in 0 1 2; do
            content_provider_node "relay$((3 + consumer_p))" || return 1
            consumer_segment=$((1 + 3 * consumer_b + consumer_p))
            consumer_left=cc$consumer_b$consumer_p; consumer_right=pc$consumer_b$consumer_p
            ip -n "$consumer_broker_ns" link add "$consumer_left" type veth \
                peer name "$consumer_right" netns "$provider_ns" || return 1
            ip -n "$consumer_broker_ns" address add "10.247.$consumer_segment.1/30" dev "$consumer_left" || return 1
            ip -n "$provider_ns" address add "10.247.$consumer_segment.2/30" dev "$consumer_right" || return 1
            content_provider_filter_link "$consumer_broker_ns" "consumer_$consumer_b$consumer_p" "$consumer_left" \
                "$consumer_broker_ip" "$provider_ip" || return 1
            content_provider_filter_link "$provider_ns" "consumer_$consumer_b$consumer_p" "$consumer_right" \
                "$provider_ip" "$consumer_broker_ip" || return 1
            ip -n "$consumer_broker_ns" link set "$consumer_left" up || return 1
            ip -n "$provider_ns" link set "$consumer_right" up || return 1
            ip -n "$consumer_broker_ns" route add "$provider_ip/32" \
                via "10.247.$consumer_segment.2" dev "$consumer_left" src "$consumer_broker_ip" || return 1
            ip -n "$provider_ns" route add "$consumer_broker_ip/32" \
                via "10.247.$consumer_segment.1" dev "$consumer_right" src "$provider_ip" || return 1
        done
    done
    storage_consumer_control_snapshot after || return 1
    jq -cSj --slurpfile after "$WORK/consumer-control-after.private" '.after=$after[0]' \
        "$WORK/consumer-control-candidate.private" >"$WORK/consumer-control-next.private" || return 1
    [ "$(wc -c <"$WORK/consumer-control-next.private")" -le 131072 ] || return 1
    mv -- "$WORK/consumer-control-next.private" "$WORK/consumer-control-candidate.private" || return 1
    storage_consumer_control_check complete || return 1
    mv -- "$WORK/consumer-control-candidate.private" "$WORK/storage-consumer-control-underlay.json"
}
