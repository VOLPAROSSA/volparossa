#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additional real peer adoption gate; the earlier catalog/cycle proof stays unchanged.
# shellcheck disable=SC2154,SC2034

agent_peer_learning_private() {
    peer_learning_fixture=agent-peer-learning-smoke.py
    [ "${agent_artifact_quarantine:-no}" != yes ] || peer_learning_fixture=agent-artifact-quarantine-smoke.py
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/$peer_learning_fixture" "$@"
}

agent_peer_learning_link() {
    case $1 in
        0) pl_ns=$R0; pl_public=42.158.0.1; pl_segment=110 ;;
        1) pl_ns=$R1; pl_public=44.160.1.1; pl_segment=112 ;;
        2) pl_ns=$R2; pl_public=45.161.2.1; pl_segment=114 ;;
        *) return 1 ;;
    esac
}

agent_peer_learning_network() {
    # Late, owned links preserve the preceding catalog proof's physical topology.
    [ "${PEER_LEARNING_NETWORK_ACTIVE:-no}" = no ] || return 1
    for pl_index in 0 1 2; do
        agent_peer_learning_link "$pl_index" || return 1
        if ip -n "$R3" link show "lr$pl_index" >/dev/null 2>&1 \
            || ip -n "$pl_ns" link show "r${pl_index}l" >/dev/null 2>&1; then return 1; fi
        [ "$(ip -n "$R3" -j route show exact "$pl_public/32" | jq 'length')" = 0 ] || return 1
        [ "$(ip -n "$pl_ns" -j route show exact 48.164.4.1/32 | jq 'length')" = 0 ] || return 1
    done
    if ip netns exec "$R3" nft list table inet vpa_peer_learning_serving >/dev/null 2>&1; then return 1; fi
    if ip netns exec "$EXIT_NODE" nft list table inet vpa_peer_learning_serving >/dev/null 2>&1; then return 1; fi
    PEER_LEARNING_NETWORK_ACTIVE=yes
    # The old R3↔Exit link is solely the already authorized provider-c application
    # endpoint. In particular it cannot carry a consumer tunnel or initiate Exit TCP.
    ip netns exec "$R3" nft -f - <<'RULES' || return 1
table inet vpa_peer_learning_serving {
 chain input { type filter hook input priority -20; policy accept;
  iifname "r3x" ip saddr 46.162.3.1 ip daddr 48.164.4.1 tcp dport 18080 ct state new,established accept
  iifname "r3x" drop
 }
 chain output { type filter hook output priority -20; policy accept;
  oifname "r3x" ip saddr 48.164.4.1 ip daddr 46.162.3.1 tcp sport 18080 ct state established accept
  oifname "r3x" drop
 }
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "r3x" drop
  oifname "r3x" drop
 }
}
RULES
    ip netns exec "$EXIT_NODE" nft -f - <<'RULES' || return 1
table inet vpa_peer_learning_serving {
 chain input { type filter hook input priority -20; policy accept;
  iifname "xr3" ip saddr 48.164.4.1 ip daddr 46.162.3.1 tcp sport 18080 ct state established accept
  iifname "xr3" drop
 }
 chain output { type filter hook output priority -20; policy accept;
  oifname "xr3" ip saddr 46.162.3.1 ip daddr 48.164.4.1 tcp dport 18080 ct state new,established accept
  oifname "xr3" drop
 }
 chain forward { type filter hook forward priority -20; policy accept;
  iifname "xr3" drop
  oifname "xr3" drop
 }
}
RULES
    for pl_index in 0 1 2; do
        agent_peer_learning_link "$pl_index" || return 1
        # Both ends are born inside owned namespaces, including partial-failure cleanup.
        ip -n "$R3" link add "lr$pl_index" type veth peer name "r${pl_index}l" netns "$pl_ns" || return 1
        ip -n "$R3" address add "10.241.$pl_segment.1/30" dev "lr$pl_index" || return 1
        ip -n "$pl_ns" address add "10.241.$pl_segment.2/30" dev "r${pl_index}l" || return 1
        ip -n "$R3" link set "lr$pl_index" up || return 1
        ip -n "$pl_ns" link set "r${pl_index}l" up || return 1
        ip -n "$R3" route add "$pl_public/32" via "10.241.$pl_segment.2" dev "lr$pl_index" src 48.164.4.1 || return 1
        ip -n "$pl_ns" route add 48.164.4.1/32 via "10.241.$pl_segment.1" dev "r${pl_index}l" src "$pl_public" || return 1
    done
    pl_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay3.service)
    case $pl_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Positive control plus actual mount isolation, not same-UID filesystem assumptions.
    nsenter --target "$pl_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups -- test -r "$WORK/state-relay3/identity.key" || return 1
    for pl_private in "$WORK/state-client" "$WORK/state-relay4" "$WORK/state-relay5" \
        "$WORK/content-replication-seed" "$artifact_user"; do
        if nsenter --target "$pl_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups -- test -r "$pl_private"; then return 1; fi
    done
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" configuration \
        "$WORK/config-relay3.yaml" >"$WORK/agent-peer-learning-configuration.json" || return 1
    jq -cn '{learner:"relay3",identity_readable:true,other_node_stores_inaccessible:true,
      publisher_private_root_inaccessible:true,links:["lr0:r0l","lr1:r1l","lr2:r2l"],
      segments:[110,112,114],exit_link_serving_only:true}' >"$WORK/agent-peer-learning-network.json"
}

agent_peer_learning_network_cleanup() {
    [ "${PEER_LEARNING_NETWORK_ACTIVE:-no}" = yes ] || return 0
    case " $AGENT_UNITS " in *' volparossa-alpha-agent@relay3.service '*) ;; *) return 1 ;; esac
    # Stop the actual consumer/contributor before removing its serving-only filter.
    retire_unit volparossa-alpha-agent@relay3.service || return 1
    pl_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay3.service 2>/dev/null || true)
    case $pl_pid in ''|0) ;; *) return 1 ;; esac
    for pl_index in 0 1 2; do
        agent_peer_learning_link "$pl_index" || return 1
        if ip -n "$R3" link show "lr$pl_index" >/dev/null 2>&1; then
            ip -n "$R3" link delete "lr$pl_index" || return 1
        fi
        if ip -n "$pl_ns" link show "r${pl_index}l" >/dev/null 2>&1; then
            ip -n "$pl_ns" link delete "r${pl_index}l" || return 1
        fi
        if ip -n "$R3" link show "lr$pl_index" >/dev/null 2>&1 \
            || ip -n "$pl_ns" link show "r${pl_index}l" >/dev/null 2>&1; then return 1; fi
        [ "$(ip -n "$R3" -j route show exact "$pl_public/32" | jq 'length')" = 0 ] || return 1
        [ "$(ip -n "$pl_ns" -j route show exact 48.164.4.1/32 | jq 'length')" = 0 ] || return 1
    done
    for pl_filter_ns in "$R3" "$EXIT_NODE"; do
        if ip netns exec "$pl_filter_ns" nft list table inet vpa_peer_learning_serving >/dev/null 2>&1; then
            ip netns exec "$pl_filter_ns" nft delete table inet vpa_peer_learning_serving || return 1
        fi
        if ip netns exec "$pl_filter_ns" nft list table inet vpa_peer_learning_serving >/dev/null 2>&1; then return 1; fi
    done
    PEER_LEARNING_NETWORK_ACTIVE=no
    jq -cn '{learner:"relay3",agent_stopped:true,owned_link_pairs_absent:3,
      serving_filter_removed:true,prior_topology_restored:true}' >"$WORK/agent-peer-learning-network-cleanup.json"
}

agent_peer_learning_share_validation() {
    PHASE=agent-peer-learning-validation-contribution
    agent_artifact_cli relay4 content export --public-content \
        --manifest "$artifact_user/loop/validation-input/dataset.manifest" --publisher-key "$artifact_publisher" \
        --agent-cache "$loop_cache" --cache "$artifact_user/peer-validation-export" \
        >"$WORK/agent-peer-learning-validation-export.json" || return 1
    agent_artifact_cli relay4 content contribute \
        --manifest "$artifact_user/loop/validation-input/dataset.manifest" --publisher-key "$artifact_publisher" \
        --cache "$artifact_user/peer-validation-export" >"$WORK/agent-peer-learning-validation-contribute.json"
}

agent_peer_learning_execute() {
    exec nsenter --net="/run/netns/$R3" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --groups="$custody_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay3/control/agent.sock" \
        compute train-loop --plan "$artifact_user/peer-plan.json" --peer-updates "$artifact_user/peer-channels.json" \
        --validation-source "$artifact_user/peer-validation-source.json" --directory "$artifact_user/peer-learning" \
        --runtime-root "$artifact_user/provision/venv" --model-root "$artifact_user/provision/model" \
        --cache "$peer_learning_cache" --max-cycles 1 --steps 8 --threads 2 --max-seconds 600 --poll-seconds 1 \
        --publish-name disposable-r3-peer-successor --publication-key "$peer_learning_publisher" \
        --identity "$artifact_user/peer-identity.key" --passphrase-file "$artifact_user/peer-passphrase" \
        --publish-cache "$artifact_user/peer-publish-cache" --execute
}

agent_peer_learning_run() {
    PHASE=agent-peer-learning-prepare
    [ "$loop_latest" != none ] || fail PEER_LEARNING_NO_APPROVED_PROVIDER_UPDATE
    agent_peer_learning_private setup "$artifact_user" "$loop_publisher" \
        >"$WORK/agent-peer-learning-selected.json" || fail PEER_LEARNING_SELECTION_FAILED
    if [ "${agent_artifact_quarantine:-no}" = yes ]; then
        agent_artifact_quarantine_publish || fail ARTIFACT_QUARANTINE_PUBLICATION_FAILED
    fi
    agent_artifact_cli relay3 init --identity "$artifact_user/peer-identity.key" \
        --passphrase-file "$artifact_user/peer-passphrase" >"$WORK/agent-peer-learning-identity.log" \
        || fail PEER_LEARNING_IDENTITY_FAILED
    agent_artifact_cli relay3 content recipient-key --identity "$artifact_user/peer-identity.key" \
        --passphrase-file "$artifact_user/peer-passphrase" >"$WORK/agent-peer-learning-owner-key.json" \
        || fail PEER_LEARNING_OWNER_KEY_FAILED
    peer_learning_publisher=$(jq -er '.identity_public_key_hex' "$WORK/agent-peer-learning-owner-key.json")
    [ "$peer_learning_publisher" != "$loop_publisher" ] || fail PEER_LEARNING_OWNER_NOT_DISTINCT
    agent_artifact_cli relay3 content publish --input "$artifact_user/peer-plan.json" --name disposable-peer-enrollment \
        --revision 1 --content-type application/json --identity "$artifact_user/peer-identity.key" \
        --passphrase-file "$artifact_user/peer-passphrase" --cache "$artifact_user/peer-publish-cache" \
        --manifest "$artifact_user/peer-enrollment.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-peer-learning-owner-cache.json" || fail PEER_LEARNING_OWNER_CACHE_FAILED
    peer_learning_cache=$WORK/state-relay3/agent-peer-learning-cache
    if [ -e "$peer_learning_cache" ] || [ -L "$peer_learning_cache" ]; then fail PEER_LEARNING_CACHE_NOT_NEW; fi
    agent_peer_learning_network || fail PEER_LEARNING_NETWORK_FAILED
    agent_artifact_cli relay3 content status >"$WORK/agent-peer-learning-service-before.json" || fail PEER_LEARNING_SERVICE_FAILED
    jq -e '.serving == true and .replication_enabled == true' "$WORK/agent-peer-learning-service-before.json" >/dev/null \
        || fail PEER_LEARNING_CONTRIBUTION_NOT_ENABLED
    content_replication_select relay3 agent-peer-learning-transfer || fail PEER_LEARNING_ROUTE_FAILED
    content_replication_capture peer-learning agent-peer-learning-transfer "$WORK/agent-peer-learning-transfer-selection.json" \
        || fail PEER_LEARNING_CAPTURE_FAILED
    # Initialize a real native cache through protected retrieval, never an empty directory.
    agent_artifact_cli relay3 content fetch-name --publisher-key "$artifact_publisher" \
        --name disposable-agent-validation --min-revision 1 --cache "$peer_learning_cache" \
        --local-output "$artifact_user/peer-initial-validation.json" \
        >"$WORK/agent-peer-learning-initial-fetch.json" || fail PEER_LEARNING_INITIAL_FETCH_FAILED
    PHASE=agent-peer-learning-adopt-and-train
    agent_peer_learning_execute >"$WORK/agent-peer-learning-stdout.jsonl" 2>"$WORK/agent-peer-learning-worker.err" &
    artifact_job_pid=$!
    peer_learning_poll=0
    while [ "$peer_learning_poll" -lt 100 ]; do
        kill -0 "$artifact_job_pid" 2>/dev/null || fail PEER_LEARNING_EARLY_EXIT
        [ "$(stat -Lc '%u' "/proc/$artifact_job_pid")" != "$WORKER_UID" ] || break
        sleep 0.01; peer_learning_poll=$((peer_learning_poll + 1))
    done
    peer_learning_service=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay3.service)
    python3 -B "$source_directory/tests/integration/$peer_learning_fixture" observe "$artifact_job_pid" \
        "$artifact_user" "/run/netns/$R3" "$peer_learning_service" \
        >"$WORK/agent-peer-learning-observer.log" 2>"$WORK/agent-peer-learning-observer.err" \
        || fail PEER_LEARNING_ACTUAL_WORKERS_MISSING
    wait "$artifact_job_pid" || fail PEER_LEARNING_COORDINATOR_FAILED
    artifact_job_pid=
    agent_peer_learning_private collect "$artifact_user" >"$WORK/agent-peer-learning-files.json" \
        || fail PEER_LEARNING_RETAINED_FILES_INVALID
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" last-json \
        "$WORK/agent-peer-learning-stdout.jsonl" compute_train_loop >"$WORK/agent-peer-learning-summary.json" \
        || fail PEER_LEARNING_SUMMARY_INVALID
    content_replication_snapshot relay3 agent-peer-learning-transfer-live || fail PEER_LEARNING_PATHS_FAILED
    stop_privacy_observers || fail PEER_LEARNING_CAPTURE_INCOMPLETE
    agent_artifact_cli relay3 content stop >"$WORK/agent-peer-learning-service-stop.json" || fail PEER_LEARNING_SERVICE_STOP_FAILED
    content_replication_disconnect relay3 agent-peer-learning-transfer || fail PEER_LEARNING_ROUTE_CLEANUP_FAILED
    agent_peer_learning_network_cleanup || fail PEER_LEARNING_NETWORK_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/$peer_learning_fixture" evidence "$WORK" "$expected_commit" \
        || fail PEER_LEARNING_PROOF_INVALID
}

agent_peer_learning_cleanup() {
    agent_peer_learning_network_cleanup || return 1
    [ -n "${artifact_user:-}" ] && [ -f "$WORK/bin/agent-peer-learning-smoke.py" ] || return 0
    if [ ! -f "$WORK/agent-peer-learning-cleanup.json" ]; then
        agent_peer_learning_private cleanup "$artifact_user" >"$WORK/agent-peer-learning-cleanup.json" || return 1
    fi
}

agent_peer_learning_finalize() {
    for peer_log in "$WORK"/agent-peer-learning-*.json "$WORK"/agent-peer-learning-*.jsonl \
        "$WORK"/agent-peer-learning-*.err "$WORK"/agent-peer-learning-*.log; do
        [ ! -f "$peer_log" ] || [ -L "$peer_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$peer_log" "$output_directory/$(basename -- "$peer_log")"
    done
    if [ "${agent_artifact_quarantine:-no}" = yes ]; then
        agent_artifact_quarantine_finalize "$1"
        return
    fi
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-peer-learning-smoke.json" "$output_directory/agent-peer-learning-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" report \
        "$WORK/agent-peer-learning-smoke.json" "$expected_commit"
}
