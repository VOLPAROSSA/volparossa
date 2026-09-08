#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced after native provider retrieval inside the disposable, exact-build KVM guest.
# shellcheck disable=SC2154,SC2034

content_provider_https_cli() {
    timeout --signal=TERM --kill-after=5s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ph_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

content_provider_https_cleanup() {
    content_provider_https_limited_remove || return 1
    # Exact owned public fixture files only; never sweep caches or arbitrary directories.
    ph_cleanup_root=$WORK/client-fixtures/https-output
    [ ! -L "$ph_cleanup_root" ] || return 1
    if [ -e "$ph_cleanup_root" ]; then
        [ -d "$ph_cleanup_root" ] \
            && [ "$(stat -Lc '%a:%u:%g' "$ph_cleanup_root")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || return 1
        for ph_cleanup_name in origin.pem complete-object.bin missing-object.bin origin-baseline.json origin-only-object.bin auto-object.bin digest-origin-only-object.bin digest-peers-first-object.bin limited-origin-only-object.bin limited-peers-first-object.bin limited-auto-object.bin; do
            ph_cleanup_mode=600
            [ "$ph_cleanup_name" != origin.pem ] || ph_cleanup_mode=400
            ph_cleanup_file=$ph_cleanup_root/$ph_cleanup_name
            [ ! -L "$ph_cleanup_file" ] || return 1
            if [ -e "$ph_cleanup_file" ]; then
                [ -f "$ph_cleanup_file" ] \
                    && [ "$(stat -Lc '%a:%u:%g' "$ph_cleanup_file")" = "$ph_cleanup_mode:$WORKER_UID:$WORKER_GID" ] \
                    || return 1
                rm -f -- "$ph_cleanup_file" || return 1
            fi
        done
        rmdir -- "$ph_cleanup_root" || return 1
    fi
    jq -n '{user_outputs_removed:true,explicit_fixture_ca_removed:true,user_directory_removed:true}' \
        >"$WORK/content-provider-https-user-cleanup.json"
}

content_provider_https_phase() {
    ph_case=$1
    case $ph_case in
        complete|missing) ph_strategy=peers-first ;;
        origin-only|auto) ph_strategy=$ph_case ;;
        digest-origin-only) ph_strategy=origin-only ;;
        digest-peers-first) ph_strategy=peers-first ;;
        limited-origin-only) ph_strategy=origin-only ;;
        limited-peers-first) ph_strategy=peers-first ;;
        limited-auto) ph_strategy=auto ;;
        *) fail PROVIDER_HTTPS_SOURCE_STRATEGY_INVALID ;;
    esac
    ph_prefix=content-provider-https-$ph_case
    ph_cache=$provider_client/https-$ph_case-cache
    ph_output=$ph_user/$ph_case-object.bin
    PHASE=$ph_prefix-capture
    if [ -e "$ph_cache" ] || [ -L "$ph_cache" ] || [ -e "$ph_output" ] || [ -L "$ph_output" ]; then
        fail PROVIDER_HTTPS_CACHE_NOT_EMPTY
    fi
    start_privacy_observers "$ph_prefix-privacy" || fail PROVIDER_HTTPS_PRIVACY_UNAVAILABLE
    content_provider_start_control_observer "$ph_prefix-control" \
        || fail PROVIDER_HTTPS_CONTROL_CAPTURE_UNAVAILABLE

    PHASE=$ph_prefix-fetch
    # Both the CLI process and the application's loopback HTTP GET inherit the exact
    # Client namespace and unprivileged operator credentials, never the VM root network.
    timeout --signal=TERM --kill-after=10s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ph_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$ph_driver" \
        consume "$ph_case" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$ph_cache" "$ph_user" \
        "$ph_parent_netns" "$ph_client_netns" "$WORKER_UID" "$WORKER_GID" "$ph_control_gid" \
        >"$WORK/$ph_prefix-consumer.json" 2>"$WORK/$ph_prefix-fetch.err" \
        || fail PROVIDER_HTTPS_RUNTIME_FETCH_FAILED
    jq '.final' "$WORK/$ph_prefix-consumer.json" >"$WORK/$ph_prefix-fetch.json" \
        || fail PROVIDER_HTTPS_RECEIPT_INVALID
    benchmark_capture_paths "$ph_prefix-live" mptcp || fail PROVIDER_HTTPS_PATHS_UNAVAILABLE
    jq -e --arg context "$provider_context" '.route_context_id == $context' \
        "$WORK/$ph_prefix-live-selection.json" >/dev/null || fail PROVIDER_HTTPS_ROUTE_CHANGED
    jq -e --arg control "$provider_control_peer" \
        '.origin_authenticated == true and .control_relay_peer_id == $control' \
        "$WORK/$ph_prefix-fetch.json" >/dev/null || fail PROVIDER_HTTPS_AUTHORITY_NOT_PROVEN
    stop_privacy_observers || fail PROVIDER_HTTPS_PRIVACY_INCOMPLETE
    content_provider_stop_control_observer || fail PROVIDER_HTTPS_CONTROL_CAPTURE_INCOMPLETE
    ph_output_digest=$(sha256sum "$ph_output" | awk '{print $1}')
    # This is the existing local-output command's no-clobber guard, also for the file
    # obtained via HTTP. It is not an invented browser-download output-path option.
    case $ph_case in
        digest-*|limited-*) set -- --origin-digest ;;
        *) set -- --metadata-path /.well-known/volparossa/content/asset ;;
    esac
    if content_provider_https_cli content fetch-https --url https://destination.volparossa.test:18443/asset.bin \
        "$@" --ca-file "$ph_user/origin.pem" \
        --source-strategy "$ph_strategy" --cache "$ph_cache" --local-output "$ph_output" \
        >"$WORK/$ph_prefix-no-clobber.out" 2>"$WORK/$ph_prefix-no-clobber.err"; then
        fail PROVIDER_HTTPS_USER_OUTPUT_OVERWRITTEN
    fi
    grep -F 'already exists' "$WORK/$ph_prefix-no-clobber.err" >/dev/null \
        || fail PROVIDER_HTTPS_NO_CLOBBER_NOT_LOCAL
    if [ "$(sha256sum "$ph_output" | awk '{print $1}')" != "$ph_output_digest" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$ph_output")" != "600:$WORKER_UID:$WORKER_GID" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$ph_user")" != "700:$WORKER_UID:$WORKER_GID" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$ph_cache")" != "700:$AGENT_UID:$AGENT_GID" ]; then
        fail PROVIDER_HTTPS_USER_OUTPUT_OWNERSHIP_CHANGED
    fi
    content_provider_https_cli content status >"$WORK/$ph_prefix-status.json" \
        2>"$WORK/$ph_prefix-status.err" || fail PROVIDER_HTTPS_USER_CONTROL_UNAVAILABLE
    jq -n --arg sha256 "$ph_output_digest" --arg path "$ph_output" --arg agent_cache "$ph_cache" \
        --argjson bytes "$(stat -Lc '%s' "$ph_output")" \
        --argjson user_uid "$WORKER_UID" --argjson agent_uid "$AGENT_UID" \
        --argjson control_gid "$ph_control_gid" --argjson agent_gid "$AGENT_GID" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          path:$path,agent_cache:$agent_cache,user_uid:$user_uid,agent_uid:$agent_uid,
          control_gid:$control_gid,agent_gid:$agent_gid,output_mode:"0600",directory_mode:"0700",
          agent_cache_mode:"0700",local_output_initially_absent:true,no_clobber_verified:true,
          no_clobber_rejected_before_network:true,agent_mount_positive_control:true,
          agent_cannot_read_user_output_directory:true,client_mount_cannot_read_origin:true}' \
        >"$WORK/$ph_prefix-output.json"
}

content_provider_https_limited_remove() {
    [ "${PH_LIMITED_QDISC_OWNED:-no}" = yes ] || return 0
    ip netns exec "$DEST" tc -j -s qdisc show dev dx >"$WORK/content-provider-https-limited-qdisc-final.json" || return 1
    jq -e 'length == 1 and .[0].kind == "tbf" and .[0].handle == "804:"
        and .[0].root == true and .[0].options.rate == 500000' \
        "$WORK/content-provider-https-limited-qdisc-final.json" >/dev/null || return 1
    printf '%s\n' "Removing only owned TBF 804: from disposable namespace $DEST interface dx."
    ip netns exec "$DEST" tc qdisc del dev dx root handle 804: || return 1
    ip netns exec "$DEST" tc -j qdisc show dev dx >"$WORK/content-provider-https-limited-qdisc-after.json" || return 1
    jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].root == true' \
        "$WORK/content-provider-https-limited-qdisc-after.json" >/dev/null || return 1
    PH_LIMITED_QDISC_OWNED=no
}

content_provider_https_limited_run() {
    # One predefined bandwidth condition, never per-request sleeps or rate tuning.
    PHASE=content-provider-https-limited-setup
    [ "${PH_LIMITED_QDISC_OWNED:-no}" = no ] || fail PROVIDER_HTTPS_QDISC_ALREADY_OWNED
    ip netns exec "$DEST" tc -j qdisc show dev dx >"$WORK/content-provider-https-limited-qdisc-before.json" \
        || fail PROVIDER_HTTPS_QDISC_UNAVAILABLE
    jq -e 'length == 1 and .[0].kind == "noqueue" and .[0].root == true' \
        "$WORK/content-provider-https-limited-qdisc-before.json" >/dev/null || fail PROVIDER_HTTPS_QDISC_NOT_EMPTY
    printf '%s\n' "Adding fixed TBF 804: rate 4mbit burst 128kb latency 250ms to disposable namespace $DEST interface dx; remove before existing missing/origin phases."
    ip netns exec "$DEST" tc qdisc add dev dx root handle 804: tbf rate 4mbit burst 128kb latency 250ms \
        || fail PROVIDER_HTTPS_QDISC_INSTALL_FAILED
    PH_LIMITED_QDISC_OWNED=yes
    ph_limited_started=$(python3 -B -c 'import time; print(time.monotonic_ns())')
    ph_limited_parent=$(readlink /proc/self/ns/net)
    ph_limited_namespace=$(ip netns exec "$DEST" readlink /proc/self/ns/net) || fail PROVIDER_HTTPS_QDISC_NAMESPACE
    [ "$ph_limited_parent" != "$ph_limited_namespace" ] || fail PROVIDER_HTTPS_QDISC_NAMESPACE
    for ph_limited_case in limited-origin-only limited-peers-first limited-auto; do
        ip netns exec "$DEST" tc -j -s qdisc show dev dx >"$WORK/content-provider-https-$ph_limited_case-qdisc-before.json" \
            || fail PROVIDER_HTTPS_QDISC_UNAVAILABLE
        timeout 5s "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" logs --limit 400 \
            >"$WORK/content-provider-https-$ph_limited_case-events-before.txt" || fail PROVIDER_HTTPS_SOURCE_EVENTS_UNAVAILABLE
        content_provider_https_phase "$ph_limited_case"
        timeout 5s "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" logs --limit 400 \
            >"$WORK/content-provider-https-$ph_limited_case-events-after.txt" || fail PROVIDER_HTTPS_SOURCE_EVENTS_UNAVAILABLE
        ip netns exec "$DEST" tc -j -s qdisc show dev dx >"$WORK/content-provider-https-$ph_limited_case-qdisc-after.json" \
            || fail PROVIDER_HTTPS_QDISC_UNAVAILABLE
    done
    ph_limited_finished=$(python3 -B -c 'import time; print(time.monotonic_ns())')
    jq -n --arg namespace "$ph_limited_namespace" --arg parent "$ph_limited_parent" \
        --argjson started "$ph_limited_started" --argjson finished "$ph_limited_finished" '
        {profile:"fixed-origin-uplink-4mbit",interface:"dx",origin_address:"47.163.4.2",handle:"804:",
         rate_bits_per_second:4000000,burst_bytes:131072,queue_latency_ms:250,
         namespace:$namespace,parent_namespace:$parent,started_monotonic_ns:$started,
         completed_monotonic_ns:$finished,window_ns:($finished-$started),application_sleeps:false,
         adaptive_rate:false}' >"$WORK/content-provider-https-limited-profile.json"
    content_provider_https_limited_remove || fail PROVIDER_HTTPS_QDISC_CLEANUP_FAILED
    [ "$((ph_limited_finished - ph_limited_started))" -lt 60000000000 ] \
        || fail PROVIDER_HTTPS_COST_WINDOW_EXPIRED
}

content_provider_https_baseline() {
    ph_prefix=content-provider-https-baseline
    PHASE=$ph_prefix-capture
    capture_product_logs
    ph_client_before=$(grep -cF 'event=INGRESS_TCP_STREAM_COMPLETED' "$WORK/logs-client.txt" || true)
    ph_exit_before=$(grep -cF 'event=MPTCP_EXIT_FLOW_COMPLETED' "$WORK/logs-exit.txt" || true)
    start_privacy_observers "$ph_prefix-privacy" || fail PROVIDER_HTTPS_PRIVACY_UNAVAILABLE
    PHASE=$ph_prefix-fetch
    timeout --signal=TERM --kill-after=10s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ph_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$ph_driver" \
        consume baseline "$ph_binary" "$WORK/runtime-client/control/agent.sock" unused \
        "$ph_user" "$ph_parent_netns" "$ph_client_netns" "$WORKER_UID" "$WORKER_GID" "$ph_control_gid" \
        >"$WORK/$ph_prefix-consumer.json" 2>"$WORK/$ph_prefix-fetch.err" \
        || fail PROVIDER_HTTPS_ORIGIN_BASELINE_FAILED
    benchmark_capture_paths "$ph_prefix-live" mptcp || fail PROVIDER_HTTPS_PATHS_UNAVAILABLE
    jq -e --arg context "$provider_context" '.route_context_id == $context' \
        "$WORK/$ph_prefix-live-selection.json" >/dev/null || fail PROVIDER_HTTPS_ROUTE_CHANGED
    # New completion events, not historical A08 successes, prove ordinary TPROXY ingress.
    ph_log_attempt=0
    while [ "$ph_log_attempt" -lt 50 ]; do
        capture_product_logs
        ph_client_after=$(grep -cF 'event=INGRESS_TCP_STREAM_COMPLETED' "$WORK/logs-client.txt" || true)
        ph_exit_after=$(grep -cF 'event=MPTCP_EXIT_FLOW_COMPLETED' "$WORK/logs-exit.txt" || true)
        if [ "$ph_client_after" -ge "$((ph_client_before + 2))" ] \
            && [ "$ph_exit_after" -ge "$((ph_exit_before + 2))" ]; then break; fi
        sleep 0.1
        ph_log_attempt=$((ph_log_attempt + 1))
    done
    [ "$ph_log_attempt" -lt 50 ] || fail PROVIDER_HTTPS_BASELINE_INGRESS_NOT_PROVEN
    stop_privacy_observers || fail PROVIDER_HTTPS_PRIVACY_INCOMPLETE
    jq -n --argjson client_before "$ph_client_before" --argjson client_after "$ph_client_after" \
        --argjson exit_before "$ph_exit_before" --argjson exit_after "$ph_exit_after" \
        '{client_before:$client_before,client_after:$client_after,exit_before:$exit_before,exit_after:$exit_after}' \
        >"$WORK/$ph_prefix-ingress.json"
}

content_provider_https_independent_index() {
    PHASE=content-provider-https-independent-index
    # Earlier native/cooperative downloads used the common index. Retire B's entire
    # registry before registering its own independent publication, never an ID alias.
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node_a/control/agent.sock" \
        content status >"$WORK/content-provider-https-index-a-status.json" \
        2>"$WORK/content-provider-https-index-a-status.err" || fail PROVIDER_HTTPS_INDEX_STATUS_FAILED
    jq -e '.serving == true and .publications == 1 and .replication_enabled == false' \
        "$WORK/content-provider-https-index-a-status.json" >/dev/null || fail PROVIDER_HTTPS_INDEX_A_CHANGED
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node_b/control/agent.sock" \
        content stop >"$WORK/content-provider-https-index-b-stop.json" \
        2>"$WORK/content-provider-https-index-b-stop.err" || fail PROVIDER_HTTPS_INDEX_STOP_FAILED
    jq -e '.serving == false and .publications == 0' \
        "$WORK/content-provider-https-index-b-stop.json" >/dev/null || fail PROVIDER_HTTPS_INDEX_NOT_RETIRED
    ph_index_root=$provider_b/digest-index
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$ph_binary" independent-index "$ph_index_root" "$provider_manifest" \
        "$provider_publisher" "$provider_b/cache" >"$WORK/content-provider-https-index-seed.log" 2>&1 \
        || fail PROVIDER_HTTPS_INDEX_SEED_FAILED
    install -o root -g root -m 0600 "$ph_index_root/publication.json" \
        "$WORK/content-provider-https-index-publication.json"
    ph_index_key=$(jq -er '.independent.publisher_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-provider-https-index-publication.json") || fail PROVIDER_HTTPS_INDEX_KEY_INVALID
    case $provider_node_b in
        relay4) ph_index_address=49.165.5.1; ph_index_hostname=provider-a.volparossa.test ;;
        relay5) ph_index_address=50.166.6.1; ph_index_hostname=provider-b.volparossa.test ;;
        relay3) ph_index_address=48.164.4.1; ph_index_hostname=provider-c.volparossa.test ;;
        *) fail PROVIDER_HTTPS_INDEX_NODE_INVALID ;;
    esac
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node_b/control/agent.sock" \
        content serve --manifest "$ph_index_root/manifest.bin" --publisher-key "$ph_index_key" \
        --cache "$provider_b/cache" --bind "$ph_index_address:18080" \
        --advertised-hostname "$ph_index_hostname" >"$WORK/content-provider-https-index-b-serve.json" \
        2>"$WORK/content-provider-https-index-b-serve.err" || fail PROVIDER_HTTPS_INDEX_SERVE_FAILED
    jq -e '.serving == true and .publications == 1' \
        "$WORK/content-provider-https-index-b-serve.json" >/dev/null || fail PROVIDER_HTTPS_INDEX_NOT_EXCLUSIVE
    jq -n --arg node "$provider_node_b" --arg key "$ph_index_key" \
        --arg cache "$provider_b/cache" --arg manifest "$ph_index_root/manifest.bin" \
        --arg sha "$(sha256sum "$ph_index_root/manifest.bin" | awk '{print $1}')" \
        --arg original_sha "$(sha256sum "$provider_manifest" | awk '{print $1}')" \
        --arg bind "$ph_index_address:18080" --arg hostname "$ph_index_hostname" \
        --argjson registered "$(date +%s)" --slurpfile peers "$WORK/a01-expected-peers.json" \
        '{provider_node:$node,provider_peer_id:$peers[0][$node],publisher_hex:$key,
          cache:$cache,manifest_path:$manifest,manifest_file_sha256:$sha,
          original_manifest_file_sha256:$original_sha,bind_address:$bind,advertised_hostname:$hostname,
          registered_unix_seconds:$registered,replacement_phase:"after-digest-origin-only"}' \
        >"$WORK/content-provider-https-index-binding.json"
}

content_provider_https_run() {
    PHASE=content-provider-https-origin-seed
    ph_binary=$binary_directory/examples/https-content-acceptance-fixture
    # The operator must not traverse the private checkout home. Stage only these
    # public driver sources, including the driver's relative read/require dependency.
    for ph_script in content-provider-https-smoke.py content-network-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$ph_script" \
            "$WORK/bin/$ph_script" || fail PROVIDER_HTTPS_DRIVER_UNAVAILABLE
    done
    ph_driver=$WORK/bin/content-provider-https-smoke.py
    # Reuse exactly the publication already held in the two independent providers. Only
    # its public key crosses into the origin fixture; no resigning or replacement authority.
    ph_origin_root=$WORK/content-provider-seed/https-origin
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$ph_binary" seed-from-publication "$ph_origin_root" "$provider_manifest" \
        "$provider_publisher" >"$WORK/content-provider-https-seed.log" 2>&1 \
        || fail PROVIDER_HTTPS_ORIGIN_SEED_FAILED
    install -o root -g root -m 0600 "$ph_origin_root/publication.json" \
        "$WORK/content-provider-https-publication.json"
    ph_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $ph_control_gid in ''|*[!0-9]*) fail PROVIDER_HTTPS_CONTROL_GROUP_INVALID ;; esac
    [ "$ph_control_gid" != "$AGENT_GID" ] || fail PROVIDER_HTTPS_CONTROL_GROUP_INVALID
    ph_user=$WORK/client-fixtures/https-output
    if [ -e "$ph_user" ] || [ -L "$ph_user" ]; then fail PROVIDER_HTTPS_USER_DIRECTORY_EXISTS; fi
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$ph_user"
    ph_parent_netns=$(readlink /proc/self/ns/net)
    ph_client_netns=$(ip netns exec "$CLIENT" readlink /proc/self/ns/net) \
        || fail PROVIDER_HTTPS_CLIENT_NAMESPACE_UNAVAILABLE
    [ "$ph_parent_netns" != "$ph_client_netns" ] || fail PROVIDER_HTTPS_CLIENT_NAMESPACE_INVALID
    # Same UID is insufficient evidence in this topology: probe the actual Client agent's
    # private mount namespace, whose existing InaccessiblePaths hides this entire seed root.
    provider_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $provider_client_pid in ''|0|*[!0-9]*) fail PROVIDER_HTTPS_CLIENT_PID_INVALID ;; esac
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$provider_manifest" || fail PROVIDER_HTTPS_ISOLATION_PROBE_UNAVAILABLE
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$ph_origin_root/object.bin"; then
        fail PROVIDER_HTTPS_LOCAL_ORIGIN_SHORTCUT
    fi
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$ph_user"; then
        fail PROVIDER_HTTPS_USER_DIRECTORY_EXPOSED
    fi

    PHASE=content-provider-https-origin
    [ -z "$TLS_POLICY_SERVER_PID" ] || fail PROVIDER_HTTPS_ORIGIN_PROCESS_SLOT_BUSY
    ph_origin_report=$WORK/destination/content-provider-https-origin.json
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$ph_binary" origin-pem-bounded "$ph_origin_root" 47.163.4.2:18443 \
        "$WORK/destination/content-provider-https-origin.pem" "$ph_origin_report" 31 \
        >"$WORK/content-provider-https-origin.log" 2>&1 &
    TLS_POLICY_SERVER_PID=$!
    wait_observer "$TLS_POLICY_SERVER_PID" "$ph_origin_report.ready" \
        || fail PROVIDER_HTTPS_ORIGIN_NOT_READY
    # This explicit public fixture CA is read by the normal CLI. No TLS bypass, host trust
    # installation, publisher-key argument or pre-fetched descriptor enters fetch-https.
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
        "$WORK/destination/content-provider-https-origin.pem" "$ph_user/origin.pem"

    content_provider_https_phase complete
    # No custom metadata-path request in either case. Replace only B's index between
    # cases: fresh HEAD must authorize bytes from both independent original indexes.
    content_provider_https_phase digest-origin-only
    content_provider_https_independent_index
    content_provider_https_phase digest-peers-first
    content_provider_https_limited_run
    PHASE=content-provider-https-withdraw-one
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node_b/control/agent.sock" \
        content stop >"$WORK/content-provider-https-provider-stop.json" \
        2>"$WORK/content-provider-https-provider-stop.err" || fail PROVIDER_HTTPS_WITHDRAW_FAILED
    jq -e '.serving == false and .publications == 0' \
        "$WORK/content-provider-https-provider-stop.json" >/dev/null \
        || fail PROVIDER_HTTPS_WITHDRAW_INCOMPLETE
    jq -n --arg node "$provider_node_b" \
        --slurpfile peers "$WORK/a01-expected-peers.json" \
        '{provider_node:$node,provider_peer_id:$peers[0][$node]}' \
        >"$WORK/content-provider-https-withdrawal.json"
    content_provider_https_phase missing
    content_provider_https_baseline
    # Same product command, user, object and carrying route; each owns a distinct cold
    # agent cache. Choice remains free in auto, and measured timing never forces a winner.
    content_provider_https_phase origin-only
    content_provider_https_phase auto

    ph_origin_status=0
    kill -TERM "$TLS_POLICY_SERVER_PID" || fail PROVIDER_HTTPS_ORIGIN_STOP_FAILED
    wait "$TLS_POLICY_SERVER_PID" || ph_origin_status=$?
    TLS_POLICY_SERVER_PID=
    [ "$ph_origin_status" -eq 0 ] || fail PROVIDER_HTTPS_ORIGIN_FAILED
    install -o root -g root -m 0600 "$ph_origin_report" "$WORK/content-provider-https-origin.json"
    content_provider_https_cleanup || fail PROVIDER_HTTPS_USER_OUTPUT_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-provider-https-smoke.py" \
        evidence "$WORK" "$WORK/content-provider-https-evidence.json" \
        || fail PROVIDER_HTTPS_EVIDENCE_INVALID
    PHASE=content-provider-https-complete
}
