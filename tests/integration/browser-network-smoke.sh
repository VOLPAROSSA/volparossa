#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicitly approved disposable KVM topology.
# shellcheck disable=SC2154,SC2034

browser_network_check() {
    python3 -B "$source_directory/tests/integration/browser-network-smoke.py" "$@"
}

browser_network_wait() {
    bn_wait=0
    while [ "$bn_wait" -lt 900 ]; do
        [ ! -s "$1" ] || return 0
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || return 1
        sleep 0.1
        bn_wait=$((bn_wait + 1))
    done
    return 1
}

browser_network_sample() {
    bn_poll=0
    while [ "$bn_poll" -lt 300 ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || return 1
        if browser_network_check sample "$WORK/browser-network-$1.json" \
            2>"$WORK/browser-network-observer.err"; then return 0; fi
        sleep 0.1
        bn_poll=$((bn_poll + 1))
    done
    return 1
}

browser_network_run() {
    PHASE=browser-network-origin
    bn_runtime=/home/vpci/browser-network-runtime
    bn_user=$WORK/client-fixtures/browser-network
    bn_origin=$WORK/destination/browser-network-origin
    bn_gates=$WORK/destination/browser-network-gates
    bn_output=$bn_runtime/build/proofs/session
    bn_control_gid=$(stat -Lc '%g' "$WORK/runtime-client/control")
    bn_parent_netns=$(readlink /proc/self/ns/net)
    if [ ! -f "$bn_runtime/provision.json" ] || [ -e "$bn_output" ]; then fail BROWSER_NETWORK_RUNTIME_UNAVAILABLE; fi
    # Debian cloud home modes differ. Add only search permission on this exact
    # disposable guest directory when needed, and restore the original mode on every cleanup.
    if ! setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        test -r "$bn_runtime/provision.json"; then
        [ ! -L /home/vpci ] || fail BROWSER_NETWORK_RUNTIME_PARENT_INVALID
        [ "$(stat -Lc '%u' /home/vpci)" = "$(id -u vpci)" ] || fail BROWSER_NETWORK_RUNTIME_PARENT_INVALID
        BROWSER_PARENT_HOME_MODE=$(stat -Lc '%a' /home/vpci)
        chmod o+x /home/vpci
    fi
    install -o root -g root -m 0600 "$bn_runtime/provision.json" "$WORK/browser-network-provision.json"
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$bn_user" "$bn_runtime/build/proofs"
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$bn_user/home"
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$bn_gates"
    # Capless fixture processes must not depend on traversing the vpci checkout.
    install -d -o root -g root -m 0755 "$WORK/browser-network-tools"
    for bn_script in browser-network-smoke.py mptcp-growth-smoke.py mpquic-growth-smoke.py content-network-smoke.py; do
        install -o root -g root -m 0444 "$source_directory/tests/integration/$bn_script" "$WORK/browser-network-tools/$bn_script"
    done
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 -B "$WORK/browser-network-tools/browser-network-smoke.py" seed "$bn_origin" "$RUN_ID" \
        >/dev/null 2>"$WORK/browser-network-seed.err" || fail BROWSER_NETWORK_ORIGIN_SEED_FAILED
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$bn_origin/ca.pem" "$bn_user/test-ca.pem"
    bn_hash=$(browser_network_check hash "$RUN_ID") || fail BROWSER_NETWORK_HASH_FAILED
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 -B "$WORK/browser-network-tools/browser-network-smoke.py" origin \
        "$bn_origin" "$bn_gates" "$RUN_ID" "$bn_gates/origin.json" \
        >/dev/null 2>"$WORK/browser-network-origin.err" &
    TLS_POLICY_SERVER_PID=$!
    wait_observer "$TLS_POLICY_SERVER_PID" "$bn_gates/origin.ready" || fail BROWSER_NETWORK_ORIGIN_UNAVAILABLE
    PHASE=browser-network-grants
    for bn_grant in a b; do
        bn_partition=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
        ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
            --groups="$bn_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
            "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
            browser grant --app-uid "$WORKER_UID" --hostname destination.volparossa.test --port 18443 \
            --partition "$bn_partition" --lifetime-seconds 300 --output "$bn_user/grant-$bn_grant.json" \
            >/dev/null 2>"$WORK/browser-network-grant.err" || fail BROWSER_NETWORK_GRANT_UNAVAILABLE
    done
    # Disposable fixture containment, NOT a product/browser-wide kill switch.
    # Only this application's UID is restricted; the distinct agent UID still owns overlay I/O.
    ip netns exec "$CLIENT" nft -f - <<EOF
add table inet vpbrowser
add chain inet vpbrowser output { type filter hook output priority -5; policy accept; }
add rule inet vpbrowser output meta skuid $WORKER_UID ip daddr != 127.0.0.1 drop
add rule inet vpbrowser output meta skuid $WORKER_UID meta nfproto ipv6 drop
EOF
    PHASE=browser-network-first
    start_privacy_observers browser-network-first-privacy || fail BROWSER_NETWORK_CAPTURE_UNAVAILABLE
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --groups="$bn_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        env HOME="$bn_user/home" python3 -B "$bn_runtime/scripts/smoke_network_core.py" --stage "$bn_runtime/build/firefox-esr" \
        --grant-a "$bn_user/grant-a.json" --grant-b "$bn_user/grant-b.json" --test-ca "$bn_user/test-ca.pem" \
        --expected-sha256 "$bn_hash" --expected-bytes 33554432 --core-revision "$expected_commit" \
        --parent-netns "$bn_parent_netns" --output "$bn_output" \
        --url-a https://destination.volparossa.test:18443/first.bin \
        --url-b https://destination.volparossa.test:18443/second.bin \
        >/dev/null 2>"$WORK/browser-network-driver.err" &
    DOWNLOAD_CLIENT_PID=$!
    browser_network_check isolation "$DOWNLOAD_CLIENT_PID" "$bn_parent_netns" \
        "$(ip netns exec "$CLIENT" readlink /proc/self/ns/net)" "$WORKER_UID" "$WORKER_GID" "$bn_control_gid" \
        "$WORK/browser-network-isolation.json" || fail BROWSER_NETWORK_APP_BOUNDARY_INVALID
    for bn_phase in first second; do
        PHASE=browser-network-$bn_phase
        browser_network_wait "$bn_gates/$bn_phase.ready" || fail BROWSER_NETWORK_HTTPS_REQUEST_UNAVAILABLE
        browser_network_sample "$bn_phase-baseline" || fail BROWSER_NETWORK_REAL_MPTCP_UNAVAILABLE
        if [ "$bn_phase" = second ]; then
            printf '%s\n' '{"version":1,"detach":true}' >"$bn_output/detach-a"
            chown "$WORKER_UID:$WORKER_GID" "$bn_output/detach-a"
            browser_network_wait "$bn_output/a-detached.json" || fail BROWSER_NETWORK_DETACH_NOT_REQUESTED
            bn_poll=0
            while [ "$bn_poll" -lt 300 ]; do
                if browser_network_check detached "$WORK/browser-network-first-baseline.json" \
                    "$WORK/browser-network-detach.json" 2>"$WORK/browser-network-detach.err"; then break; fi
                sleep 0.1
                bn_poll=$((bn_poll + 1))
            done
            [ "$bn_poll" -lt 300 ] || fail BROWSER_NETWORK_FIRST_ROUTE_NOT_RETIRED
        fi
        printf '%s\n' '{"version":1,"release":true}' >"$bn_gates/$bn_phase.release"
        chown "$AGENT_UID:$AGENT_GID" "$bn_gates/$bn_phase.release"
        browser_network_wait "$bn_gates/$bn_phase.progress-ready" || fail BROWSER_NETWORK_PAYLOAD_UNAVAILABLE
        bn_poll=0
        while [ "$bn_poll" -lt 300 ]; do
            if browser_network_check sample "$WORK/browser-network-$bn_phase-progress.json" \
                && browser_network_check progress "$WORK/browser-network-$bn_phase-baseline.json" \
                "$WORK/browser-network-$bn_phase-progress.json"; then break; fi
            sleep 0.1
            bn_poll=$((bn_poll + 1))
        done
        [ "$bn_poll" -lt 300 ] || fail BROWSER_NETWORK_TWO_CARRYING_PATHS_MISSING
        stop_privacy_observers || fail BROWSER_NETWORK_CAPTURE_NOT_DRAINED
        # Final half needs no new path claim; it completes the independent full browser hash.
        printf '%s\n' '{"version":1,"continue":true}' >"$bn_gates/$bn_phase.continue"
        chown "$AGENT_UID:$AGENT_GID" "$bn_gates/$bn_phase.continue"
        if [ "$bn_phase" = first ]; then
            browser_network_wait "$bn_output/a-complete.json" || fail BROWSER_NETWORK_FIRST_HASH_FAILED
            start_privacy_observers browser-network-second-privacy || fail BROWSER_NETWORK_CAPTURE_UNAVAILABLE
        fi
    done
    bn_browser_status=0
    wait "$DOWNLOAD_CLIENT_PID" || bn_browser_status=$?
    DOWNLOAD_CLIENT_PID=
    [ "$bn_browser_status" -eq 0 ] || fail BROWSER_NETWORK_BROWSER_FAILED
    bn_origin_status=0
    wait "$TLS_POLICY_SERVER_PID" || bn_origin_status=$?
    TLS_POLICY_SERVER_PID=
    [ "$bn_origin_status" -eq 0 ] || fail BROWSER_NETWORK_ORIGIN_FAILED
    install -o root -g root -m 0600 "$bn_output/report.json" "$WORK/browser-network-browser.json"
    install -o root -g root -m 0600 "$bn_gates/origin.json" "$WORK/browser-network-origin.json"
    browser_network_check evidence "$WORK" "$WORK/browser-network-evidence.json" || fail BROWSER_NETWORK_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=browser-network-complete
}

browser_network_cleanup() {
    # Capture only bounded sanitized results, including failures; never grant/profile/log bytes.
    bn_cleanup_status=0
    bn_report=/home/vpci/browser-network-runtime/build/proofs/session/report.json
    browser_network_check driver-diagnostic \
        /home/vpci/browser-network-runtime/build/proofs/session/driver-status.json \
        "$WORK/browser-network-driver.err" "$WORK/browser-network-driver.json" || bn_cleanup_status=1
    if [ -f "$bn_report" ] && [ ! -L "$bn_report" ] && [ "$(stat -Lc '%s' "$bn_report")" -le 16384 ]; then
        install -o root -g root -m 0600 "$bn_report" "$WORK/browser-network-browser.json" || bn_cleanup_status=1
    fi
    if [ -n "${BROWSER_PARENT_HOME_MODE:-}" ]; then
        chmod "$BROWSER_PARENT_HOME_MODE" /home/vpci || bn_cleanup_status=1
        [ "$(stat -Lc '%a' /home/vpci)" = "$BROWSER_PARENT_HOME_MODE" ] || bn_cleanup_status=1
    fi
    browser_network_check cleanup "$WORK" /home/vpci/browser-network-runtime \
        "$WORK/browser-network-private-cleanup.json" || bn_cleanup_status=1
    return "$bn_cleanup_status"
}

browser_network_finalize_report() {
    bn_status=$1
    bn_evidence=$(optional_json_evidence "$WORK/browser-network-evidence.json")
    bn_host=$(optional_json_evidence "$WORK/a15-evidence.json")
    jq -n --arg revision "$expected_commit" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$bn_status" --argjson network "$bn_evidence" --argjson host "$bn_host" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-browser-network",source_revision:$revision,
       phase:$phase,runner_exit_status:$status,network:$network,
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       success:($status == 0 and $network != null and $complete and $remaining == 0 and $host.unchanged == true),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host|del(.acceptance_id)),
       full_browser_killswitch_claimed:false,http3_claimed:false,direct_fallback:false,
       scope:"two explicit privileged Gecko HTTPS channels through app-scoped real MPTCP; not general browsing interception"}
    ' >"$WORK/browser-network-smoke.json" || return 1
    for bn_name in $(browser_network_check export-names); do
        [ ! -f "$WORK/$bn_name" ] || [ -L "$WORK/$bn_name" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/$bn_name" "$output_directory/$bn_name" || return 1
    done
    browser_network_check report "$output_directory/browser-network-smoke.json" "$expected_commit"
}
