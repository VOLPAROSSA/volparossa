#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced after native provider retrieval inside the disposable, exact-build KVM guest.
# shellcheck disable=SC2154,SC2034

content_provider_https_cli() {
    timeout --signal=TERM --kill-after=5s 120s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ph_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

content_provider_https_cleanup() {
    # Exact owned public fixture files only; never sweep caches or arbitrary directories.
    ph_cleanup_root=$WORK/client-fixtures/https-output
    [ ! -L "$ph_cleanup_root" ] || return 1
    if [ -e "$ph_cleanup_root" ]; then
        [ -d "$ph_cleanup_root" ] \
            && [ "$(stat -Lc '%a:%u:%g' "$ph_cleanup_root")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || return 1
        for ph_cleanup_name in origin.pem complete-object.bin missing-object.bin; do
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
    content_provider_https_cli content fetch-https --url https://destination.volparossa.test:18443/asset.bin \
        --metadata-path /.well-known/volparossa/content/asset \
        --ca-file "$ph_user/origin.pem" \
        --cache "$ph_cache" --local-output "$ph_output" \
        >"$WORK/$ph_prefix-fetch.json" 2>"$WORK/$ph_prefix-fetch.err" \
        || fail PROVIDER_HTTPS_RUNTIME_FETCH_FAILED
    benchmark_capture_paths "$ph_prefix-live" mptcp || fail PROVIDER_HTTPS_PATHS_UNAVAILABLE
    jq -e --arg context "$provider_context" '.route_context_id == $context' \
        "$WORK/$ph_prefix-live-selection.json" >/dev/null || fail PROVIDER_HTTPS_ROUTE_CHANGED
    jq -e --arg control "$provider_control_peer" \
        '.origin_authenticated == true and .control_relay_peer_id == $control' \
        "$WORK/$ph_prefix-fetch.json" >/dev/null || fail PROVIDER_HTTPS_AUTHORITY_NOT_PROVEN
    stop_privacy_observers || fail PROVIDER_HTTPS_PRIVACY_INCOMPLETE
    content_provider_stop_control_observer || fail PROVIDER_HTTPS_CONTROL_CAPTURE_INCOMPLETE
    ph_output_digest=$(sha256sum "$ph_output" | awk '{print $1}')
    # The existing output is refused by the caller before another origin/control request.
    if content_provider_https_cli content fetch-https --url https://destination.volparossa.test:18443/asset.bin \
        --metadata-path /.well-known/volparossa/content/asset --ca-file "$ph_user/origin.pem" \
        --cache "$ph_cache" --local-output "$ph_output" \
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

content_provider_https_run() {
    PHASE=content-provider-https-origin-seed
    ph_binary=$binary_directory/examples/https-content-acceptance-fixture
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
        --no-new-privs -- "$ph_binary" origin-pem "$ph_origin_root" 47.163.4.2:18443 \
        "$WORK/destination/content-provider-https-origin.pem" "$ph_origin_report" 6 \
        >"$WORK/content-provider-https-origin.log" 2>&1 &
    TLS_POLICY_SERVER_PID=$!
    wait_observer "$TLS_POLICY_SERVER_PID" "$ph_origin_report.ready" \
        || fail PROVIDER_HTTPS_ORIGIN_NOT_READY
    # This explicit public fixture CA is read by the normal CLI. No TLS bypass, host trust
    # installation, publisher-key argument or pre-fetched descriptor enters fetch-https.
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
        "$WORK/destination/content-provider-https-origin.pem" "$ph_user/origin.pem"

    content_provider_https_phase complete
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

    ph_origin_status=0
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
