#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced after native provider retrieval inside the disposable, exact-build KVM guest.
# shellcheck disable=SC2154,SC2034

content_provider_https_phase() {
    ph_case=$1
    ph_prefix=content-provider-https-$ph_case
    ph_cache=$provider_client/https-$ph_case-cache
    ph_output=$provider_client/https-$ph_case-object.bin
    PHASE=$ph_prefix-capture
    if [ -e "$ph_cache" ] || [ -e "$ph_output" ]; then
        fail PROVIDER_HTTPS_CACHE_NOT_EMPTY
    fi
    start_privacy_observers "$ph_prefix-privacy" || fail PROVIDER_HTTPS_PRIVACY_UNAVAILABLE
    content_provider_start_control_observer "$ph_prefix-control" \
        || fail PROVIDER_HTTPS_CONTROL_CAPTURE_UNAVAILABLE

    PHASE=$ph_prefix-fetch
    timeout --signal=TERM --kill-after=5s 120s "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch-https --url https://destination.volparossa.test:18443/asset.bin \
        --metadata-path /.well-known/volparossa/content/asset \
        --ca-file "$provider_client/https-origin.pem" \
        --cache "$ph_cache" --output "$ph_output" \
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
    jq -n --arg sha256 "$(sha256sum "$ph_output" | awk '{print $1}')" \
        --argjson bytes "$(stat -Lc '%s' "$ph_output")" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          client_mount_cannot_read_origin:true}' >"$WORK/$ph_prefix-output.json"
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
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 \
        "$WORK/destination/content-provider-https-origin.pem" "$provider_client/https-origin.pem"

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
    python3 -B "$source_directory/tests/integration/content-provider-https-smoke.py" \
        evidence "$WORK" "$WORK/content-provider-https-evidence.json" \
        || fail PROVIDER_HTTPS_EVIDENCE_INVALID
    PHASE=content-provider-https-complete
}
