#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Only sourced by the explicitly approved disposable KVM topology.
# shellcheck disable=SC2154,SC2034

protected_quote_cli() {
    quote_cli_node=$1
    shift
    timeout --signal=TERM --kill-after=5s 160s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$quote_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$quote_cli_node/control/agent.sock" "$@"
}

protected_quote_public_key() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" content recipient-key \
        --identity "$WORK/state-$1/identity.key" \
        --passphrase-file "$WORK/credential-$1/identity-passphrase" \
        | jq -er '.identity_public_key_hex | select(test("^[0-9a-f]{64}$"))'
}

protected_quote_attach() {
    quote_attach_case=$1
    quote_attach_key=$2
    protected_quote_cli "$provider_node_a" compute quote attach \
        --bind "$quote_provider_address:18080" --advertised-hostname "$quote_provider_hostname" \
        --requester-key "$quote_attach_key" --max-seconds 600 --max-attempts 1 \
        >"$WORK/protected-quote-attach-$quote_attach_case.json" \
        2>"$WORK/protected-quote-attach-$quote_attach_case.err" || return 1
    jq -e '.operation == "native_content" and .serving == true and .publications == 0' \
        "$WORK/protected-quote-attach-$quote_attach_case.json" >/dev/null
}

protected_quote_case() {
    quote_case=$1
    case $quote_case in wrong|device-unavailable|repeat) ;; *) return 1 ;; esac
    # Fresh ring window, not an assumed cumulative counter. A denial counts
    # only if the actual requester reached the signed exchange boundary.
    capture_product_logs
    quote_baseline=$(client_log_baseline_ms) || return 1
    quote_status=0
    protected_quote_cli client compute quote verify --provider-key "$quote_provider_key" \
        --public-policy "$WORK/protected-quote-inputs/policy.json" \
        --vcek "$WORK/protected-quote-inputs/vcek.der" \
        --vendor-crl "$WORK/protected-quote-inputs/vendor.crl" \
        >"$WORK/protected-quote-$quote_case.json" \
        2>"$WORK/protected-quote-$quote_case.err" || quote_status=$?
    printf '%s\n' "$quote_status" >"$WORK/protected-quote-$quote_case.status"
    capture_product_logs
    quote_exchange_failures=$(client_event_count_after "$quote_baseline" \
        QUOTE_SIGNED_EXCHANGE_FAILED "$WORK/protected-quote-$quote_case-private-events.txt") || return 1
    [ "$quote_status" -eq 1 ] || return 1
    if [ "$quote_case" = device-unavailable ]; then
        [ -s "$WORK/protected-quote-$quote_case.json" ] && [ "$quote_exchange_failures" -eq 0 ] || return 1
        quote_stdout_empty=false
    else
        [ ! -s "$WORK/protected-quote-$quote_case.json" ] && [ "$quote_exchange_failures" -eq 1 ] || return 1
        quote_stdout_empty=true
    fi
    jq -n --argjson status "$quote_status" --argjson empty "$quote_stdout_empty" \
        --argjson after "$quote_exchange_failures" \
        '{exit_status:$status,stdout_empty:$empty,signed_exchange_failures_before:0,signed_exchange_failures_after:$after}' \
        >"$WORK/protected-quote-$quote_case-gate.json"
}

protected_quote_route_run() {
    PHASE=protected-quote-prepare
    quote_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $quote_control_gid in ''|0|*[!0-9]*) fail QUOTE_OPERATOR_GROUP_INVALID ;; esac
    python3 -B "$source_directory/tests/integration/protected-quote-route.py" \
        prepare "$WORK" "$source_directory" || fail QUOTE_PUBLIC_INPUT_INVALID
    # The CLI requires same-owner inputs, not merely readable collateral.
    # Transfer only these three newly created, source-pinned public fixtures to
    # the capless operator. The root-owned parent and private material are untouched.
    chmod 0755 "$WORK/protected-quote-inputs" || fail QUOTE_PUBLIC_INPUT_INVALID
    chown "$WORKER_UID:$WORKER_GID" "$WORK/protected-quote-inputs/policy.json" \
        "$WORK/protected-quote-inputs/vcek.der" "$WORK/protected-quote-inputs/vendor.crl" \
        || fail QUOTE_PUBLIC_INPUT_INVALID
    chmod 0400 "$WORK/protected-quote-inputs/policy.json" \
        "$WORK/protected-quote-inputs/vcek.der" "$WORK/protected-quote-inputs/vendor.crl" \
        || fail QUOTE_PUBLIC_INPUT_INVALID
    PHASE=protected-quote-route
    python3 -B "$WORK/bin/content-provider-readiness.py" "$WORK" \
        >"$WORK/content-provider-readiness.json" || fail QUOTE_INVENTORY_UNAVAILABLE
    benchmark_select_route protected-quote mptcp || fail QUOTE_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/protected-quote-selection.json" || fail QUOTE_ROUTE_INVALID
    install -m 0600 "$WORK/protected-quote-selection.json" "$WORK/protected-quote-selected-route.json"
    quote_context=$(jq -er '.route_context_id' "$WORK/protected-quote-selection.json")
    protected_quote_cli client content status >"$WORK/protected-quote-status-before.json" \
        2>"$WORK/protected-quote-status-before.err" || fail QUOTE_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' \
        "$WORK/protected-quote-status-before.json") || fail QUOTE_CONTROL_UNAVAILABLE
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" \
        --arg first "$BENCH_NODE1" --arg second "$BENCH_NODE2" \
        '. as $p | ["relay4","relay5","relay3"] | map(select(. != $first and . != $second and $p[.] != $control))
         | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") || fail QUOTE_PROVIDER_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    content_provider_control_underlay || fail QUOTE_CONTROL_UNDERLAY_FAILED
    content_provider_node "$provider_node_a" || fail QUOTE_PROVIDER_INVALID
    quote_provider_address=$provider_ip
    case $provider_node_a in
        relay3) quote_provider_hostname=provider-c.volparossa.test ;;
        relay4) quote_provider_hostname=provider-a.volparossa.test ;;
        relay5) quote_provider_hostname=provider-b.volparossa.test ;;
        *) fail QUOTE_PROVIDER_INVALID ;;
    esac
    quote_provider_key=$(protected_quote_public_key "$provider_node_a") || fail QUOTE_IDENTITY_UNAVAILABLE
    quote_requester_key=$(protected_quote_public_key client) || fail QUOTE_IDENTITY_UNAVAILABLE
    quote_wrong_key=$(protected_quote_public_key "$provider_node_b") || fail QUOTE_IDENTITY_UNAVAILABLE
    [ "$quote_requester_key" != "$quote_wrong_key" ] || fail QUOTE_IDENTITY_INVALID
    jq -n --argjson providers "$provider_nodes" --arg provider "$provider_node_a" \
        --arg control "$provider_control_peer" --arg key "$quote_provider_key" \
        --arg requester "$quote_requester_key" --arg wrong "$quote_wrong_key" \
        '{provider_nodes:$providers,quote_provider:$provider,control_relay_peer_id:$control,
          provider_key:$key,requester_key:$requester,wrong_requester_key:$wrong}' \
        >"$WORK/protected-quote-layout.json"
    quote_provider_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$provider_node_a.service")
    case $quote_provider_pid in ''|0|*[!0-9]*) fail QUOTE_PROVIDER_PID_INVALID ;; esac
    # Observe the same fixed path in the actual service mount, without creating,
    # opening, replacing or mocking the device. Firmware-other errors must fail.
    nsenter --target "$quote_provider_pid" --mount -- test ! -e /dev/sev-guest \
        || fail QUOTE_DEVICE_PRESENT_OR_UNKNOWN
    nsenter --target "$quote_provider_pid" --mount -- test ! -L /dev/sev-guest \
        || fail QUOTE_DEVICE_PRESENT_OR_UNKNOWN
    [ "$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$provider_node_a.service")" = "$quote_provider_pid" ] \
        || fail QUOTE_PROVIDER_CHANGED
    start_privacy_observers protected-quote-privacy || fail QUOTE_CAPTURE_FAILED
    content_provider_start_control_observer protected-quote-control-privacy || fail QUOTE_CONTROL_CAPTURE_FAILED
    PHASE=protected-quote-wrong-requester
    protected_quote_attach wrong "$quote_wrong_key" || fail QUOTE_ATTACH_FAILED
    protected_quote_case wrong || fail QUOTE_WRONG_REQUESTER_NOT_REJECTED
    protected_quote_cli "$provider_node_a" compute quote detach \
        >"$WORK/protected-quote-detach-wrong.json" 2>"$WORK/protected-quote-detach-wrong.err" || fail QUOTE_DETACH_FAILED
    PHASE=protected-quote-device-unavailable
    protected_quote_attach valid "$quote_requester_key" || fail QUOTE_ATTACH_FAILED
    protected_quote_case device-unavailable || fail QUOTE_DEVICE_REFUSAL_MISSING
    PHASE=protected-quote-exhausted
    protected_quote_case repeat || fail QUOTE_BUDGET_NOT_REJECTED
    benchmark_capture_paths protected-quote-live mptcp || fail QUOTE_LIVE_ROUTE_MISSING
    jq -e --arg context "$quote_context" '.route_context_id == $context' \
        "$WORK/protected-quote-live-selection.json" >/dev/null || fail QUOTE_ROUTE_CHANGED
    protected_quote_cli client content status >"$WORK/protected-quote-status-after.json" \
        2>"$WORK/protected-quote-status-after.err" || fail QUOTE_CONTROL_UNAVAILABLE
    jq -e --arg control "$provider_control_peer" '.control_relay_peer_id == $control' \
        "$WORK/protected-quote-status-after.json" >/dev/null || fail QUOTE_CONTROL_CHANGED
    stop_privacy_observers || fail QUOTE_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail QUOTE_CONTROL_CAPTURE_INCOMPLETE
    PHASE=protected-quote-finish
    protected_quote_cli "$provider_node_a" compute quote detach \
        >"$WORK/protected-quote-detach-valid.json" 2>"$WORK/protected-quote-detach-valid.err" || fail QUOTE_DETACH_FAILED
    protected_quote_cli "$provider_node_a" content stop >"$WORK/protected-quote-stop.json" \
        2>"$WORK/protected-quote-stop.err" || fail QUOTE_STOP_FAILED
    jq -e '.serving == false' "$WORK/protected-quote-stop.json" >/dev/null || fail QUOTE_STOP_FAILED
    benchmark_disconnect_route protected-quote || fail QUOTE_DISCONNECT_FAILED
    jq -n --slurpfile wrong "$WORK/protected-quote-wrong-gate.json" \
        --slurpfile device "$WORK/protected-quote-device-unavailable-gate.json" \
        --slurpfile repeat "$WORK/protected-quote-repeat-gate.json" \
        '{wrong:$wrong[0],device_unavailable:$device[0],repeat:$repeat[0],
          grant:{max_seconds:600,max_attempts:1,wrong_key_distinct:true,requester_key_bound:true},
          device:{provider_mount_checked:true,fixed_device_absent:true},
          detach_wrong:true,detach_valid:true,provider_stopped:true,client_disconnected:true}' \
        >"$WORK/protected-quote-gates.json"
    python3 -B "$source_directory/tests/integration/protected-quote-route.py" \
        evidence "$WORK" "$expected_commit" || fail QUOTE_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=protected-quote-complete
}

protected_quote_route_finalize_report() {
    python3 -B "$source_directory/tests/integration/protected-quote-route.py" \
        finalize "$WORK" "$output_directory" "$expected_commit" "$1" \
        "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER"
}
