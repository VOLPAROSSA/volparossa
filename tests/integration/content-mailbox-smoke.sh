#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicitly approved disposable KVM topology.
# Two independent application identities share one Client agent, never two claimed client nodes.
# shellcheck disable=SC2154,SC2034

content_mailbox_cli() {
    mailbox_cli_node=$1
    shift
    timeout --signal=TERM --kill-after=5s 180s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$mailbox_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$mailbox_cli_node/control/agent.sock" "$@"
}

content_mailbox_endpoint() {
    case $1 in
        relay4) mailbox_address=49.165.5.1; mailbox_hostname=provider-a.volparossa.test ;;
        relay5) mailbox_address=50.166.6.1; mailbox_hostname=provider-b.volparossa.test ;;
        relay3) mailbox_address=48.164.4.1; mailbox_hostname=provider-c.volparossa.test ;;
        *) return 1 ;;
    esac
    content_provider_node "$1"
}

content_mailbox_remove_private() {
    case $1 in sender|owner) ;; *) return 1 ;; esac
    mailbox_private=$WORK/client-fixtures/mailbox/$1
    [ ! -L "$mailbox_private" ] || return 1
    if [ -e "$mailbox_private" ]; then
        [ -d "$mailbox_private" ] \
            && [ "$(stat -Lc '%a:%u:%g' "$mailbox_private")" = "700:$WORKER_UID:$WORKER_GID" ] || return 1
        for mailbox_secret in identity.key passphrase input.bin; do
            mailbox_secret=$mailbox_private/$mailbox_secret
            [ ! -L "$mailbox_secret" ] || return 1
            if [ -e "$mailbox_secret" ]; then
                [ -f "$mailbox_secret" ] \
                    && [ "$(stat -Lc '%a:%u:%g' "$mailbox_secret")" = "600:$WORKER_UID:$WORKER_GID" ] || return 1
                rm -f -- "$mailbox_secret" || return 1
            fi
        done
        rmdir -- "$mailbox_private" || return 1
    fi
}

content_mailbox_cleanup() {
    content_mailbox_remove_private sender || return 1
    content_mailbox_remove_private owner || return 1
    # Only regular, opaque fixture outputs in the two exact newly created directories.
    for mailbox_output in "$WORK/client-fixtures/mailbox/received" "$WORK/client-fixtures/mailbox/empty"; do
        [ ! -L "$mailbox_output" ] || return 1
        if [ -e "$mailbox_output" ]; then
            [ -d "$mailbox_output" ] \
                && [ "$(stat -Lc '%a:%u:%g' "$mailbox_output")" = "700:$WORKER_UID:$WORKER_GID" ] || return 1
            for mailbox_file in "$mailbox_output"/*; do
                [ ! -e "$mailbox_file" ] && [ ! -L "$mailbox_file" ] && continue
                basename -- "$mailbox_file" | grep -Eq '^[0-9a-f]{64}$' || return 1
                [ ! -L "$mailbox_file" ] && [ -f "$mailbox_file" ] \
                    && [ "$(stat -Lc '%a:%u:%g' "$mailbox_file")" = "600:$WORKER_UID:$WORKER_GID" ] || return 1
                rm -f -- "$mailbox_file" || return 1
            done
            rmdir -- "$mailbox_output" || return 1
        fi
    done
    jq -n '{sender_secrets_removed:true,owner_secrets_removed:true,plaintext_outputs_removed:true}' \
        >"$WORK/content-mailbox-private-cleanup.json"
}

content_mailbox_identity() {
    mailbox_identity_role=$1
    mailbox_identity_root=$mailbox_user/$mailbox_identity_role
    # shellcheck disable=SC2016 # The exact private path is positional in the unprivileged shell.
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- sh -eu -c 'umask 077; mkdir -m 0700 -- "$1"; set -C;
            head -c 48 /dev/urandom | base64 > "$1/passphrase"' sh "$mailbox_identity_root" \
        >"$WORK/content-mailbox-$mailbox_identity_role-init.log" 2>&1 \
        || fail MAILBOX_PRIVATE_IDENTITY_STATE_FAILED
    content_mailbox_cli client init --identity "$mailbox_identity_root/identity.key" \
        --passphrase-file "$mailbox_identity_root/passphrase" \
        >>"$WORK/content-mailbox-$mailbox_identity_role-init.log" 2>&1 || fail MAILBOX_IDENTITY_FAILED
    content_mailbox_cli client content recipient-key --identity "$mailbox_identity_root/identity.key" \
        --passphrase-file "$mailbox_identity_root/passphrase" \
        >"$WORK/content-mailbox-$mailbox_identity_role-public.json" \
        2>"$WORK/content-mailbox-$mailbox_identity_role-public.err" || fail MAILBOX_PUBLIC_KEY_FAILED
}

content_mailbox_route() {
    mailbox_route_phase=$1
    benchmark_select_route "content-mailbox-$mailbox_route_phase" mptcp || fail MAILBOX_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-mailbox-$mailbox_route_phase-selection.json" || fail MAILBOX_ROUTE_INVALID
    content_mailbox_cli client content status >"$WORK/content-mailbox-$mailbox_route_phase-status.json" \
        2>"$WORK/content-mailbox-$mailbox_route_phase-status.err" || fail MAILBOX_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' \
        "$WORK/content-mailbox-$mailbox_route_phase-status.json") || fail MAILBOX_CONTROL_INVALID
    if [ "$mailbox_route_phase" = send ]; then
        provider_nodes=$(jq -cer --arg control "$provider_control_peer" '
            . as $peers | ["relay4","relay5","relay3"]
            | map(select($peers[.] != $control)) | .[:2] | select(length == 2)' \
            "$WORK/a01-expected-peers.json") || fail MAILBOX_PROVIDERS_INVALID
        provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
        provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
        content_provider_control_underlay
    else
        jq -e --arg peer "$provider_control_peer" --arg a "$provider_node_a" --arg b "$provider_node_b" \
            '.[$a] != $peer and .[$b] != $peer' "$WORK/a01-expected-peers.json" >/dev/null \
            || fail MAILBOX_RECEIVER_CONTROL_IS_PROVIDER
        if [ "$provider_control_peer" != "$mailbox_previous_control" ]; then
            # Remove only the exact fixture-owned control links after the previous capture drained.
            # Their peer ends and /32 routes disappear with the interfaces; other links remain.
            for mailbox_link in 0 1; do
                ip -n "$provider_control_ns" link del "cp$mailbox_link" || fail MAILBOX_CONTROL_LINK_CLEANUP_FAILED
                ip netns exec "$provider_control_ns" nft delete table inet "vpa_content_control_$mailbox_link" \
                    || fail MAILBOX_CONTROL_FILTER_CLEANUP_FAILED
                if [ "$mailbox_link" = 0 ]; then mailbox_old_node=$provider_node_a
                else mailbox_old_node=$provider_node_b; fi
                content_provider_node "$mailbox_old_node" || fail MAILBOX_PROVIDER_INVALID
                ip netns exec "$provider_ns" nft delete table inet "vpa_content_control_$mailbox_link" \
                    || fail MAILBOX_CONTROL_FILTER_CLEANUP_FAILED
            done
            content_provider_control_underlay
        fi
    fi
    mailbox_previous_control=$provider_control_peer
    mailbox_phase_context=$(jq -er '.route_context_id' "$WORK/content-mailbox-$mailbox_route_phase-selection.json")
}

content_mailbox_serve() {
    mailbox_serve_node=$1; mailbox_serve_report=$2; mailbox_reuse=$3
    content_mailbox_endpoint "$mailbox_serve_node" || fail MAILBOX_PROVIDER_INVALID
    set --
    [ "$mailbox_reuse" != yes ] || set -- --reuse-cache
    content_mailbox_cli "$mailbox_serve_node" content mailbox serve \
        --bind "$mailbox_address:18080" --advertised-hostname "$mailbox_hostname" \
        --cache "$WORK/state-$mailbox_serve_node/mailbox-cache" --quota-bytes 16777216 --max-entries 64 "$@" \
        >"$WORK/content-mailbox-$mailbox_serve_report.json" \
        2>"$WORK/content-mailbox-$mailbox_serve_report.err" || fail MAILBOX_SERVE_FAILED
    jq -e '.serving == true and .replication_enabled == false' \
        "$WORK/content-mailbox-$mailbox_serve_report.json" >/dev/null || fail MAILBOX_SERVE_NOT_ACTIVE
}

content_mailbox_phase_start() {
    mailbox_phase=$1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail MAILBOX_EVENT_BASELINE_UNAVAILABLE
    start_privacy_observers "content-mailbox-$mailbox_phase-privacy" || fail MAILBOX_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer "content-provider-mailbox-$mailbox_phase-control" \
        || fail MAILBOX_CONTROL_CAPTURE_UNAVAILABLE
}

content_mailbox_phase_finish() {
    mailbox_expected=$1
    benchmark_capture_paths "content-mailbox-$mailbox_phase-live" mptcp || fail MAILBOX_LIVE_ROUTE_UNAVAILABLE
    jq -e --arg context "$mailbox_phase_context" '.route_context_id == $context' \
        "$WORK/content-mailbox-$mailbox_phase-live-selection.json" >/dev/null || fail MAILBOX_ROUTE_CHANGED
    stop_privacy_observers || fail MAILBOX_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail MAILBOX_CONTROL_CAPTURE_INCOMPLETE
    mailbox_poll=0
    while [ "$mailbox_poll" -lt 50 ]; do
        capture_product_logs
        mailbox_exit_count=$(content_provider_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        mailbox_exact_count=$(content_provider_event_count "$provider_control_node" CONTENT_EXACT_LOOKUP_FINISHED)
        [ "$mailbox_exit_count" -lt "$mailbox_expected" ] || [ "$mailbox_exact_count" -lt "$mailbox_expected" ] || break
        mailbox_poll=$((mailbox_poll + 1)); sleep 0.1
    done
    jq -n --argjson baseline "$provider_baseline_ms" --argjson completed "$mailbox_exit_count" \
        --argjson lookups "$mailbox_exact_count" \
        '{event_baseline_unix_ms:$baseline,exit_mptcp_tls_completed:$completed,exact_provider_lookups:$lookups}' \
        >"$WORK/content-mailbox-$mailbox_phase-gates.json"
    if [ "$mailbox_exit_count" -lt "$mailbox_expected" ] || [ "$mailbox_exact_count" -lt "$mailbox_expected" ]; then
        fail MAILBOX_REAL_PROTECTED_FLOW_NOT_COMPLETED
    fi
}

content_mailbox_run() {
    PHASE=content-mailbox-prepare
    mailbox_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $mailbox_control_gid in ''|*[!0-9]*) fail MAILBOX_CONTROL_GROUP_INVALID ;; esac
    [ "$mailbox_control_gid" != "$AGENT_GID" ] || fail MAILBOX_CONTROL_GROUP_INVALID
    mailbox_user=$WORK/client-fixtures/mailbox
    if [ -e "$mailbox_user" ] || [ -L "$mailbox_user" ]; then fail MAILBOX_USER_STATE_NOT_NEW; fi
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$mailbox_user"
    content_mailbox_identity sender
    content_mailbox_identity owner
    mailbox_sender=$(jq -er '.identity_public_key_hex | select(test("^[0-9a-f]{64}$"))' "$WORK/content-mailbox-sender-public.json")
    mailbox_owner=$(jq -er '.identity_public_key_hex | select(test("^[0-9a-f]{64}$"))' "$WORK/content-mailbox-owner-public.json")
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-mailbox-smoke.py" input "$mailbox_user/sender/input.bin" \
        || fail MAILBOX_INPUT_FAILED
    content_mailbox_route send
    mailbox_sender_context=$mailbox_phase_context
    for mailbox_node in "$provider_node_a" "$provider_node_b"; do
        # Independently configured permanent fixture identity, never a key inferred from discovery.
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" content recipient-key \
            --identity "$WORK/state-$mailbox_node/identity.key" \
            --passphrase-file "$WORK/credential-$mailbox_node/identity-passphrase" \
            >"$WORK/content-mailbox-$mailbox_node-public.json" \
            2>"$WORK/content-mailbox-$mailbox_node-public.err" || fail MAILBOX_PROVIDER_KEY_FAILED
        content_mailbox_serve "$mailbox_node" "$mailbox_node-serve" no
        jq -n --arg node "$mailbox_node" \
            --argjson pid "$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$mailbox_node.service")" \
            --argjson inode "$(stat -Lc '%i' "$WORK/state-$mailbox_node/mailbox-cache")" \
            --arg mode "$(stat -Lc '%a' "$WORK/state-$mailbox_node/mailbox-cache")" \
            --slurpfile serve "$WORK/content-mailbox-$mailbox_node-serve.json" \
            '{node:$node,pid:$pid,cache_inode:$inode,cache_mode:$mode,serve:$serve[0]}' \
            >"$WORK/content-mailbox-$mailbox_node-state.json"
    done
    mailbox_key_a=$(jq -er '.identity_public_key_hex' "$WORK/content-mailbox-$provider_node_a-public.json")
    mailbox_key_b=$(jq -er '.identity_public_key_hex' "$WORK/content-mailbox-$provider_node_b-public.json")
    content_mailbox_cli client content mailbox invite --sender-key "$mailbox_sender" \
        --provider-key "$mailbox_key_a" --provider-key "$mailbox_key_b" \
        --invitation "$mailbox_user/invitation.bin" --max-bytes 4194304 --max-messages 4 --lifetime-seconds 3600 \
        --identity "$mailbox_user/owner/identity.key" --passphrase-file "$mailbox_user/owner/passphrase" \
        >"$WORK/content-mailbox-invite.json" 2>"$WORK/content-mailbox-invite.err" || fail MAILBOX_INVITE_FAILED
    mailbox_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $mailbox_client_pid in ''|0|*[!0-9]*) fail MAILBOX_CLIENT_PID_INVALID ;; esac
    nsenter --target "$mailbox_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail MAILBOX_POSITIVE_ISOLATION_PROBE_FAILED
    for mailbox_hidden in "$mailbox_user" "$WORK/state-$provider_node_a/mailbox-cache" \
        "$WORK/state-$provider_node_b/mailbox-cache"; do
        if nsenter --target "$mailbox_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$mailbox_hidden"; then fail MAILBOX_LOCAL_SECRET_OR_PROVIDER_SHORTCUT; fi
    done
    PHASE=content-mailbox-send
    content_mailbox_phase_start send
    content_mailbox_cli client content mailbox enroll --invitation "$mailbox_user/invitation.bin" \
        --identity "$mailbox_user/owner/identity.key" --passphrase-file "$mailbox_user/owner/passphrase" \
        >"$WORK/content-mailbox-enroll.json" 2>"$WORK/content-mailbox-enroll.err" || fail MAILBOX_ENROLL_FAILED
    content_mailbox_cli client content mailbox send --invitation "$mailbox_user/invitation.bin" \
        --owner-key "$mailbox_owner" --input "$mailbox_user/sender/input.bin" \
        --cache "$mailbox_user/ciphertext-cache" --manifest "$mailbox_user/sender-manifest.bin" \
        --identity "$mailbox_user/sender/identity.key" --passphrase-file "$mailbox_user/sender/passphrase" \
        --quota-bytes 16777216 --max-entries 64 --lifetime-seconds 1800 \
        >"$WORK/content-mailbox-send.json" 2>"$WORK/content-mailbox-send.err" || fail MAILBOX_SEND_FAILED
    content_mailbox_phase_finish 4
    content_mailbox_remove_private sender || fail MAILBOX_SENDER_PRIVATE_CLEANUP_FAILED
    if [ -L "$mailbox_user/sender-manifest.bin" ] || [ ! -f "$mailbox_user/sender-manifest.bin" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$mailbox_user/sender-manifest.bin")" != "600:$WORKER_UID:$WORKER_GID" ]; then
        fail MAILBOX_SENDER_MANIFEST_TARGET_INVALID
    fi
    rm -- "$mailbox_user/sender-manifest.bin" || fail MAILBOX_SENDER_MANIFEST_REMOVAL_FAILED
    benchmark_disconnect_route content-mailbox-sender || fail MAILBOX_SENDER_ROUTE_CLEANUP_FAILED
    PHASE=content-mailbox-provider-reopen
    mailbox_inode=$(stat -Lc '%i' "$WORK/state-$provider_node_b/mailbox-cache")
    content_mailbox_cli "$provider_node_b" content stop >"$WORK/content-mailbox-restart-stop.json" \
        2>"$WORK/content-mailbox-restart-stop.err" || fail MAILBOX_PROVIDER_STOP_FAILED
    content_mailbox_endpoint "$provider_node_b" || fail MAILBOX_PROVIDER_INVALID
    [ -z "$(ip netns exec "$provider_ns" ss -H -ltn 'sport = :18080')" ] || fail MAILBOX_STOPPED_LISTENER_PRESENT
    content_mailbox_serve "$provider_node_b" restart-reopen yes
    jq -n --arg node "$provider_node_b" --argjson before "$mailbox_inode" \
        --argjson after "$(stat -Lc '%i' "$WORK/state-$provider_node_b/mailbox-cache")" \
        --slurpfile stop "$WORK/content-mailbox-restart-stop.json" \
        --slurpfile reopen "$WORK/content-mailbox-restart-reopen.json" \
        '{provider_node:$node,cache_inode_before:$before,cache_inode_after:$after,
          cache_mode:"0700",listener_absent_between:true,reuse_cache:true,stop:$stop[0],reopen:$reopen[0]}' \
        >"$WORK/content-mailbox-restart.json"
    content_mailbox_route receive
    [ "$mailbox_phase_context" != "$mailbox_sender_context" ] || fail MAILBOX_RECEIVER_ROUTE_NOT_FRESH
    PHASE=content-mailbox-receive
    content_mailbox_phase_start receive
    # No sender manifest, message ID, ciphertext cache, plaintext path or peer response becomes input.
    content_mailbox_cli client content mailbox receive --invitation "$mailbox_user/invitation.bin" \
        --output-dir "$mailbox_user/received" --identity "$mailbox_user/owner/identity.key" \
        --passphrase-file "$mailbox_user/owner/passphrase" --quota-bytes 16777216 --max-entries 64 \
        >"$WORK/content-mailbox-receive.json" 2>"$WORK/content-mailbox-receive.err" || fail MAILBOX_RECEIVE_FAILED
    content_mailbox_cli client content mailbox receive --invitation "$mailbox_user/invitation.bin" \
        --output-dir "$mailbox_user/empty" --identity "$mailbox_user/owner/identity.key" \
        --passphrase-file "$mailbox_user/owner/passphrase" --quota-bytes 16777216 --max-entries 64 \
        >"$WORK/content-mailbox-receive-empty.json" 2>"$WORK/content-mailbox-receive-empty.err" || fail MAILBOX_SECOND_RECEIVE_FAILED
    content_mailbox_phase_finish 7
    python3 -B "$source_directory/tests/integration/content-mailbox-smoke.py" output \
        "$mailbox_user/received" "$mailbox_user/empty" >"$WORK/content-mailbox-output-raw.json" \
        || fail MAILBOX_PLAINTEXT_INVALID
    jq '. + {sender_application_exited:true,sender_keys_and_input_removed_before_receive:true,
        sender_manifest_removed_before_receive:true,
        no_manifest_or_message_id_argument:true,agent_mount_positive_control:true,
        agent_cannot_read_user_state:true,client_cannot_read_provider_stores:true}' \
        "$WORK/content-mailbox-output-raw.json" >"$WORK/content-mailbox-output.json"
    for mailbox_node in "$provider_node_a" "$provider_node_b"; do
        [ "$(stat -Lc '%a:%u:%g' "$WORK/state-$mailbox_node/mailbox-cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
            || fail MAILBOX_PROVIDER_STORE_MODE_INVALID
        content_mailbox_cli "$mailbox_node" content stop >"$WORK/content-mailbox-$mailbox_node-stop.json" \
            2>"$WORK/content-mailbox-$mailbox_node-stop.err" || fail MAILBOX_FINAL_PROVIDER_STOP_FAILED
    done
    benchmark_disconnect_route content-mailbox-receiver || fail MAILBOX_RECEIVER_ROUTE_CLEANUP_FAILED
    content_mailbox_cleanup || fail MAILBOX_PRIVATE_CLEANUP_FAILED
    jq -n --argjson nodes "$provider_nodes" --arg a "$provider_node_a" --arg b "$provider_node_b" \
        --arg ka "$mailbox_key_a" --arg kb "$mailbox_key_b" --arg owner "$mailbox_owner" --arg sender "$mailbox_sender" \
        '{provider_nodes:$nodes,provider_keys:{($a):$ka,($b):$kb},identities:{owner:$owner,sender:$sender},
          sender_route_disconnected:true,receiver_route_disconnected:true}' >"$WORK/content-mailbox-summary.json"
    python3 -B "$source_directory/tests/integration/content-mailbox-smoke.py" evidence \
        "$WORK" "$WORK/content-mailbox-evidence.json" || fail MAILBOX_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-mailbox-complete
}

content_mailbox_finalize_report() {
    mailbox_status=$1
    for mailbox_artifact in "$WORK"/content-mailbox-*.json "$WORK"/content-mailbox-*.txt \
        "$WORK"/content-mailbox-*.log "$WORK"/content-mailbox-*.err "$WORK"/content-mailbox-*.out \
        "$WORK"/content-provider-mailbox-*.json "$WORK"/content-provider-mailbox-*.log \
        "$WORK"/content-provider-control-*.json; do
        [ ! -f "$mailbox_artifact" ] || [ -L "$mailbox_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$mailbox_artifact" \
                "$output_directory/$(basename -- "$mailbox_artifact")"
    done
    optional_json_evidence "$WORK/content-mailbox-evidence.json" >"$WORK/mailbox-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/mailbox-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" \
        --arg blocker "$OBSERVED_BLOCKER" --argjson status "$mailbox_status" \
        --slurpfile evidence "$WORK/mailbox-report-evidence.part" --slurpfile host "$WORK/mailbox-report-host.part" \
        --argjson complete "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-private-mailbox",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,mailbox:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"two signed providers; independent sender/owner applications behind one Client; sender keys removed; fresh owner route; mailbox store reopened; opaque inbox discovery/decryption/two ACKs/empty repeat",
       independent_sender_node_claimed:false,full_c07_claimed:false,full_alpha_acceptance_claimed:false}' \
        >"$WORK/content-mailbox-smoke.json" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/content-mailbox-smoke.json" \
        "$output_directory/content-mailbox-smoke.json"
    python3 -B "$source_directory/tests/integration/content-mailbox-smoke.py" report \
        "$WORK/content-mailbox-smoke.json" "$expected_commit"
}
