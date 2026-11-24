#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Disposable two-participant trial. Each app receives only its own ordinary Core socket.
# shellcheck disable=SC2154,SC2034

paired_peer_actor() {
    case $1 in
        sender) peer_role=sender; peer_node=client; peer_ns=$CLIENT; peer_other=relay4; peer_uid=$WORKER_UID; peer_gid=$WORKER_GID ;;
        recipient) peer_role=recipient; peer_node=relay4; peer_ns=$R4; peer_other=client; peer_uid=$(id -u mail); peer_gid=$(id -g mail) ;;
        *) return 1 ;;
    esac
    peer_home=$WORK/paired-mail-private-$peer_role
    peer_socket=$WORK/runtime-$peer_node/control/agent.sock
    peer_bin=$WORK/bin/paired-mail-cli-$peer_role
}

paired_peer_app() {
    paired_peer_actor "$1"; peer_op=$2; shift 2
    case $peer_op in init|pair) peer_out=paired-mail-peers-$peer_role-$peer_op ;; *) peer_out=paired-mail-peers-$peer_op ;; esac
    PHASE=paired-mail-peers-$peer_role-$peer_op
    [ "$(stat -Lc '%g' "$peer_socket")" = "$mailbox_control_gid" ] || fail PAIRED_MAIL_SOCKET_GROUP_INVALID
    timeout --signal=TERM --kill-after=10s 700s ip netns exec "$peer_ns" setpriv --reuid="$peer_uid" --regid="$peer_gid" \
        --groups="$mailbox_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
        python3 -I -B "$WORK/bin/paired-mail-peer-sandbox.py" "$peer_home" "$peer_bin" "$peer_socket" \
        "$peer_role" "$peer_op" "$@" >"$WORK/$peer_out.json" || fail PAIRED_MAIL_PEER_APPLICATION_FAILED
}

paired_peer_remove() {
    paired_peer_actor "$1"
    [ ! -L "$peer_home" ] || return 1
    [ -e "$peer_home" ] || return 0
    [ "$(stat -Lc '%u:%g:%a' "$peer_home")" = "$peer_uid:$peer_gid:700" ] || return 1
    setpriv --reuid="$peer_uid" --regid="$peer_gid" --clear-groups --inh-caps=-all --ambient-caps=-all \
        --bounding-set=-all --no-new-privs -- python3 -I -B - "$peer_home" <<'PY' || return 1
import os, shutil, stat, sys
assert shutil.rmtree.avoids_symlink_attacks
fd=os.open(sys.argv[1],os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    for name in os.listdir(fd):
        item = os.stat(name,dir_fd=fd,follow_symlinks=False)
        if name not in {"app","store"} or not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid():
            raise ValueError("unexpected participant state")
        shutil.rmtree(name,dir_fd=fd)
finally:
    os.close(fd)
PY
    rmdir "$peer_home"
}

paired_mail_peers_cleanup() {
    for peer_pid in ${PAIRED_OBSERVERS:-}; do kill -TERM "$peer_pid" 2>/dev/null || true; done
    for peer_pid in ${PAIRED_OBSERVERS:-}; do wait "$peer_pid" 2>/dev/null || true; done
    PAIRED_OBSERVERS=
    if [ "${PAIRED_PRIVATE_CREATED:-no}" = yes ]; then
        paired_peer_remove sender && paired_peer_remove recipient || return 1
    fi
}

paired_peer_offline() {
    paired_peer_actor "$1"
    content_mailbox_cli "$peer_node" status >"$WORK/paired-peer-offline-status" || fail PAIRED_MAIL_PEER_STATUS_FAILED
    if ! grep -Fx 'connected: false' "$WORK/paired-peer-offline-status" >/dev/null ||
        ! grep -Fx 'active contexts: 0' "$WORK/paired-peer-offline-status" >/dev/null; then
        content_replication_disconnect "$peer_node" "paired-mail-peers-$peer_role-offline-$2" || fail PAIRED_MAIL_PEER_DISCONNECT_FAILED
    fi
    retire_unit "volparossa-alpha-agent@$peer_node.service" || fail PAIRED_MAIL_PEER_STOP_FAILED
    peer_wait=0
    while [ "$peer_wait" -lt 100 ] && [ "$(unit_load_state "volparossa-alpha-agent@$peer_node.service")" != not-found ]; do
        peer_wait=$((peer_wait + 1)); sleep 0.1
    done
    [ "$(unit_load_state "volparossa-alpha-agent@$peer_node.service")" = not-found ] || fail PAIRED_MAIL_PEER_NOT_OFFLINE
    if content_mailbox_cli "$peer_node" status >/dev/null 2>&1; then fail PAIRED_MAIL_OFFLINE_SOCKET_ACCEPTED; fi
}

paired_peer_online() {
    paired_peer_actor "$1"
    launch_agent "$peer_node" "$peer_ns"
    peer_wait=0
    while [ "$peer_wait" -lt 300 ]; do
        if [ -S "$peer_socket" ] && content_mailbox_cli "$peer_node" role show >"$WORK/peer-role-$peer_node" 2>/dev/null \
            && grep -Fx 'client: true' "$WORK/peer-role-$peer_node" >/dev/null; then return 0; fi
        peer_wait=$((peer_wait + 1)); sleep 0.1
    done
    fail PAIRED_MAIL_PEER_START_FAILED
}

paired_peer_route() {
    paired_peer_actor "$1"; peer_phase=$2; peer_prefix=paired-mail-peers-$peer_phase
    PHASE=$peer_prefix-route
    # A restarted agent's role bit is available before peer discovery is ready.
    # The ordinary selector still chooses the control and two data relays.
    peer_discovery_deadline=$(($(date +%s) + 60))
    while ! { CONTENT_REPLICATION_COMMAND_TIMEOUT=2s content_replication_cli "$peer_node" peers \
            >"$WORK/$peer_prefix-peers.private" &&
        awk -v a="$R0_PEER" -v b="$R1_PEER" -v c="$R2_PEER" '
            ($1 == a || $1 == b || $1 == c) && $2 == "roles=0b010" { seen[$1] = 1 }
            END { exit !(seen[a] && seen[b] && seen[c]) }' "$WORK/$peer_prefix-peers.private"; }; do
        [ "$(date +%s)" -lt "$peer_discovery_deadline" ] || fail PAIRED_MAIL_PEER_RELAY_DISCOVERY_UNAVAILABLE
        sleep 1
    done
    content_replication_select "$peer_node" "$peer_prefix" || fail PAIRED_MAIL_PEER_ROUTE_UNAVAILABLE
    peer_context=$(jq -er '.route_context_id' "$WORK/$peer_prefix-selection.json")
    content_mailbox_cli "$peer_node" content status >"$WORK/$peer_prefix-status.json" || fail PAIRED_MAIL_PEER_ROUTE_STATUS_FAILED
    provider_control_peer=$(jq -er '.control_relay_peer_id | select(length > 0)' "$WORK/$peer_prefix-status.json")
    jq -e --arg p "$provider_control_peer" '[.relay0,.relay1,.relay2]|index($p) != null' "$WORK/a01-expected-peers.json" >/dev/null \
        || fail PAIRED_MAIL_PEER_CONTROL_INVALID
    if [ -z "${mailbox_previous_control:-}" ]; then content_provider_control_underlay; else content_mailbox_rebind_control; fi
    mailbox_previous_control=$provider_control_peer
}

paired_peer_begin() {
    content_provider_start_control_observer "content-provider-mail-peers-$peer_phase-control" || fail PAIRED_MAIL_PEER_CONTROL_OBSERVER_FAILED
    PAIRED_OBSERVERS=
    for peer_sensor in client relay4 exit; do
        case $peer_sensor in client) peer_capture_ns=$CLIENT ;; relay4) peer_capture_ns=$R4 ;; exit) peer_capture_ns=$EXIT_NODE ;; esac
        peer_file=$WORK/$peer_prefix-$peer_sensor
        ip netns exec "$peer_capture_ns" python3 -I -B "$WORK/bin/paired-mail-peer-capture.py" capture \
            "$peer_phase" "$peer_sensor" "$peer_file.json" "$peer_file.ready" >"$peer_file.log" 2>&1 &
        peer_pid=$!; PAIRED_OBSERVERS="$PAIRED_OBSERVERS $peer_pid"
        wait_observer "$peer_pid" "$peer_file.ready" || fail PAIRED_MAIL_PEER_OBSERVER_UNAVAILABLE
    done
    provider_baseline_ms=$(date +%s%3N); sleep 0.01
}

paired_peer_finish() {
    PHASE=$peer_prefix-measure
    content_replication_snapshot "$peer_node" "$peer_prefix-live" || fail PAIRED_MAIL_PEER_ROUTE_CHANGED
    jq -e --arg initial "$peer_context" '.route_context_id == $initial' "$WORK/$peer_prefix-live-selection.json" >/dev/null \
        || fail PAIRED_MAIL_PEER_ROUTE_CHANGED
    for peer_pid in $PAIRED_OBSERVERS; do kill -TERM "$peer_pid" || fail PAIRED_MAIL_PEER_OBSERVER_STOP_FAILED; done
    for peer_pid in $PAIRED_OBSERVERS; do wait "$peer_pid" || fail PAIRED_MAIL_PEER_OBSERVER_DRAIN_FAILED; done
    PAIRED_OBSERVERS=
    content_provider_stop_control_observer || fail PAIRED_MAIL_PEER_CONTROL_DRAIN_FAILED
    peer_wait=0
    while [ "$peer_wait" -lt 60 ]; do
        for peer_log in exit "$provider_control_node"; do
            # The guest observer reads these service-private rings. Neither Mail
            # participant has permission to traverse the Exit or relay runtime.
            CONTENT_REPLICATION_COMMAND_TIMEOUT=5s content_replication_cli "$peer_log" logs --limit 400 \
                >"$WORK/logs-$peer_log.txt" || fail PAIRED_MAIL_PEER_LOG_FAILED
        done
        peer_flows=$(content_provider_event_count exit MPTCP_EXIT_FLOW_COMPLETED)
        peer_lookups=$(content_provider_event_count "$provider_control_node" CONTENT_EXACT_LOOKUP_FINISHED)
        [ "$peer_flows" -lt "$1" ] || [ "$peer_lookups" -lt "$1" ] || break
        peer_wait=$((peer_wait + 1)); sleep 0.1
    done
    peer_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$peer_node.service")
    [ "$peer_pid" -gt 0 ] && [ "$(unit_load_state "volparossa-alpha-agent@$peer_other.service")" = not-found ] \
        && [ "$(stat -Lc %i "/proc/$peer_pid/ns/net")" = "$(stat -Lc %i "/run/netns/$peer_ns")" ] || fail PAIRED_MAIL_PEER_ISOLATION_FAILED
    for peer_hidden in "$WORK/state-$provider_node_a/mailbox-cache" "$WORK/state-$provider_node_b/mailbox-cache" \
        "$WORK/state-$peer_other/identity.key"; do
        if nsenter -t "$peer_pid" -m setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- test -r "$peer_hidden"; then fail PAIRED_MAIL_PEER_STATE_EXPOSED; fi
    done
    nsenter -t "$peer_pid" -m setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups --inh-caps=-all \
        --ambient-caps=-all --bounding-set=-all --no-new-privs -- test -r "$WORK/state-$peer_node/identity.key" || fail PAIRED_MAIL_PEER_POSITIVE_CONTROL_FAILED
    content_mailbox_cli "$peer_node" role show >"$WORK/peer-role-$peer_node" && grep -Fx 'client: true' "$WORK/peer-role-$peer_node" >/dev/null || fail PAIRED_MAIL_PEER_CLIENT_ROLE_MISSING
    if content_mailbox_cli "$peer_other" status >/dev/null 2>&1; then fail PAIRED_MAIL_OFFLINE_SOCKET_ACCEPTED; fi
    jq -cn --arg a "$peer_node" --arg i "$peer_other" --arg c "$provider_control_peer" --argjson pid "$peer_pid" \
        --argjson uid "$peer_uid" --argjson ns "$(stat -Lc %i "/run/netns/$peer_ns")" --argjson sock "$(stat -Lc %i "$peer_socket")" \
        --argjson t "$provider_baseline_ms" --argjson f "$peer_flows" --argjson l "$peer_lookups" \
        '{client_role_verified:true,own_agent_key_readable:true,other_agent_key_hidden:true,provider_caches_hidden:true,offline_socket_unavailable:true,
          active_node:$a,inactive_node:$i,inactive_pid:0,active_pid:$pid,application_uid:$uid,active_netns:$ns,active_socket:$sock,
          event_baseline_unix_ms:$t,exit_mptcp_tls_completed:$f,exact_provider_lookups:$l,control_relay_peer_id:$c}' >"$WORK/$peer_prefix-gates.json"
    [ "$peer_flows" -ge "$1" ] && [ "$peer_lookups" -ge "$1" ] || fail PAIRED_MAIL_PEER_PROTECTED_FLOW_INCOMPLETE
}

paired_peer_exchange() {
    from_role=$1; to_role=$2
    case $3:$4 in public.bundle:peer.bundle|invitation:invitation) ;; *) return 1 ;; esac
    paired_peer_actor "$from_role"; exchange_source=$peer_home/app/$3
    [ ! -L "$exchange_source" ] && [ -f "$exchange_source" ] && [ "$(stat -Lc '%u:%a' "$exchange_source")" = "$peer_uid:600" ] \
        && [ "$(stat -Lc '%s' "$exchange_source")" -le 16384 ] || return 1
    paired_peer_actor "$to_role"
    [ ! -e "$peer_home/app/$4" ] && [ ! -L "$peer_home/app/$4" ] || return 1
    install -o "$peer_uid" -g "$peer_gid" -m 0600 "$exchange_source" "$peer_home/app/$4"
    cmp -s "$exchange_source" "$peer_home/app/$4"
}

paired_mail_peers_run() {
    PHASE=paired-mail-peers-prepare
    paired_peer_actor recipient
    [ "$peer_uid" != "$WORKER_UID" ] && [ "$peer_uid" != "$AGENT_UID" ] && [ "$peer_uid" -gt 0 ] || fail PAIRED_MAIL_PEER_UID_INVALID
    mailbox_control_gid=$(getent group volparossa-users | cut -d: -f3)
    for peer_file in paired-mail-peer-capture.py content-replication-capture.py paired-mail-guest.py paired-mail-sandbox.py \
        paired-mail-peer-guest.py paired-mail-peer-sandbox.py; do
        install -o root -g root -m 0444 "$source_directory/tests/integration/$peer_file" "$WORK/bin/$peer_file"
    done
    for peer_person in sender recipient; do
        paired_peer_actor "$peer_person"
        [ ! -e "$peer_home" ] && [ ! -L "$peer_home" ] && [ ! -e "$peer_bin" ] || fail PAIRED_MAIL_PEER_STATE_EXISTS
    done
    PAIRED_PRIVATE_CREATED=yes
    for peer_person in sender recipient; do
        paired_peer_actor "$peer_person"
        install -d -o "$peer_uid" -g "$peer_gid" -m 0700 "$peer_home"
        install -o "$peer_uid" -g "$peer_gid" -m 0500 "$binary_directory/volparossa" "$peer_bin"
        cmp -s "$binary_directory/volparossa" "$peer_bin" || fail PAIRED_MAIL_PEER_CLI_CHANGED
        content_mailbox_cli "$peer_node" role show >"$WORK/peer-role-$peer_node" \
            && grep -Fx 'client: true' "$WORK/peer-role-$peer_node" >/dev/null || fail PAIRED_MAIL_PEER_CLIENT_ROLE_MISSING
        peer_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$peer_node.service")
        [ "$peer_pid" -gt 0 ] && [ "$(stat -Lc %i "/proc/$peer_pid/ns/net")" = "$(stat -Lc %i "/run/netns/$peer_ns")" ] || fail PAIRED_MAIL_PEER_ISOLATION_FAILED
        jq -cn --argjson pid "$peer_pid" --argjson uid "$peer_uid" --argjson sock "$(stat -Lc %i "$peer_socket")" \
            --argjson ns "$(stat -Lc %i "/run/netns/$peer_ns")" '{pid:$pid,socket:$sock,netns:$ns,uid:$uid}' >"$WORK/paired-peer-initial-$peer_node.json"
        paired_peer_app "$peer_person" init
    done
    sender_key=$(jq -er '.core_key' "$WORK/paired-mail-peers-sender-init.json")
    recipient_key=$(jq -er '.core_key' "$WORK/paired-mail-peers-recipient-init.json")
    for peer_person in sender recipient; do
        if [ "$peer_person" = sender ]; then other_person=recipient; else other_person=sender; fi
        paired_peer_exchange "$other_person" "$peer_person" public.bundle peer.bundle || fail PAIRED_MAIL_PEER_BUNDLE_FAILED
        paired_peer_app "$peer_person" pair "$(jq -er '.core_key' "$WORK/paired-mail-peers-$other_person-init.json")" \
            "$(jq -er '.signal_bundle_sha256' "$WORK/paired-mail-peers-$other_person-init.json")"
    done
    paired_peer_offline sender initial
    provider_node_a=relay3; provider_node_b=relay5
    paired_peer_route recipient enroll
    content_mailbox_open_providers
    paired_peer_begin
    paired_peer_app recipient enroll "$sender_key" "$mailbox_key_a" "$mailbox_key_b"
    paired_peer_finish 2
    paired_peer_exchange recipient sender invitation invitation || fail PAIRED_MAIL_PEER_INVITATION_FAILED
    paired_peer_offline recipient after-enroll
    paired_peer_online sender
    paired_peer_route sender send
    paired_peer_begin
    paired_peer_app sender send "$recipient_key"
    paired_peer_finish 2
    paired_peer_remove sender || fail PAIRED_MAIL_SENDER_CLEANUP_FAILED
    paired_peer_offline sender after-send
    content_mailbox_reopen_provider
    paired_peer_online recipient
    paired_peer_route recipient receive
    paired_peer_begin
    paired_peer_app recipient receive
    paired_peer_finish 7
    paired_peer_remove recipient || fail PAIRED_MAIL_RECIPIENT_CLEANUP_FAILED
    content_replication_disconnect relay4 paired-mail-peers-finished || fail PAIRED_MAIL_PEER_DISCONNECT_FAILED
    for peer_provider in "$provider_node_a" "$provider_node_b"; do
        content_mailbox_cli "$peer_provider" content stop >"$WORK/peer-$peer_provider-stop.json" || fail PAIRED_MAIL_PROVIDER_STOP_FAILED
        jq -e '.serving == false' "$WORK/peer-$peer_provider-stop.json" >/dev/null || fail PAIRED_MAIL_PROVIDER_STILL_SERVING
    done
    jq -ce --arg a "$mailbox_key_a" --arg b "$mailbox_key_b" --slurpfile sender "$WORK/paired-peer-initial-client.json" \
        --slurpfile recipient "$WORK/paired-peer-initial-relay4.json" 'select(.provider_node == "relay5" and .stop.serving == false
        and .reopen.serving == true and .reuse_cache == true and .cache_mode == "0700" and .listener_absent_between == true)
        | {participants:{client:$sender[0],relay4:$recipient[0]},provider_keys:{relay3:$a,relay5:$b},reopened_provider:.provider_node,cache_inode_before,cache_inode_after,
           listener_absent_between,sender_private_removed:true,recipient_private_removed:true}' "$WORK/content-mailbox-restart.json" \
        >"$WORK/paired-mail-peers-lifecycle.json" || fail PAIRED_MAIL_PEER_CACHE_NOT_REOPENED
    PHASE=paired-mail-peers-complete
    OBSERVED_BLOCKER=NONE
}

paired_mail_peers_finalize() {
    peer_verifier=$source_directory/tests/integration/paired-mail-peers-smoke.py
    peer_status=$1
    if [ -f /var/tmp/volparossa-paired-mail-runtime/paired-mail-supply.json ]; then
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 /var/tmp/volparossa-paired-mail-runtime/paired-mail-supply.json \
            "$WORK/paired-mail-supply.json" || return 1
    fi
    for peer_file in $(python3 -I -B "$peer_verifier" export-names); do
        case $peer_file in paired-mail-peers-smoke.json) continue ;; esac
        if [ -f "$WORK/$peer_file" ] && [ ! -L "$WORK/$peer_file" ]; then
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/$peer_file" "$output_directory/$peer_file" || return 1
        fi
    done
    python3 -I -B "$peer_verifier" assemble "$output_directory" "$expected_commit" "$peer_status" "$OBSERVED_BLOCKER" \
        "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "${host_before_sha256:-}" "${host_after_sha256:-}" \
        >"$WORK/paired-mail-peers-report.part" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/paired-mail-peers-report.part" "$output_directory/paired-mail-peers-smoke.json" || return 1
    python3 -I -B "$peer_verifier" report "$output_directory/paired-mail-peers-smoke.json" "$expected_commit"
}
