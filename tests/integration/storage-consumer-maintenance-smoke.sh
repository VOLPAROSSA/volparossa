#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Called only after the original maintenance archive has been deleted in the
# disposable topology. This file does not itself enable or provision a profile.
# shellcheck disable=SC2154,SC2034

private_storage_consumer_private() {
    consumer_profile_version=${storage_consumer_profile_version-7}
    case $consumer_profile_version in 7|8|9|10) ;; *) fail CONSUMER_PROFILE_INVALID; return 1 ;; esac
    set -- "$@" --profile-version "$consumer_profile_version" --network-version 2
    case $1:${storage_fixture_correlation:-no}:$consumer_profile_version in
        publish:yes:9|exercise:yes:9|finish:yes:9|publish:yes:10|exercise:yes:10|finish:yes:10) set -- "$@" --fixture-correlation ;;
    esac
    STORAGE_PROOF_BASELINE_MS=${provider_baseline_ms:-0} \
      STORAGE_PROOF_ROUTE_SCOPE=${storage_route_scope:-} \
      STORAGE_PROOF_ROUTE_POLICY=${consumer_route_policy:-} \
      STORAGE_PROOF_UNDERLAY_SHA256=${consumer_underlay_sha:-} \
      timeout --signal=TERM --kill-after=30s 2400s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/storage-consumer-maintenance-smoke.py" "$@"
}

private_storage_consumer_phase() {
    case $1 in publish|exercise|finish) ;; *) fail CONSUMER_PHASE_INVALID ;; esac
    consumer_phase=$1
    consumer_minimum=$(python3 -B "$WORK/bin/storage-consumer-maintenance-smoke.py" \
        flow-minimum "$consumer_phase") || fail CONSUMER_FLOW_MINIMUM_INVALID
    case $consumer_minimum in ''|*[!0-9]*) fail CONSUMER_FLOW_MINIMUM_INVALID ;; esac
    PHASE=storage-consumer-$consumer_phase
    storage_consumer_phase_start || fail CONSUMER_NETWORK_START_FAILED
    consumer_status=0
    private_storage_consumer_private "$consumer_phase" "$consumer_user" \
        "$WORK/runtime-exit/control/agent.sock" "$storage_user" \
        >"$WORK/storage-consumer-$consumer_phase.json" || consumer_status=$?
    # The independent observer is already stopped/joined before this command
    # returns. Project only its closed, phase-bound private record, also on an
    # application failure. Missing/rejected diagnostics never replace that result.
    if (umask 077; python3 -B "$WORK/bin/storage-provider-activity-sampler.py" \
        "$consumer_user/private-storage-provider-activity-$consumer_phase.json" \
        "$consumer_phase" "$WORKER_UID" >"$WORK/provider-activity.part") 2>/dev/null; then
        mv -- "$WORK/provider-activity.part" "$WORK/private-storage-provider-activity.json" || true
    else
        rm -f -- "$WORK/provider-activity.part" || true
    fi
    if [ "${storage_fixture_correlation:-no}" = yes ]; then
        if (umask 077; python3 -B "$WORK/bin/storage-fixture-correlation-sampler.py" \
            "$consumer_user/private-storage-fixture-correlation-$consumer_phase.json" \
            "$consumer_phase" "$WORKER_UID" >"$WORK/fixture-correlation.part") 2>/dev/null; then
            mv -- "$WORK/fixture-correlation.part" "$WORK/private-storage-fixture-correlation.json" || true
        else
            rm -f -- "$WORK/fixture-correlation.part" || true
        fi
    fi
    [ "$consumer_status" -eq 0 ] || fail CONSUMER_APPLICATION_FAILED
    # These are independent actual route, packet/control and completion checks,
    # not an inference from the application's successful process exit.
    storage_consumer_phase_finish "$consumer_minimum" || fail CONSUMER_NETWORK_FINISH_FAILED
}

private_storage_consumer_cleanup() {
    [ "${consumer_private_cleanup_complete:-no}" != yes ] || return 0
    [ -n "${consumer_user:-}" ] || return 0
    private_storage_consumer_private cleanup "$consumer_user" \
        >"$WORK/storage-consumer-private-cleanup.json" || return 1
    # Only an empty fixture-owned parent is removed here. Provider deletion is
    # checked separately; removing private local state never proves it.
    rmdir "$WORK/u" || return 1
    consumer_private_cleanup_complete=yes
}

private_storage_consumer_run() {
    [ "${private_storage_maintenance:-no}" = yes ] || fail CONSUMER_PROFILE_INVALID
    # Do not let surviving old archives or their charges masquerade as this
    # new pair of application objects, or as their eventual cleanup.
    jq -e 'length == 3 and all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})' \
        "$WORK/private-storage-fragments-deleted_usage.json" >/dev/null \
        || fail CONSUMER_INITIAL_STORE_NOT_EMPTY
    storage_consumer_control_prepare || fail CONSUMER_CONTROL_MATRIX_FAILED
    if [ -e "$WORK/u" ] || [ -L "$WORK/u" ]; then fail CONSUMER_OWNER_PARENT_NOT_NEW; fi
    consumer_user=$WORK/u/m
    consumer_longest_socket=$consumer_user/image/restored-bundle/g-xxxxxxxx/S.gpg-agent
    [ "${#consumer_longest_socket}" -lt 104 ] || fail CONSUMER_SOCKET_PATH_TOO_LONG
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/u" "$consumer_user"
    # Recheck the actual new owner root in the current client mount namespace;
    # the older archive's probe is not evidence about this separate directory.
    consumer_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $consumer_client_pid in ''|0|*[!0-9]*) fail CONSUMER_CLIENT_PID_INVALID ;; esac
    nsenter --target "$consumer_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CONSUMER_POSITIVE_ISOLATION_FAILED
    for consumer_private in "$consumer_user" "$WORK/state-relay4/private-store" \
        "$WORK/state-relay5/private-store" "$WORK/state-relay3/private-store"; do
        if nsenter --target "$consumer_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$consumer_private"; then fail CONSUMER_LOCAL_SHORTCUT; fi
    done
    jq -n --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" \
        '{user_uid:$user,agent_uid:$agent,agent_mount_positive_control:true,
        client_cannot_read_new_owner_root:true,client_cannot_read_any_provider_store:true}' \
        >"$WORK/storage-consumer-isolation.json"
    [ -f /opt/volparossa-storage-consumers/provision.json ] \
        && [ ! -L /opt/volparossa-storage-consumers/provision.json ] \
        || fail CONSUMER_PROVISION_MISSING
    install -o root -g root -m 0600 /opt/volparossa-storage-consumers/provision.json \
        "$WORK/storage-consumer-provision.json"

    private_storage_fragments_reopen relay4 relay5 relay3
    PHASE=storage-consumer-prepare
    private_storage_consumer_private prepare "$consumer_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$WORK/runtime-relay4/control/agent.sock" \
        "$WORK/runtime-relay5/control/agent.sock" "$WORK/runtime-relay3/control/agent.sock" \
        "$storage_key_a" "$storage_key_b" "$storage_key_c" \
        >"$WORK/storage-consumer-prepare.json" || fail CONSUMER_PREPARE_FAILED
    private_storage_consumer_phase publish
    private_storage_fragments_usage consumer_uploaded_usage

    # The same A store remains intact but unavailable throughout repair and
    # application reads. The helper cannot start an alternate provider itself.
    private_storage_fragments_reopen relay5 relay3
    content_custody_cli relay4 content status | jq -e '.serving == false' >/dev/null \
        || fail CONSUMER_SOURCE_STILL_SERVING
    for consumer_node in relay5 relay3; do
        content_custody_cli "$consumer_node" content status | jq -e '.serving == true' >/dev/null \
            || fail CONSUMER_SURVIVOR_NOT_SERVING
    done
    private_storage_consumer_phase exercise
    private_storage_fragments_usage consumer_restored_usage

    private_storage_fragments_reopen relay4 relay5 relay3
    private_storage_consumer_phase finish
    private_storage_fragments_usage consumer_deleted_usage
    jq -e 'length == 3 and all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})' \
        "$WORK/private-storage-fragments-consumer_deleted_usage.json" >/dev/null \
        || fail CONSUMER_PROVIDER_CLEANUP_INCOMPLETE
    jq -n '{first_provider_stopped_before_repair_and_read:true,first_store_retained:true,
        other_two_providers_serving:true,same_three_stores_reopened:true,
        all_usage_snapshots_with_services_stopped:true,all_three_store_inodes_preserved:true}' \
        >"$WORK/storage-consumer-withdrawal.json"
    private_storage_consumer_cleanup || fail CONSUMER_PRIVATE_CLEANUP_FAILED
    consumer_profile_version=${storage_consumer_profile_version-7}
    case $consumer_profile_version in 7|8|9|10) ;; *) fail CONSUMER_PROFILE_INVALID; return 1 ;; esac
    python3 -B "$source_directory/tests/integration/storage-consumer-maintenance-evidence.py" \
        "evidence-v$consumer_profile_version" "$WORK" "$WORK/storage-consumer-evidence.json" \
        || fail CONSUMER_EVIDENCE_INVALID
}
