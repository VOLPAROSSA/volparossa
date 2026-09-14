#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive name retrieval after the existing native/HTTPS/public-user phases in the KVM guest.
# shellcheck disable=SC2154,SC2034

content_named_cli() {
    timeout --signal=TERM --kill-after=5s 120s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$named_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

content_named_cleanup() {
    named_cleanup_root=$WORK/client-fixtures/named-output
    [ ! -L "$named_cleanup_root" ] || return 1
    if [ -e "$named_cleanup_root" ]; then
        [ -d "$named_cleanup_root" ] \
            && [ "$(stat -Lc '%a:%u:%g' "$named_cleanup_root")" = "700:$WORKER_UID:$WORKER_GID" ] || return 1
        named_cleanup_file=$named_cleanup_root/object.bin
        [ ! -L "$named_cleanup_file" ] || return 1
        if [ -e "$named_cleanup_file" ]; then
            [ -f "$named_cleanup_file" ] \
                && [ "$(stat -Lc '%a:%u:%g' "$named_cleanup_file")" = "600:$WORKER_UID:$WORKER_GID" ] || return 1
            rm -f -- "$named_cleanup_file" || return 1
        fi
        rmdir -- "$named_cleanup_root" || return 1
    fi
    jq -n '{user_output_removed:true,user_directory_removed:true}' >"$WORK/content-provider-named-cleanup.json"
}

content_named_run() {
    PHASE=content-provider-named-register
    # Keep every earlier phase unchanged. Name serving is an explicit stop/restart, not
    # a silent change to hash-only registrations or an opportunistic-replication opt-in.
    for named_node in "$provider_node_a" "$provider_node_b"; do
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$named_node/control/agent.sock" \
            content stop >"$WORK/content-provider-named-$named_node-reset.json" \
            2>"$WORK/content-provider-named-$named_node-reset.err" || fail CONTENT_NAME_RESET_FAILED
        case $named_node in
            relay4) named_address=49.165.5.1; named_hostname=provider-a.volparossa.test ;;
            relay5) named_address=50.166.6.1; named_hostname=provider-b.volparossa.test ;;
            relay3) named_address=48.164.4.1; named_hostname=provider-c.volparossa.test ;;
            *) fail CONTENT_NAME_PROVIDER_INVALID ;;
        esac
        "$binary_directory/volparossa" --control-socket "$WORK/runtime-$named_node/control/agent.sock" \
            content serve --name-lookup --manifest "$provider_manifest" --publisher-key "$provider_publisher" \
            --cache "$WORK/state-$named_node/content/cache" --bind "$named_address:18080" \
            --advertised-hostname "$named_hostname" >"$WORK/content-provider-named-$named_node-serve.json" \
            2>"$WORK/content-provider-named-$named_node-serve.err" || fail CONTENT_NAME_SERVE_FAILED
        jq -e '.serving == true and .publications == 1 and .replication_enabled == false' \
            "$WORK/content-provider-named-$named_node-serve.json" >/dev/null || fail CONTENT_NAME_SERVE_NOT_READY
    done
    named_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $named_control_gid in ''|*[!0-9]*) fail CONTENT_NAME_CONTROL_GROUP_INVALID ;; esac
    [ "$named_control_gid" != "$AGENT_GID" ] || fail CONTENT_NAME_CONTROL_GROUP_INVALID
    named_user=$WORK/client-fixtures/named-output
    named_cache=$provider_client/named-cache
    for named_new in "$named_user" "$named_cache"; do
        if [ -e "$named_new" ] || [ -L "$named_new" ]; then fail CONTENT_NAME_PATH_EXISTS; fi
    done
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$named_user"
    # Demonstrate the live consumer mount can access its own original public metadata,
    # then remove that exact fixture copy before calling the manifest-free command.
    if [ "$provider_manifest" != "$WORK/state-client/content/manifest.bin" ] \
        || [ -L "$provider_manifest" ] || [ ! -f "$provider_manifest" ]; then
        fail CONTENT_NAME_MANIFEST_TARGET
    fi
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$provider_manifest" || fail CONTENT_NAME_POSITIVE_CONTROL
    for named_hidden in "$named_user" "$provider_root" "$provider_a/cache" "$provider_b/cache"; do
        if nsenter --target "$provider_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$named_hidden"; then fail CONTENT_NAME_LOCAL_SHORTCUT; fi
    done
    rm -- "$provider_manifest" || fail CONTENT_NAME_MANIFEST_REMOVAL_FAILED
    [ ! -e "$provider_manifest" ] || fail CONTENT_NAME_MANIFEST_STILL_PRESENT
    PHASE=content-provider-named-fetch
    start_privacy_observers content-provider-named-privacy || fail CONTENT_NAME_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer content-provider-named-control \
        || fail CONTENT_NAME_CONTROL_CAPTURE_UNAVAILABLE
    content_named_cli content fetch-name --publisher-key "$provider_publisher" \
        --name disposable-native-network-publication --min-revision 1 --cache "$named_cache" \
        --local-output "$named_user/object.bin" >"$WORK/content-provider-named-fetch.json" \
        2>"$WORK/content-provider-named-fetch.err" || fail CONTENT_NAME_FETCH_FAILED
    benchmark_capture_paths content-provider-named mptcp || fail CONTENT_NAME_PATHS_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_NAME_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail CONTENT_NAME_CONTROL_CAPTURE_INCOMPLETE
    named_sha=$(sha256sum "$named_user/object.bin" | awk '{print $1}')
    if content_named_cli content fetch-name --publisher-key "$provider_publisher" \
        --name disposable-native-network-publication --cache "$named_cache" \
        --local-output "$named_user/object.bin" >"$WORK/content-provider-named-no-clobber.out" \
        2>"$WORK/content-provider-named-no-clobber.err"; then fail CONTENT_NAME_OUTPUT_OVERWRITTEN; fi
    grep -F 'already exists' "$WORK/content-provider-named-no-clobber.err" >/dev/null \
        || fail CONTENT_NAME_NO_CLOBBER_NOT_LOCAL
    if [ "$(sha256sum "$named_user/object.bin" | awk '{print $1}')" != "$named_sha" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$named_user/object.bin")" != "600:$WORKER_UID:$WORKER_GID" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$named_cache")" != "700:$AGENT_UID:$AGENT_GID" ]; then
        fail CONTENT_NAME_ACCOUNT_BOUNDARY_CHANGED
    fi
    jq -n --arg sha "$named_sha" --arg path "$named_user/object.bin" --arg cache "$named_cache" \
        --argjson bytes "$(stat -Lc '%s' "$named_user/object.bin")" \
        --argjson user "$WORKER_UID" --argjson agent "$AGENT_UID" \
        --argjson control "$named_control_gid" --argjson agent_gid "$AGENT_GID" \
        '{sha256:$sha,bytes:$bytes,path:$path,agent_cache:$cache,user_uid:$user,agent_uid:$agent,
          control_gid:$control,agent_gid:$agent_gid,output_mode:"0600",cache_mode:"0700",
          fresh_cache:true,client_manifest_removed:true,no_manifest_argument:true,
          agent_mount_positive_control:true,agent_cannot_read_user_output:true,
          client_cannot_read_provider_caches:true,no_clobber_verified:true}' \
        >"$WORK/content-provider-named-output.json"
    content_named_cleanup || fail CONTENT_NAME_OUTPUT_CLEANUP_FAILED
    PHASE=content-provider-named-complete
}
