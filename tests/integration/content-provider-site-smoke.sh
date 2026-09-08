#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive ordinary native-site publication after named retrieval, before provider stop.
# shellcheck disable=SC2154,SC2034

content_provider_site_cli() {
    site_socket_node=$1
    shift
    timeout --signal=TERM --kill-after=5s 120s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$site_socket_node/control/agent.sock" "$@"
}

content_provider_site_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-provider-site-smoke.py" "$@"
}

content_provider_site_cleanup() {
    # All CLI/HTTP child processes have been synchronously waited by their bounded driver.
    # These exact new user roots never contain provider/consumer agent caches.
    [ -f "$WORK/bin/content-provider-site-smoke.py" ] || return 0
    content_provider_site_private publisher-cleanup "$WORK/client-fixtures/site-publisher" \
        >"$WORK/content-provider-site-publisher-cleanup.json" || return 1
    content_provider_site_private user-cleanup "$WORK/client-fixtures/site-viewer" \
        >"$WORK/content-provider-site-cleanup.json" || return 1
}

content_provider_site_run() {
    PHASE=content-provider-site-publish
    site_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $site_control_gid in ''|*[!0-9]*) fail CONTENT_SITE_CONTROL_GROUP_INVALID ;; esac
    [ "$site_control_gid" != "$AGENT_GID" ] || fail CONTENT_SITE_CONTROL_GROUP_INVALID
    for site_script in content-provider-site-smoke.py content-provider-https-smoke.py content-network-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$site_script" \
            "$WORK/bin/$site_script" || fail CONTENT_SITE_DRIVER_UNAVAILABLE
    done
    site_publisher=$WORK/client-fixtures/site-publisher
    site_user=$WORK/client-fixtures/site-viewer
    site_client_cache=$WORK/state-client/site-cache
    for site_new in "$site_publisher" "$site_user" "$site_client_cache" \
        "$WORK/state-$provider_node_a/site-cache" "$WORK/state-$provider_node_b/site-cache"; do
        if [ -e "$site_new" ] || [ -L "$site_new" ]; then fail CONTENT_SITE_PATH_EXISTS; fi
    done
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$site_publisher" "$site_user"
    content_provider_site_private init "$site_publisher" >"$WORK/content-provider-site-assets.json" \
        2>"$WORK/content-provider-site-init.err" || fail CONTENT_SITE_INPUT_FAILED
    content_provider_site_cli "$provider_node_a" init --identity "$site_publisher/identity.key" \
        --passphrase-file "$site_publisher/passphrase" >"$WORK/content-provider-site-init.log" \
        2>>"$WORK/content-provider-site-init.err" || fail CONTENT_SITE_IDENTITY_FAILED
    content_provider_site_cli "$provider_node_a" content site pack --directory "$site_publisher/assets" \
        --output "$site_publisher/bundle.bin" >"$WORK/content-provider-site-pack.json" \
        2>"$WORK/content-provider-site-pack.err" || fail CONTENT_SITE_PACK_FAILED
    content_provider_site_cli "$provider_node_a" content publish --input "$site_publisher/bundle.bin" \
        --name disposable-native-static-site --revision 1 --content-type application/vnd.volparossa.site.v1 \
        --identity "$site_publisher/identity.key" --passphrase-file "$site_publisher/passphrase" \
        --cache "$site_publisher/source-cache" --manifest "$site_publisher/manifest.bin" \
        >"$WORK/content-provider-site-publish.json" 2>"$WORK/content-provider-site-publish.err" \
        || fail CONTENT_SITE_PUBLISH_FAILED
    site_key=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-provider-site-publish.json") || fail CONTENT_SITE_PUBLISHER_INVALID
    [ "$site_key" != "$provider_publisher" ] || fail CONTENT_SITE_FIXTURE_PUBLISHER_REUSED
    jq --arg publisher_key "$site_key" \
        --arg bundle_sha256 "$(sha256sum "$site_publisher/bundle.bin" | awk '{print $1}')" \
        --argjson bundle_bytes "$(stat -Lc '%s' "$site_publisher/bundle.bin")" \
        '. + {publisher_key:$publisher_key,bundle_sha256:$bundle_sha256,bundle_bytes:$bundle_bytes}' \
        "$WORK/content-provider-site-assets.json" >"$WORK/content-provider-site-input.json" \
        || fail CONTENT_SITE_INPUT_METADATA_FAILED
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$WORK/content-provider-site-input.json" \
        "$site_user/expected.json"
    PHASE=content-provider-site-register
    for site_node in "$provider_node_a" "$provider_node_b"; do
        case $site_node in
            relay4) site_address=49.165.5.1; site_hostname=provider-a.volparossa.test ;;
            relay5) site_address=50.166.6.1; site_hostname=provider-b.volparossa.test ;;
            relay3) site_address=48.164.4.1; site_hostname=provider-c.volparossa.test ;;
            *) fail CONTENT_SITE_PROVIDER_INVALID ;;
        esac
        content_provider_site_cli "$site_node" content import --public-content \
            --manifest "$site_publisher/manifest.bin" --publisher-key "$site_key" \
            --cache "$site_publisher/source-cache" --agent-cache "$WORK/state-$site_node/site-cache" \
            >"$WORK/content-provider-site-$site_node-import.json" \
            2>"$WORK/content-provider-site-$site_node-import.err" || fail CONTENT_SITE_IMPORT_FAILED
        # Name lookup already explicitly enabled in the preceding phase. Attach this
        # signed public manifest to each existing listener; no lifecycle change or new port.
        content_provider_site_cli "$site_node" content serve --name-lookup \
            --manifest "$site_publisher/manifest.bin" --publisher-key "$site_key" \
            --cache "$WORK/state-$site_node/site-cache" --bind "$site_address:18080" \
            --advertised-hostname "$site_hostname" >"$WORK/content-provider-site-$site_node-serve.json" \
            2>"$WORK/content-provider-site-$site_node-serve.err" || fail CONTENT_SITE_SERVE_FAILED
        jq -e '.serving == true and .publications == 2 and .replication_enabled == false' \
            "$WORK/content-provider-site-$site_node-serve.json" >/dev/null || fail CONTENT_SITE_NOT_READY
        [ "$(stat -Lc '%a:%u:%g' "$WORK/state-$site_node/site-cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
            || fail CONTENT_SITE_PROVIDER_CACHE_OWNERSHIP_CHANGED
        if nsenter --target "$provider_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$site_node/site-cache"; then fail CONTENT_SITE_LOCAL_SHORTCUT; fi
        if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$site_node/site-cache"; then fail CONTENT_SITE_AGENT_CACHE_EXPOSED; fi
    done
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CONTENT_SITE_ISOLATION_PROBE_FAILED
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$site_user"; then fail CONTENT_SITE_USER_STATE_EXPOSED; fi
    # Every publisher CLI has exited. Delete its identity, original bundle, manifest,
    # assets AND source chunks before the independent Client requests only key/name.
    content_provider_site_private publisher-cleanup "$site_publisher" \
        >"$WORK/content-provider-site-publisher-cleanup.json" || fail CONTENT_SITE_PUBLISHER_CLEANUP_FAILED
    [ ! -e "$site_publisher" ] || fail CONTENT_SITE_PUBLISHER_FILES_REMAIN
    site_parent_ns=$(readlink /proc/self/ns/net)
    site_client_ns=$(ip netns exec "$CLIENT" readlink /proc/self/ns/net) || fail CONTENT_SITE_CLIENT_NAMESPACE_FAILED
    [ "$site_parent_ns" != "$site_client_ns" ] || fail CONTENT_SITE_CLIENT_NAMESPACE_INVALID
    PHASE=content-provider-site-open
    start_privacy_observers content-provider-site-privacy || fail CONTENT_SITE_PRIVACY_UNAVAILABLE
    content_provider_start_control_observer content-provider-site-control || fail CONTENT_SITE_CONTROL_CAPTURE_UNAVAILABLE
    timeout --signal=TERM --kill-after=10s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-provider-site-smoke.py" consume "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$site_client_cache" "$site_user" \
        "$site_parent_ns" "$site_client_ns" "$WORKER_UID" "$WORKER_GID" "$site_control_gid" \
        >"$WORK/content-provider-site-consumer.json" 2>"$WORK/content-provider-site-open.err" \
        || fail CONTENT_SITE_OPEN_OR_HTTP_FAILED
    benchmark_capture_paths content-provider-site mptcp || fail CONTENT_SITE_PATHS_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_SITE_PRIVACY_INCOMPLETE
    content_provider_stop_control_observer || fail CONTENT_SITE_CONTROL_CAPTURE_INCOMPLETE
    [ "$(stat -Lc '%a:%u:%g' "$site_client_cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
        || fail CONTENT_SITE_CACHE_OWNERSHIP_CHANGED
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$site_client_cache"; then fail CONTENT_SITE_CONSUMER_CACHE_EXPOSED; fi
    jq -n --arg context "$provider_context" --argjson user "$WORKER_UID" --argjson user_gid "$WORKER_GID" \
        --argjson agent "$AGENT_UID" --argjson agent_gid "$AGENT_GID" --argjson control "$site_control_gid" \
        '{route_context_id:$context,user_uid:$user,user_gid:$user_gid,agent_uid:$agent,agent_gid:$agent_gid,
          control_gid:$control,cache_modes:"0700",fresh_client_cache:true,agent_mount_positive_control:true,
          client_cannot_read_provider_caches:true,agent_cannot_read_user_directory:true,
          user_cannot_read_agent_caches:true,publisher_process_exited_before_fetch:true,
          publisher_node_offline_claimed:false}' >"$WORK/content-provider-site-isolation.json"
    content_provider_site_cleanup || fail CONTENT_SITE_USER_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-provider-site-smoke.py" evidence "$WORK" \
        >"$WORK/content-provider-site-evidence.json" || fail CONTENT_SITE_EVIDENCE_INVALID
    PHASE=content-provider-site-complete
}
