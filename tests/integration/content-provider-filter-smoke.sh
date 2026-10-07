#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive exact public-filter export before/after the site's existing route retirement.
# shellcheck disable=SC2154,SC2034

content_provider_filter_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-provider-filter-smoke.py" "$@"
}

content_provider_filter_cleanup() {
    [ -f "$WORK/bin/content-provider-filter-smoke.py" ] || return 0
    content_provider_filter_private publisher-cleanup "$WORK/client-fixtures/filter-publisher" \
        >"$WORK/content-provider-filter-publisher-cleanup.json" || return 1
    content_provider_filter_private user-cleanup "$WORK/client-fixtures/filter-viewer" \
        >"$WORK/content-provider-filter-cleanup.json" || return 1
}

content_provider_filter_consume() {
    filter_phase=$1
    PHASE=content-provider-filter-$filter_phase
    start_privacy_observers "content-provider-filter-$filter_phase-privacy" || fail CONTENT_FILTER_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer "content-provider-filter-$filter_phase-control" \
        || fail CONTENT_FILTER_CONTROL_CAPTURE_UNAVAILABLE
    timeout --signal=TERM --kill-after=10s 120s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-provider-filter-smoke.py" "$filter_phase" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$filter_cache" "$filter_user" \
        "$site_parent_ns" "$site_client_ns" "$WORKER_UID" "$WORKER_GID" "$site_control_gid" \
        >"$WORK/content-provider-filter-$filter_phase-consumer.json" \
        2>"$WORK/content-provider-filter-$filter_phase.err" || fail CONTENT_FILTER_CONSUMER_FAILED
    if [ "$filter_phase" = cold ]; then
        benchmark_capture_paths content-provider-filter mptcp || fail CONTENT_FILTER_PATHS_UNAVAILABLE
    fi
    stop_privacy_observers || fail CONTENT_FILTER_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail CONTENT_FILTER_CONTROL_CAPTURE_INCOMPLETE
    if [ -L "$filter_cache" ] || [ "$(stat -Lc '%a:%u:%g' "$filter_cache")" != "700:$AGENT_UID:$AGENT_GID" ]; then
        fail CONTENT_FILTER_CACHE_OWNERSHIP_CHANGED
    fi
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$filter_cache"; then fail CONTENT_FILTER_AGENT_CACHE_EXPOSED; fi
}

content_provider_filter_cold_run() {
    PHASE=content-provider-filter-publish
    install -o root -g root -m 0555 "$source_directory/tests/integration/content-provider-filter-smoke.py" \
        "$WORK/bin/content-provider-filter-smoke.py" || fail CONTENT_FILTER_DRIVER_UNAVAILABLE
    filter_publisher=$WORK/client-fixtures/filter-publisher
    filter_user=$WORK/client-fixtures/filter-viewer
    filter_cache=$WORK/state-client/filter-cache
    for filter_new in "$filter_publisher" "$filter_user" "$filter_cache" \
        "$WORK/state-$provider_node_a/filter-cache" "$WORK/state-$provider_node_b/filter-cache"; do
        if [ -e "$filter_new" ] || [ -L "$filter_new" ]; then fail CONTENT_FILTER_PATH_EXISTS; fi
    done
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$filter_publisher" "$filter_user"
    content_provider_filter_private init "$filter_publisher" >"$WORK/content-provider-filter-assets.json" \
        2>"$WORK/content-provider-filter-init.err" || fail CONTENT_FILTER_INPUT_FAILED
    content_provider_site_cli "$provider_node_a" init --identity "$filter_publisher/identity.key" \
        --passphrase-file "$filter_publisher/passphrase" >"$WORK/content-provider-filter-init.log" \
        2>>"$WORK/content-provider-filter-init.err" || fail CONTENT_FILTER_IDENTITY_FAILED
    content_provider_site_cli "$provider_node_a" content publish --input "$filter_publisher/filters.txt" \
        --name disposable-public-domain-filters --revision 1 --content-type text/plain \
        --identity "$filter_publisher/identity.key" --passphrase-file "$filter_publisher/passphrase" \
        --cache "$filter_publisher/source-cache" --manifest "$filter_publisher/manifest.bin" \
        >"$WORK/content-provider-filter-publish.json" 2>"$WORK/content-provider-filter-publish.err" \
        || fail CONTENT_FILTER_PUBLISH_FAILED
    filter_key=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-provider-filter-publish.json") || fail CONTENT_FILTER_PUBLISHER_INVALID
    if [ "$filter_key" = "$provider_publisher" ] || [ "$filter_key" = "$site_key" ]; then
        fail CONTENT_FILTER_PUBLISHER_REUSED
    fi
    # The owner selects this exact envelope before any provider/consumer request.
    filter_manifest=$(sha256sum "$filter_publisher/manifest.bin" | awk '{print $1}')
    jq --arg publisher "$filter_key" --arg manifest "$filter_manifest" \
        '. + {publisher_key:$publisher,manifest_id:$manifest}' "$WORK/content-provider-filter-assets.json" \
        >"$WORK/content-provider-filter-input.json" || fail CONTENT_FILTER_SELECTION_FAILED
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$WORK/content-provider-filter-input.json" \
        "$filter_user/expected.json"
    for filter_node in "$provider_node_a" "$provider_node_b"; do
        case $filter_node in
            relay4) filter_address=49.165.5.1; filter_hostname=provider-a.volparossa.test ;;
            relay5) filter_address=50.166.6.1; filter_hostname=provider-b.volparossa.test ;;
            relay3) filter_address=48.164.4.1; filter_hostname=provider-c.volparossa.test ;;
            *) fail CONTENT_FILTER_PROVIDER_INVALID ;;
        esac
        content_provider_site_cli "$filter_node" content import --public-content \
            --manifest "$filter_publisher/manifest.bin" --publisher-key "$filter_key" \
            --cache "$filter_publisher/source-cache" --agent-cache "$WORK/state-$filter_node/filter-cache" \
            >"$WORK/content-provider-filter-$filter_node-import.json" \
            2>"$WORK/content-provider-filter-$filter_node-import.err" || fail CONTENT_FILTER_IMPORT_FAILED
        content_provider_site_cli "$filter_node" content serve --name-lookup \
            --manifest "$filter_publisher/manifest.bin" --publisher-key "$filter_key" \
            --cache "$WORK/state-$filter_node/filter-cache" --bind "$filter_address:18080" \
            --advertised-hostname "$filter_hostname" >"$WORK/content-provider-filter-$filter_node-serve.json" \
            2>"$WORK/content-provider-filter-$filter_node-serve.err" || fail CONTENT_FILTER_SERVE_FAILED
        jq -e '.serving == true and .publications == 3 and .replication_enabled == false' \
            "$WORK/content-provider-filter-$filter_node-serve.json" >/dev/null || fail CONTENT_FILTER_NOT_READY
        [ "$(stat -Lc '%a:%u:%g' "$WORK/state-$filter_node/filter-cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
            || fail CONTENT_FILTER_PROVIDER_CACHE_OWNERSHIP_CHANGED
        if nsenter --target "$provider_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$filter_node/filter-cache"; then fail CONTENT_FILTER_LOCAL_SHORTCUT; fi
        if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$filter_node/filter-cache"; then fail CONTENT_FILTER_AGENT_CACHE_EXPOSED; fi
    done
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail CONTENT_FILTER_ISOLATION_PROBE_FAILED
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$filter_user"; then fail CONTENT_FILTER_USER_STATE_EXPOSED; fi
    content_provider_filter_private publisher-cleanup "$filter_publisher" \
        >"$WORK/content-provider-filter-publisher-cleanup.json" || fail CONTENT_FILTER_PUBLISHER_CLEANUP_FAILED
    [ ! -e "$filter_publisher" ] || fail CONTENT_FILTER_PUBLISHER_FILES_REMAIN
    content_provider_filter_consume cold
    filter_cache_before=$(stat -Lc '%d:%i' "$filter_cache") || fail CONTENT_FILTER_CACHE_IDENTITY_UNAVAILABLE
}

content_provider_filter_warm_run() {
    # Site cache-only has retired the route. Reuse is not an enforced cache-only CLI mode:
    # a miss would try the network and fail this phase's zero-work observations.
    content_provider_filter_consume warm
    filter_cache_after=$(stat -Lc '%d:%i' "$filter_cache") || fail CONTENT_FILTER_CACHE_IDENTITY_UNAVAILABLE
    [ "$filter_cache_before" = "$filter_cache_after" ] || fail CONTENT_FILTER_CACHE_REPLACED
    jq -n --arg context "$provider_context" --argjson user "$WORKER_UID" --argjson user_gid "$WORKER_GID" \
        --argjson agent "$AGENT_UID" --argjson agent_gid "$AGENT_GID" --argjson control "$site_control_gid" \
        --arg cache "$filter_cache" --arg before "$filter_cache_before" --arg after "$filter_cache_after" \
        '{route_context_id:$context,user_uid:$user,user_gid:$user_gid,agent_uid:$agent,agent_gid:$agent_gid,
          control_gid:$control,cache_modes:"0700",fresh_client_cache:true,agent_mount_positive_control:true,
          agent_cache:$cache,cache_identity_before:$before,cache_identity_after:$after,
          client_cannot_read_provider_caches:true,agent_cannot_read_user_directory:true,
          user_cannot_read_agent_caches:true,publisher_sources_removed_before_fetch:true,
          selection_pinned_before_fetch:true}' >"$WORK/content-provider-filter-isolation.json"
    content_provider_filter_cleanup || fail CONTENT_FILTER_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-provider-filter-smoke.py" evidence "$WORK" \
        >"$WORK/content-provider-filter-evidence.json" || fail CONTENT_FILTER_EVIDENCE_INVALID
}
