#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Called with the established twelve-node route and its ordinary provider/client agents.
# shellcheck disable=SC2154,SC2034

map_publisher() {
    timeout --kill-after=5s 100s setpriv --reuid="$map_uid" --regid="$map_gid" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- "$@"
}

map_publish_cli() {
    map_publisher "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node_a/control/agent.sock" "$@"
}

map_client_phase() {
    timeout --kill-after=5s 285s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$site_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$map_bin/trial.py" "$1" "$map_owner" --core "$binary_directory/volparossa" \
            --socket "$WORK/runtime-client/control/agent.sock" --cache "$map_client_cache" --parent-namespace "$site_parent_ns" \
        >"$WORK/content-provider-map-$1.json" || fail MAP_TRAFFIC_OWNER_PHASE_FAILED
}

map_traffic_cold() {
    PHASE=map-traffic-publish
    map_bin=$WORK/bin/map-traffic
    map_owner=$WORK/client-fixtures/map-traffic
    map_publisher_dir=$WORK/map-traffic-publisher
    map_provider_cache=$WORK/state-$provider_node_a/map-traffic-cache
    map_client_cache=$WORK/state-client/map-traffic-cache
    for map_new in "$map_bin" "$map_owner" "$map_publisher_dir" "$map_provider_cache" "$map_client_cache"; do
        [ ! -e "$map_new" ] && [ ! -L "$map_new" ] || fail MAP_TRAFFIC_PATH_EXISTS
    done
    map_uid=$(id -u nobody)
    map_gid=$(id -g nobody)
    [ "$map_uid" != 0 ] && [ "$map_uid" != "$WORKER_UID" ] && [ "$map_uid" != "$AGENT_UID" ] || fail MAP_TRAFFIC_OWNER_INVALID
    install -d -o root -g root -m 0755 "$map_bin"
    for map_file in core_traffic.py traffic_snapshot.py trial.py synthetic-dataset.json; do
        install -o root -g root -m 0444 "/home/vpci/map-traffic/$map_file" "$map_bin/$map_file" || fail MAP_TRAFFIC_SOURCE_MISSING
    done
    map_revision=$(sh "$source_directory/tests/integration/map-traffic-sources.sh" verify "$map_bin") || fail MAP_TRAFFIC_SOURCE_CHANGED
    install -d -o "$map_uid" -g "$map_gid" -m 0700 "$map_publisher_dir"
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$map_owner"
    map_publisher python3 -B "$map_bin/trial.py" prepare "$map_publisher_dir" || fail MAP_TRAFFIC_INPUT_INVALID
    map_publish_cli init --identity "$map_publisher_dir/identity" --passphrase-file "$map_publisher_dir/passphrase" \
        >/dev/null || fail MAP_TRAFFIC_IDENTITY_FAILED
    map_publish_cli content publish --input "$map_publisher_dir/payload" --cache "$map_publisher_dir/cache" \
        --identity "$map_publisher_dir/identity" --passphrase-file "$map_publisher_dir/passphrase" \
        --manifest "$map_publisher_dir/manifest" --name traffic/Synthetic/1 --revision 1 \
        --content-type application/vnd.volparossa.road-traffic.v1+json --lifetime-seconds 180 \
        >"$WORK/map-traffic-publication.json" || fail MAP_TRAFFIC_PUBLISH_FAILED
    map_key=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' "$WORK/map-traffic-publication.json") || fail MAP_TRAFFIC_KEY_INVALID
    jq -ce '{name,revision,bytes,manifest_id,publisher_key_hex,expires_unix_seconds}' "$WORK/map-traffic-publication.json" >"$WORK/map-traffic-public.json"
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$WORK/map-traffic-public.json" "$map_owner/public.json"
    PHASE=map-traffic-register
    case $provider_node_a in
        relay4) map_bind=49.165.5.1:18080; map_hostname=provider-a.volparossa.test ;;
        relay5) map_bind=50.166.6.1:18080; map_hostname=provider-b.volparossa.test ;;
        relay3) map_bind=48.164.4.1:18080; map_hostname=provider-c.volparossa.test ;;
        *) fail MAP_TRAFFIC_PROVIDER_INVALID ;;
    esac
    map_publish_cli content import --public-content --manifest "$map_publisher_dir/manifest" --publisher-key "$map_key" \
        --cache "$map_publisher_dir/cache" --agent-cache "$map_provider_cache" >/dev/null || fail MAP_TRAFFIC_IMPORT_FAILED
    map_publish_cli content serve --name-lookup --manifest "$map_publisher_dir/manifest" --publisher-key "$map_key" \
        --cache "$map_provider_cache" --bind "$map_bind" --advertised-hostname "$map_hostname" >"$WORK/map-traffic-serve.json" \
        || fail MAP_TRAFFIC_REGISTRATION_FAILED
    jq -e '.serving and .replication_enabled == false' "$WORK/map-traffic-serve.json" >/dev/null || fail MAP_TRAFFIC_NOT_SERVING
    [ "$(stat -c '%a:%u:%g' "$map_provider_cache")" = "700:$AGENT_UID:$AGENT_GID" ] || fail MAP_TRAFFIC_PROVIDER_CACHE_OWNERSHIP
    # Remove only this newly created publisher fixture before a manifest-free cold request.
    [ "$(stat -c '%a:%u:%g' "$map_publisher_dir")" = "700:$map_uid:$map_gid" ] || fail MAP_TRAFFIC_OWNER_INVALID
    rm -r --one-file-system -- "$map_publisher_dir"
    [ ! -e "$map_publisher_dir" ] && [ ! -e "$map_client_cache" ] || fail MAP_TRAFFIC_LOCAL_SOURCE_REMAINS
    if nsenter --target "$provider_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- test -r "$map_provider_cache"; then fail MAP_TRAFFIC_PROVIDER_CACHE_EXPOSED; fi
    PHASE=map-traffic-cold
    map_client_phase cold
    [ "$(stat -c '%a:%u:%g' "$map_client_cache")" = "700:$AGENT_UID:$AGENT_GID" ] || fail MAP_TRAFFIC_CLIENT_CACHE_OWNERSHIP
}

map_traffic_offline() {
    PHASE=map-traffic-offline
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" status \
        | grep -Fx 'connected: false' >/dev/null || fail MAP_TRAFFIC_ROUTE_STILL_ACTIVE
    map_client_phase warm
    PHASE=map-traffic-expiry
    map_client_phase expired
    for map_file in public.json cold.json warm.json; do rm -- "$map_owner/$map_file" || fail MAP_TRAFFIC_OWNER_CLEANUP; done
    rmdir -- "$map_owner" || fail MAP_TRAFFIC_OWNER_CLEANUP
    jq -n --slurpfile cold "$WORK/content-provider-map-cold.json" --slurpfile warm "$WORK/content-provider-map-warm.json" \
        --slurpfile expired "$WORK/content-provider-map-expired.json" --arg map "$map_revision" --arg core "$expected_commit" \
        '{schema:1,map_revision:$map,core_revision:$core,cold:$cold[0],warm:$warm[0],expired:$expired[0],
          publisher_originals_removed:true,distinct_publisher_and_client:true,provider_cache_isolated:true,
          route_disconnected:true,owner_cleanup:true}' >"$WORK/content-provider-map-traffic.json" || fail MAP_TRAFFIC_RECEIPT_FAILED
}
