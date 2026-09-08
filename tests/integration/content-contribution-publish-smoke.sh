#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive after the complete automatic P proof; no manual import/serve in this publication phase.
# shellcheck disable=SC2154,SC2034

content_contribution_publish_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-contribution-publish-smoke.py" "$@"
}

content_contribution_publish_cli() {
    ccp_node=$1; shift
    case $ccp_node in relay4) ccp_namespace=$R4 ;; client) ccp_namespace=$CLIENT ;; *) return 1 ;; esac
    timeout --signal=TERM --kill-after=5s 120s ip netns exec "$ccp_namespace" \
        setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ccp_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-$ccp_node/control/agent.sock" "$@"
}

content_contribution_publish_cleanup() {
    [ -f "$WORK/bin/content-contribution-publish-smoke.py" ] || return 0
    content_contribution_publish_private publisher-cleanup "$WORK/client-fixtures/site-publisher" \
        >"$WORK/content-replication-publication-publisher-cleanup.json" || return 1
    content_contribution_publish_private user-cleanup "$WORK/client-fixtures/site-viewer" \
        >"$WORK/content-replication-publication-cleanup.json"
}

content_contribution_publish_status() {
    ccp_status_label=$1; ccp_publications=$2; ccp_chunks=$3; ccp_bytes=$4
    ccp_status_deadline=$(($(date +%s) + 120))
    while [ "$(date +%s)" -lt "$ccp_status_deadline" ]; do
        if CONTENT_REPLICATION_COMMAND_TIMEOUT=2s content_replication_cli relay4 content status \
            >"$WORK/content-replication-publication-$ccp_status_label.json" \
            2>"$WORK/content-replication-publication-$ccp_status_label.err" \
            && jq -e --argjson pubs "$ccp_publications" --argjson chunks "$ccp_chunks" --argjson bytes "$ccp_bytes" '
                .serving and .replication_enabled and .publications == $pubs
                and .replica_publications == $pubs and .replica_chunks == $chunks and .replica_bytes == $bytes' \
                "$WORK/content-replication-publication-$ccp_status_label.json" >/dev/null; then return 0; fi
        sleep 0.25
    done
    return 1
}

content_contribution_publish_snapshot() {
    python3 -B "$source_directory/tests/integration/content-contribution-publish-smoke.py" cache \
        "$ccp_cache" >"$WORK/content-replication-publication-cache-$1.json"
}

content_contribution_publish_run() {
    PHASE=content-replication-publication-startup
    ccp_cache=$WORK/state-relay4/content/automatic-replicas
    ccp_user=$WORK/client-fixtures/site-viewer
    ccp_publisher=$WORK/client-fixtures/site-publisher
    ccp_destination=$WORK/state-client/content/publication-cache
    for ccp_new in "$ccp_user" "$ccp_publisher" "$ccp_destination"; do
        if [ -e "$ccp_new" ] || [ -L "$ccp_new" ]; then fail CONTENT_PUBLICATION_PATH_EXISTS; fi
    done
    ccp_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $ccp_control_gid in ''|*[!0-9]*) fail CONTENT_PUBLICATION_CONTROL_GROUP ;; esac
    [ "$ccp_control_gid" != "$AGENT_GID" ] || fail CONTENT_PUBLICATION_CONTROL_GROUP
    for ccp_script in content-contribution-publish-smoke.py content-provider-site-smoke.py \
        content-provider-https-smoke.py content-network-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$ccp_script" \
            "$WORK/bin/$ccp_script" || fail CONTENT_PUBLICATION_DRIVER_UNAVAILABLE
    done
    # The preceding proof stopped this service after its independent P retrieval. A real
    # configured startup restores the same P journal; never manually attach another listener.
    content_replication_automatic_restart publication-startup || fail CONTENT_PUBLICATION_STARTUP_FAILED
    content_contribution_publish_status before 1 3 524609 || fail CONTENT_PUBLICATION_INITIAL_STATE
    content_contribution_publish_snapshot initial || fail CONTENT_PUBLICATION_CACHE_INVALID
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$ccp_publisher" "$ccp_user"
    content_contribution_publish_private init "$ccp_publisher" \
        >"$WORK/content-replication-publication-assets.json" || fail CONTENT_PUBLICATION_INPUT_FAILED
    content_contribution_publish_cli relay4 init --identity "$ccp_publisher/identity.key" \
        --passphrase-file "$ccp_publisher/passphrase" >"$WORK/content-replication-publication-init.log" \
        2>"$WORK/content-replication-publication-init.err" || fail CONTENT_PUBLICATION_IDENTITY_FAILED
    content_contribution_publish_cli relay4 content site pack --directory "$ccp_publisher/assets" \
        --output "$ccp_publisher/bundle.bin" >"$WORK/content-replication-publication-pack.json" \
        2>"$WORK/content-replication-publication-pack.err" || fail CONTENT_PUBLICATION_PACK_FAILED
    content_contribution_publish_cli relay4 content publish --contribute \
        --input "$ccp_publisher/bundle.bin" --name disposable-native-static-site --revision 1 \
        --content-type application/vnd.volparossa.site.v1 --identity "$ccp_publisher/identity.key" \
        --passphrase-file "$ccp_publisher/passphrase" --cache "$ccp_publisher/source-cache" \
        --manifest "$ccp_publisher/manifest.bin" >"$WORK/content-replication-publication-publish.json" \
        2>"$WORK/content-replication-publication-publish.err" || fail CONTENT_PUBLICATION_NOT_ADMITTED
    jq -e '.operation == "content_publish" and .network_publication and .serving
        and .publications == 2 and .chunks == 9 and .bytes == 2097628' \
        "$WORK/content-replication-publication-publish.json" >/dev/null || fail CONTENT_PUBLICATION_RECEIPT_INVALID
    content_contribution_publish_private input "$ccp_publisher" \
        >"$WORK/content-replication-publication-input.json" || fail CONTENT_PUBLICATION_INPUT_BINDING
    ccp_key=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-replication-publication-publish.json") || fail CONTENT_PUBLICATION_KEY_INVALID
    [ "$ccp_key" != "$cr_key" ] || fail CONTENT_PUBLICATION_FIXTURE_SIGNER_REUSED
    jq --arg publisher_key "$ccp_key" '. + {publisher_key:$publisher_key}' \
        "$WORK/content-replication-publication-publish.json" >"$WORK/content-replication-publication-expected.json"
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
        "$WORK/content-replication-publication-expected.json" "$ccp_user/expected.json"
    content_contribution_publish_status after 2 12 2622237 || fail CONTENT_PUBLICATION_INCOMPLETE_CACHE
    content_contribution_publish_snapshot before || fail CONTENT_PUBLICATION_JOURNAL_MISSING

    # Same-account service isolation is checked in the actual process mount namespace;
    # ordinary operator separation is checked without joining the service's private group.
    content_replication_isolation client "$WORK/state-client/identity.key" || fail CONTENT_PUBLICATION_LOCAL_SHORTCUT
    ccp_agent_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay4.service)
    case $ccp_agent_pid in ''|0|*[!0-9]*) fail CONTENT_PUBLICATION_AGENT_UNAVAILABLE ;; esac
    nsenter --target "$ccp_agent_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$ccp_cache/.volparossa-owner-v1" || fail CONTENT_PUBLICATION_ISOLATION_CONTROL
    if nsenter --target "$ccp_agent_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$ccp_publisher/source-cache"; then fail CONTENT_PUBLICATION_USER_CACHE_EXPOSED; fi
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ccp_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$ccp_cache"; then fail CONTENT_PUBLICATION_AGENT_CACHE_EXPOSED; fi
    # Remove original bytes, signed manifest, source chunks and signing identity before fetch.
    content_contribution_publish_private publisher-cleanup "$ccp_publisher" \
        >"$WORK/content-replication-publication-publisher-cleanup.json" || fail CONTENT_PUBLICATION_SOURCE_CLEANUP
    [ ! -e "$ccp_publisher" ] || fail CONTENT_PUBLICATION_SOURCE_REMAINS
    PHASE=content-replication-publication-restart
    content_replication_automatic_restart publication-restart || fail CONTENT_PUBLICATION_RESTART_FAILED
    content_contribution_publish_status restored 2 12 2622237 || fail CONTENT_PUBLICATION_NOT_RESTORED
    content_contribution_publish_snapshot after || fail CONTENT_PUBLICATION_RESTORED_CACHE_INVALID
    content_replication_isolation client "$WORK/state-client/identity.key" || fail CONTENT_PUBLICATION_LOCAL_SHORTCUT
    jq -n --argjson user "$WORKER_UID" --argjson gid "$WORKER_GID" --argjson agent "$AGENT_UID" \
        --argjson agent_gid "$AGENT_GID" --argjson control "$ccp_control_gid" '
        {user_uid:$user,user_gid:$gid,agent_uid:$agent,agent_gid:$agent_gid,control_gid:$control,
          fresh_client_cache:true,agent_mount_positive_control:true,client_cannot_read_provider_cache:true,
          agent_cannot_read_user_source:true,user_cannot_read_agent_cache:true,
          publisher_process_exited_before_fetch:true,publisher_node_offline_claimed:false}' \
        >"$WORK/content-replication-publication-isolation.json"

    PHASE=content-replication-publication-fetch
    content_replication_select client content-replication-publication-final || fail CONTENT_PUBLICATION_ROUTE_UNAVAILABLE
    content_replication_capture reserve-fetch content-replication-publication-fetch \
        "$WORK/content-replication-publication-final-selection.json" || fail CONTENT_PUBLICATION_CAPTURE_UNAVAILABLE
    ccp_parent_ns=$(readlink /proc/self/ns/net)
    ccp_client_ns=$(ip netns exec "$CLIENT" readlink /proc/self/ns/net) || fail CONTENT_PUBLICATION_NAMESPACE_UNAVAILABLE
    timeout --signal=TERM --kill-after=10s 120s ip netns exec "$CLIENT" \
        setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$ccp_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/content-contribution-publish-smoke.py" consume "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$ccp_destination" "$ccp_user" \
        "$ccp_parent_ns" "$ccp_client_ns" "$WORKER_UID" "$WORKER_GID" "$ccp_control_gid" \
        >"$WORK/content-replication-publication-application.json" \
        2>"$WORK/content-replication-publication-fetch.err" || fail CONTENT_PUBLICATION_FETCH_FAILED
    [ "$(stat -Lc '%a:%u:%g' "$ccp_destination")" = "700:$AGENT_UID:$AGENT_GID" ] \
        || fail CONTENT_PUBLICATION_DESTINATION_OWNERSHIP
    content_replication_snapshot client content-replication-publication-final-live || fail CONTENT_PUBLICATION_PATHS_MISSING
    stop_privacy_observers || fail CONTENT_PUBLICATION_CAPTURE_INCOMPLETE
    content_replication_disconnect client content-replication-publication-final || fail CONTENT_PUBLICATION_DISCONNECT_FAILED
    content_replication_cli relay4 content stop >"$WORK/content-replication-publication-stop.json" \
        2>"$WORK/content-replication-publication-stop.err" || fail CONTENT_PUBLICATION_STOP_FAILED
    content_contribution_publish_cleanup || fail CONTENT_PUBLICATION_USER_CLEANUP_FAILED
}
