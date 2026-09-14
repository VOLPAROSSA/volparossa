#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the guarded disposable content-provider scenario.
# Adds one ordinary user publication; existing complementary stores/HTTPS remain unchanged.
# shellcheck disable=SC2154,SC2034

content_publication_cli() {
    publication_socket_node=$1
    shift
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$publication_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$publication_socket_node/control/agent.sock" "$@"
}

content_publication_cleanup() {
    # Exact secrets/known fixture bytes only. Cache roots are not moved, adopted or swept.
    publication_cleanup_private=$WORK/client-fixtures/publication-user/private
    [ ! -L "$publication_cleanup_private" ] || return 1
    if [ -e "$publication_cleanup_private" ]; then
        [ -d "$publication_cleanup_private" ] \
            && [ "$(stat -Lc '%a:%u:%g' "$publication_cleanup_private")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || return 1
        for publication_secret in identity.key passphrase input.bin output.bin; do
            publication_secret=$publication_cleanup_private/$publication_secret
            [ ! -L "$publication_secret" ] || return 1
            if [ -e "$publication_secret" ]; then
                [ -f "$publication_secret" ] \
                    && [ "$(stat -Lc '%a:%u:%g' "$publication_secret")" = "600:$WORKER_UID:$WORKER_GID" ] \
                    || return 1
                rm -f -- "$publication_secret" || return 1
            fi
        done
        rmdir -- "$publication_cleanup_private" || return 1
    fi
    jq -n '{encrypted_identity_removed:true,passphrase_removed:true,
            input_and_output_removed:true,private_directory_removed:true}' \
        >"$WORK/content-provider-user-cleanup.json"
}

content_publication_run() {
    PHASE=content-provider-user-publication
    publication_node=$provider_node_a
    case $publication_node in
        relay4) publication_address=49.165.5.1; publication_hostname=provider-a.volparossa.test ;;
        relay5) publication_address=50.166.6.1; publication_hostname=provider-b.volparossa.test ;;
        relay3) publication_address=48.164.4.1; publication_hostname=provider-c.volparossa.test ;;
        *) fail CONTENT_PUBLICATION_PROVIDER_INVALID ;;
    esac
    publication_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $publication_control_gid in ''|*[!0-9]*) fail CONTENT_PUBLICATION_CONTROL_GROUP_INVALID ;; esac
    [ "$publication_control_gid" != "$AGENT_GID" ] || fail CONTENT_PUBLICATION_CONTROL_GROUP_INVALID
    publication_user=$WORK/client-fixtures/publication-user
    publication_private=$publication_user/private
    publication_manifest=$publication_user/manifest.bin
    publication_agent=$WORK/state-$publication_node/user-publication-cache
    publication_remote=$WORK/state-client/user-publication-cache
    publication_remote_output=$WORK/state-client/user-publication.bin
    for publication_new in "$publication_user" "$publication_agent" "$publication_remote" \
        "$publication_remote_output"; do
        if [ -e "$publication_new" ] || [ -L "$publication_new" ]; then
            fail CONTENT_PUBLICATION_PATH_NOT_NEW
        fi
    done
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$publication_user"
    # shellcheck disable=SC2016 # Expand only the positional path within the unprivileged shell.
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- sh -eu -c 'umask 077; mkdir -m 0700 -- "$1"; set -C;
            head -c 48 /dev/urandom | base64 > "$1/passphrase"' sh "$publication_private" \
        >"$WORK/content-provider-user-init.log" 2>&1 || fail CONTENT_PUBLICATION_PRIVATE_STATE_FAILED
    content_publication_cli "$publication_node" init --identity "$publication_private/identity.key" \
        --passphrase-file "$publication_private/passphrase" \
        >>"$WORK/content-provider-user-init.log" 2>&1 || fail CONTENT_PUBLICATION_IDENTITY_INIT_FAILED
    publication_identity_digest=$(sha256sum "$publication_private/identity.key" | awk '{print $1}')
    # Known public test bytes already verified by the independent 5+4-shard proof. Only the
    # ordinary input file is copied; the new publisher creates/signs its own cache and manifest.
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0600 "$provider_client/object.bin" \
        "$publication_private/input.bin"
    [ "$(sha256sum "$publication_private/input.bin" | awk '{print $1}')" = \
        add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767 ] \
        || fail CONTENT_PUBLICATION_INPUT_CHANGED
    content_publication_cli "$publication_node" content publish --input "$publication_private/input.bin" \
        --name disposable-user-publication --revision 1 --content-type application/octet-stream \
        --identity "$publication_private/identity.key" --passphrase-file "$publication_private/passphrase" \
        --cache "$publication_user/source-cache" --manifest "$publication_manifest" \
        >"$WORK/content-provider-user-publish.json" 2>"$WORK/content-provider-user-publish.err" \
        || fail CONTENT_PUBLICATION_PUBLISH_FAILED
    publication_publisher=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-provider-user-publish.json") || fail CONTENT_PUBLICATION_PUBLISHER_INVALID
    [ "$publication_publisher" != "$provider_publisher" ] || fail CONTENT_PUBLICATION_FIXTURE_KEY_REUSED
    content_publication_cli "$publication_node" content import --public-content \
        --manifest "$publication_manifest" --publisher-key "$publication_publisher" \
        --cache "$publication_user/source-cache" --agent-cache "$publication_agent" \
        >"$WORK/content-provider-user-import.json" 2>"$WORK/content-provider-user-import.err" \
        || fail CONTENT_PUBLICATION_IMPORT_FAILED
    content_publication_cli "$publication_node" content serve --manifest "$publication_manifest" \
        --publisher-key "$publication_publisher" --cache "$publication_agent" \
        --bind "$publication_address:18080" --advertised-hostname "$publication_hostname" \
        >"$WORK/content-provider-user-serve.json" 2>"$WORK/content-provider-user-serve.err" \
        || fail CONTENT_PUBLICATION_SERVE_FAILED

    PHASE=content-provider-user-fetch
    start_privacy_observers content-provider-user-privacy || fail CONTENT_PUBLICATION_CAPTURE_UNAVAILABLE
    timeout --signal=TERM --kill-after=5s 120s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$publication_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch --manifest "$publication_manifest" --publisher-key "$publication_publisher" \
        --cache "$publication_remote" --output "$publication_remote_output" \
        >"$WORK/content-provider-user-fetch.json" 2>"$WORK/content-provider-user-fetch.err" \
        || fail CONTENT_PUBLICATION_REMOTE_FETCH_FAILED
    benchmark_capture_paths content-provider-user mptcp || fail CONTENT_PUBLICATION_LIVE_PATHS_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_PUBLICATION_CAPTURE_INCOMPLETE
    content_publication_cli client content export --public-content --manifest "$publication_manifest" \
        --publisher-key "$publication_publisher" --agent-cache "$publication_remote" \
        --cache "$publication_user/received-cache" \
        >"$WORK/content-provider-user-export.json" 2>"$WORK/content-provider-user-export.err" \
        || fail CONTENT_PUBLICATION_EXPORT_FAILED
    content_publication_cli client content assemble --manifest "$publication_manifest" \
        --publisher-key "$publication_publisher" --cache "$publication_user/received-cache" \
        --output "$publication_private/output.bin" \
        >"$WORK/content-provider-user-assemble.json" 2>"$WORK/content-provider-user-assemble.err" \
        || fail CONTENT_PUBLICATION_ASSEMBLE_FAILED
    publication_output_sha=$(sha256sum "$publication_private/output.bin" | awk '{print $1}')
    publication_output_bytes=$(stat -Lc '%s' "$publication_private/output.bin")
    [ "$(sha256sum "$publication_remote_output" | awk '{print $1}')" = "$publication_output_sha" ] \
        || fail CONTENT_PUBLICATION_REMOTE_OUTPUT_CHANGED
    [ "$(sha256sum "$publication_private/identity.key" | awk '{print $1}')" = "$publication_identity_digest" ] \
        || fail CONTENT_PUBLICATION_IDENTITY_CHANGED
    for publication_user_cache in "$publication_user/source-cache" "$publication_user/received-cache"; do
        [ "$(stat -Lc '%a:%u:%g' "$publication_user_cache")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || fail CONTENT_PUBLICATION_USER_CACHE_OWNERSHIP
    done
    for publication_agent_cache in "$publication_agent" "$publication_remote"; do
        [ "$(stat -Lc '%a:%u:%g' "$publication_agent_cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
            || fail CONTENT_PUBLICATION_AGENT_CACHE_OWNERSHIP
        if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$publication_control_gid" \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$publication_agent_cache"; then fail CONTENT_PUBLICATION_AGENT_CACHE_EXPOSED; fi
    done
    for publication_user_secret in "$publication_private/identity.key" "$publication_private/passphrase" \
        "$publication_private/output.bin"; do
        [ "$(stat -Lc '%a:%u:%g' "$publication_user_secret")" = "600:$WORKER_UID:$WORKER_GID" ] \
            || fail CONTENT_PUBLICATION_PRIVATE_FILE_OWNERSHIP
    done
    if setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$publication_user"; then fail CONTENT_PUBLICATION_USER_STATE_EXPOSED; fi
    # Actual consumer mount still hides the provider, despite both services sharing a UID.
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$publication_agent"; then fail CONTENT_PUBLICATION_LOCAL_CACHE_SHORTCUT; fi
    jq -n --arg provider_node "$publication_node" --arg sha256 "$publication_output_sha" \
        --arg context "$provider_context" --argjson bytes "$publication_output_bytes" \
        --argjson user_uid "$WORKER_UID" --argjson agent_uid "$AGENT_UID" \
        --argjson control_gid "$publication_control_gid" --argjson agent_gid "$AGENT_GID" \
        '{provider_node:$provider_node,sha256:$sha256,bytes:$bytes,route_context_id:$context,
          user_uid:$user_uid,agent_uid:$agent_uid,control_gid:$control_gid,agent_gid:$agent_gid,
          fresh_destination_cache:true,agent_cannot_read_user_state:true,user_cannot_read_agent_caches:true,
          client_mount_cannot_read_provider_cache:true,encrypted_identity_unchanged:true,
          cache_modes:"0700",output_mode:"0600",publisher_process_exited_before_fetch:true,
          explicit_public_fixture:true,https_origin_authenticated:false,mailbox_claimed:false}' \
        >"$WORK/content-provider-user-object.json"
    content_publication_cleanup || fail CONTENT_PUBLICATION_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/content-provider-smoke.py" \
        user-publication "$WORK" "$WORK/content-provider-user-publication.json" \
        || fail CONTENT_PUBLICATION_EVIDENCE_INVALID
}
