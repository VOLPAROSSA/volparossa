#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive normal private sender/service/network/recipient proof in the guarded KVM scenario.
# The earlier complementary 5+4 replica proof remains unchanged. No mailbox is claimed.
# shellcheck disable=SC2154,SC2034 # Exact disposable state and lifecycle belong to the parent.

content_message_publication_cli() {
    message_control_node=$1
    shift
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$content_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$message_control_node/control/agent.sock" "$@"
}

content_message_publication_cleanup() {
    # Only this fixture's new sender secrets; no recursive removal or cache adoption.
    message_cleanup_private=$WORK/client-fixtures/message-publication/private
    [ ! -L "$message_cleanup_private" ] || return 1
    if [ -e "$message_cleanup_private" ]; then
        [ -d "$message_cleanup_private" ] \
            && [ "$(stat -Lc '%a:%u:%g' "$message_cleanup_private")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || return 1
        for message_secret in identity.key passphrase input.bin; do
            message_secret=$message_cleanup_private/$message_secret
            [ ! -L "$message_secret" ] || return 1
            if [ -e "$message_secret" ]; then
                [ -f "$message_secret" ] \
                    && [ "$(stat -Lc '%a:%u:%g' "$message_secret")" = "600:$WORKER_UID:$WORKER_GID" ] \
                    || return 1
                rm -f -- "$message_secret" || return 1
            fi
        done
        rmdir -- "$message_cleanup_private" || return 1
    fi
    jq -n '{encrypted_sender_identity_removed:true,sender_passphrase_removed:true,
            sender_input_removed:true,sender_private_directory_removed:true}' \
        >"$WORK/content-message-publication-sender-cleanup.json"
}

content_message_publication_setup() {
    PHASE=content-message-publication-selection
    benchmark_select_route content-message-publication mptcp \
        || fail CONTENT_MESSAGE_PUBLICATION_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/content-message-publication-selection.json" \
        || fail CONTENT_MESSAGE_PUBLICATION_ROUTE_INVALID
    provider_context=$(jq -er '.route_context_id' "$WORK/content-message-publication-selection.json")
    content_message_publication_cli client content status \
        >"$WORK/content-message-publication-status-before.json" \
        2>"$WORK/content-message-publication-status-before.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id | select(type == "string" and length > 0)' \
        "$WORK/content-message-publication-status-before.json") \
        || fail CONTENT_MESSAGE_PUBLICATION_CONTROL_INVALID
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '
        . as $peers | ["relay4", "relay5", "relay3"]
        | map(select($peers[.] != $control)) | .[:2] | select(length == 2)' \
        "$WORK/a01-expected-peers.json") || fail CONTENT_MESSAGE_PUBLICATION_PROVIDER_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    jq -n --argjson nodes "$provider_nodes" --arg control "$provider_control_peer" \
        '{provider_nodes:$nodes,control_relay_peer_id:$control}' \
        >"$WORK/content-message-publication-layout.json"
    # Existing bounded fixture links admit generic QUIC control only, never content payload.
    content_provider_control_underlay
    case $provider_node_a in
        relay4) message_address=49.165.5.1; message_hostname=provider-a.volparossa.test ;;
        relay5) message_address=50.166.6.1; message_hostname=provider-b.volparossa.test ;;
        relay3) message_address=48.164.4.1; message_hostname=provider-c.volparossa.test ;;
        *) fail CONTENT_MESSAGE_PUBLICATION_PROVIDER_INVALID ;;
    esac
    message_user=$WORK/client-fixtures/message-publication
    message_sender_private=$message_user/private
    message_manifest=$message_user/manifest.bin
    message_agent=$WORK/state-$provider_node_a/message-publication-cache
    message_remote=$WORK/state-client/message-publication-cache
    message_remote_object=$WORK/state-client/message-publication-ciphertext.bin
    for message_new in "$message_user" "$message_agent" "$message_remote" "$message_remote_object"; do
        if [ -e "$message_new" ] || [ -L "$message_new" ]; then
            fail CONTENT_MESSAGE_PUBLICATION_PATH_NOT_NEW
        fi
    done
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$message_user"
    # shellcheck disable=SC2016 # Positional path expands only inside the unprivileged shell.
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- sh -eu -c 'umask 077; mkdir -m 0700 -- "$1"; set -C;
            head -c 48 /dev/urandom | base64 > "$1/passphrase"' sh "$message_sender_private" \
        >"$WORK/content-message-publication-init.log" 2>&1 \
        || fail CONTENT_MESSAGE_PUBLICATION_PRIVATE_STATE_FAILED
    content_message_publication_cli "$provider_node_a" init --identity "$message_sender_private/identity.key" \
        --passphrase-file "$message_sender_private/passphrase" \
        >>"$WORK/content-message-publication-init.log" 2>&1 \
        || fail CONTENT_MESSAGE_PUBLICATION_IDENTITY_FAILED
    message_identity_digest=$(sha256sum "$message_sender_private/identity.key" | awk '{print $1}')
    # Ordinary input only: known bytes from the separately proved original message, not its cache/key.
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0600 "$content_plaintext" "$message_sender_private/input.bin"
    content_message_publication_cli "$provider_node_a" content publish-message \
        --input "$message_sender_private/input.bin" --recipient-key "$content_recipient_public" \
        --identity "$message_sender_private/identity.key" --passphrase-file "$message_sender_private/passphrase" \
        --cache "$message_user/source-cache" --manifest "$message_manifest" \
        >"$WORK/content-message-publication-publish.json" 2>"$WORK/content-message-publication-publish.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_PUBLISH_FAILED
    message_sender=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-message-publication-publish.json") || fail CONTENT_MESSAGE_PUBLICATION_SENDER_INVALID
    [ "$message_sender" != "$content_publisher" ] || fail CONTENT_MESSAGE_PUBLICATION_FIXTURE_KEY_REUSED
    content_message_publication_cli "$provider_node_a" content import --manifest "$message_manifest" \
        --publisher-key "$message_sender" --cache "$message_user/source-cache" --agent-cache "$message_agent" \
        >"$WORK/content-message-publication-import.json" 2>"$WORK/content-message-publication-import.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_IMPORT_FAILED
    content_message_publication_cli "$provider_node_a" content serve --manifest "$message_manifest" \
        --publisher-key "$message_sender" --cache "$message_agent" --bind "$message_address:18080" \
        --advertised-hostname "$message_hostname" \
        >"$WORK/content-message-publication-serve.json" 2>"$WORK/content-message-publication-serve.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_SERVE_FAILED
    [ "$(sha256sum "$message_sender_private/identity.key" | awk '{print $1}')" = "$message_identity_digest" ] \
        || fail CONTENT_MESSAGE_PUBLICATION_IDENTITY_CHANGED
    if setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$message_user"; then fail CONTENT_MESSAGE_PUBLICATION_SENDER_STATE_EXPOSED; fi
    # Sender command has exited; remove its encrypted identity, passphrase and input BEFORE retrieval.
    content_message_publication_cleanup || fail CONTENT_MESSAGE_PUBLICATION_SENDER_CLEANUP_FAILED
}

content_message_publication_open() {
    PHASE=content-message-publication-recipient
    content_message_publication_cli client content export --manifest "$message_manifest" \
        --publisher-key "$message_sender" --agent-cache "$message_remote" --cache "$message_user/received-cache" \
        >"$WORK/content-message-publication-export.json" 2>"$WORK/content-message-publication-export.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_EXPORT_FAILED
    if content_network_recipient_cli content open-message --manifest "$message_manifest" \
        --sender-key "$message_sender" --cache "$message_user/received-cache" \
        --identity "$content_private/wrong-identity.key" --passphrase-file "$content_private/passphrase" \
        --output "$content_private/network-wrong-message.bin" \
        >"$WORK/content-message-publication-wrong.out" 2>"$WORK/content-message-publication-wrong.err"; then
        fail CONTENT_MESSAGE_PUBLICATION_WRONG_RECIPIENT_ACCEPTED
    fi
    if [ -e "$content_private/network-wrong-message.bin" ] || [ -L "$content_private/network-wrong-message.bin" ]; then
        fail CONTENT_MESSAGE_PUBLICATION_WRONG_OUTPUT_CREATED
    fi
    content_network_recipient_cli content open-message --manifest "$message_manifest" \
        --sender-key "$message_sender" --cache "$message_user/received-cache" \
        --identity "$content_private/identity.key" --passphrase-file "$content_private/passphrase" \
        --output "$content_private/network-message.bin" \
        >"$WORK/content-message-publication-open.json" 2>"$WORK/content-message-publication-open.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_OPEN_FAILED
    message_output_sha=$(sha256sum "$content_private/network-message.bin" | awk '{print $1}')
    [ "$message_output_sha" = "$content_plaintext_digest" ] || fail CONTENT_MESSAGE_PUBLICATION_BYTES_CHANGED
    if content_network_recipient_cli content open-message --manifest "$message_manifest" \
        --sender-key "$message_sender" --cache "$message_user/received-cache" \
        --identity "$content_private/identity.key" --passphrase-file "$content_private/passphrase" \
        --output "$content_private/network-message.bin" \
        >"$WORK/content-message-publication-no-clobber.out" 2>"$WORK/content-message-publication-no-clobber.err"; then
        fail CONTENT_MESSAGE_PUBLICATION_OUTPUT_OVERWRITTEN
    fi
    if [ "$(sha256sum "$content_private/network-message.bin" | awk '{print $1}')" != "$message_output_sha" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$content_private/network-message.bin")" != "600:$WORKER_UID:$WORKER_GID" ] \
        || [ "$(sha256sum "$content_private/identity.key" | awk '{print $1}')" != "$content_identity_digest" ] \
        || [ "$(sha256sum "$content_private/wrong-identity.key" | awk '{print $1}')" != "$content_wrong_identity_digest" ]; then
        fail CONTENT_MESSAGE_PUBLICATION_RECIPIENT_STATE_CHANGED
    fi
}

content_message_publication_run() {
    content_message_publication_setup
    PHASE=content-message-publication-fetch
    message_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $message_client_pid in ''|0|*[!0-9]*) fail CONTENT_MESSAGE_PUBLICATION_CLIENT_PID_INVALID ;; esac
    # Prove this exact namespace/UID/command works before interpreting unreadable paths.
    # Only permission is checked; the encrypted service identity is never read or exported.
    nsenter --target "$message_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" \
        || fail CONTENT_MESSAGE_PUBLICATION_ISOLATION_PROBE_UNAVAILABLE
    for message_hidden in "$message_agent" "$message_user"; do
        if nsenter --target "$message_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$message_hidden"; then fail CONTENT_MESSAGE_PUBLICATION_LOCAL_CACHE_SHORTCUT; fi
    done
    start_privacy_observers content-message-publication-privacy \
        || fail CONTENT_MESSAGE_PUBLICATION_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer content-provider-message-control-privacy \
        || fail CONTENT_MESSAGE_PUBLICATION_CONTROL_CAPTURE_UNAVAILABLE
    timeout --signal=TERM --kill-after=5s 120s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$content_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        content fetch --manifest "$message_manifest" --publisher-key "$message_sender" \
        --cache "$message_remote" --output "$message_remote_object" \
        >"$WORK/content-message-publication-fetch.json" 2>"$WORK/content-message-publication-fetch.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_FETCH_FAILED
    benchmark_capture_paths content-message-publication-live mptcp \
        || fail CONTENT_MESSAGE_PUBLICATION_LIVE_PATHS_UNAVAILABLE
    stop_privacy_observers || fail CONTENT_MESSAGE_PUBLICATION_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail CONTENT_MESSAGE_PUBLICATION_CONTROL_CAPTURE_INCOMPLETE
    content_message_publication_open
    for message_cache in "$message_agent" "$message_remote"; do
        [ "$(stat -Lc '%a:%u:%g' "$message_cache")" = "700:$AGENT_UID:$AGENT_GID" ] \
            || fail CONTENT_MESSAGE_PUBLICATION_SERVICE_CACHE_MODE_CHANGED
        if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$content_control_gid" \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$message_cache"; then fail CONTENT_MESSAGE_PUBLICATION_SERVICE_CACHE_EXPOSED; fi
    done
    for message_cache in "$message_user/source-cache" "$message_user/received-cache"; do
        [ "$(stat -Lc '%a:%u:%g' "$message_cache")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || fail CONTENT_MESSAGE_PUBLICATION_USER_CACHE_MODE_CHANGED
    done
    content_message_publication_cli "$provider_node_a" content stop \
        >"$WORK/content-message-publication-stop.json" 2>"$WORK/content-message-publication-stop.err" \
        || fail CONTENT_MESSAGE_PUBLICATION_STOP_FAILED
    benchmark_disconnect_route content-message-publication || fail CONTENT_MESSAGE_PUBLICATION_ROUTE_CLEANUP_FAILED
    jq -n --arg provider_node "$provider_node_a" --arg sha256 "$message_output_sha" \
        --arg ciphertext_sha256 "$(sha256sum "$message_remote_object" | awk '{print $1}')" \
        --argjson ciphertext_bytes "$(stat -Lc '%s' "$message_remote_object")" \
        --arg context "$provider_context" --argjson user_uid "$WORKER_UID" --argjson agent_uid "$AGENT_UID" \
        --argjson control_gid "$content_control_gid" --argjson agent_gid "$AGENT_GID" \
        '{provider_node:$provider_node,plaintext_sha256:$sha256,plaintext_bytes:2097275,
          ciphertext_sha256:$ciphertext_sha256,ciphertext_bytes:$ciphertext_bytes,route_context_id:$context,
          user_uid:$user_uid,agent_uid:$agent_uid,control_gid:$control_gid,agent_gid:$agent_gid,
          cache_modes:"0700",output_mode:"0600",sender_identity_unchanged_before_removal:true,
          sender_removed_before_fetch:true,agent_cannot_read_sender_state:true,
          client_mount_positive_control:true,client_mount_cannot_read_provider_cache:true,
          user_cannot_read_agent_caches:true,
          fresh_destination_cache:true,wrong_recipient_rejected:true,wrong_recipient_output_absent:true,
          no_clobber_verified:true,recipient_identities_unchanged:true,
          recipient_key_independently_supplied:true,mailbox_claimed:false}' \
        >"$WORK/content-message-publication-object.json"
}
