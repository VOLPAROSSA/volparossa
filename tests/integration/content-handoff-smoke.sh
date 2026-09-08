#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the guarded disposable KVM message scenario, after real recipient opening.
# This adds a cross-UID local operation proof, not another network-publisher claim.
# shellcheck disable=SC2154,SC2034

content_handoff_cli() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$content_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-relay4/control/agent.sock" "$@"
}

content_network_handoff() {
    PHASE=content-private-cache-handoff
    content_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $content_control_gid in ''|*[!0-9]*) fail CONTENT_CONTROL_GROUP_INVALID ;; esac
    [ "$content_control_gid" != "$AGENT_GID" ] || fail CONTENT_CONTROL_GROUP_INVALID
    content_sender=$(jq -er '.identity_public_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-wrong-recipient.json") || fail CONTENT_HANDOFF_SENDER_INVALID
    content_handoff_source=$content_client_root/handoff-source
    content_handoff_return=$content_client_root/handoff-return
    content_handoff_agent=$WORK/state-relay4/message-handoff
    content_handoff_manifest=$content_client_root/handoff-manifest.bin
    content_handoff_cli content status >"$WORK/content-handoff-status-before.json" \
        2>"$WORK/content-handoff-status-before.err" || fail CONTENT_HANDOFF_CONTROL_UNAVAILABLE
    content_network_recipient_cli content publish-message --input "$content_plaintext" \
        --recipient-key "$content_recipient_public" --identity "$content_private/wrong-identity.key" \
        --passphrase-file "$content_private/passphrase" --cache "$content_handoff_source" \
        --manifest "$content_handoff_manifest" \
        >"$WORK/content-handoff-publish.json" 2>"$WORK/content-handoff-publish.err" \
        || fail CONTENT_HANDOFF_PUBLISH_FAILED
    # Only the control group is granted. Neither account may open the other's private files.
    for content_user_private in "$content_handoff_source" "$content_plaintext" \
        "$content_private/passphrase" "$content_private/wrong-identity.key"; do
        if setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$content_user_private"; then fail CONTENT_HANDOFF_USER_STATE_EXPOSED; fi
    done
    content_handoff_cli content import --manifest "$content_handoff_manifest" \
        --publisher-key "$content_sender" --cache "$content_handoff_source" \
        --agent-cache "$content_handoff_agent" \
        >"$WORK/content-handoff-import.json" 2>"$WORK/content-handoff-import.err" \
        || fail CONTENT_HANDOFF_IMPORT_FAILED
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$content_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$content_handoff_agent"; then fail CONTENT_HANDOFF_SERVICE_STATE_EXPOSED; fi
    content_handoff_cli content export --manifest "$content_handoff_manifest" \
        --publisher-key "$content_sender" --agent-cache "$content_handoff_agent" \
        --cache "$content_handoff_return" \
        >"$WORK/content-handoff-export.json" 2>"$WORK/content-handoff-export.err" \
        || fail CONTENT_HANDOFF_EXPORT_FAILED
    content_network_recipient_cli content open-message --manifest "$content_handoff_manifest" \
        --sender-key "$content_sender" --cache "$content_handoff_return" \
        --identity "$content_private/identity.key" --passphrase-file "$content_private/passphrase" \
        --output "$content_private/handoff-message.bin" \
        >"$WORK/content-handoff-open.json" 2>"$WORK/content-handoff-open.err" \
        || fail CONTENT_HANDOFF_OPEN_FAILED
    content_handoff_sha=$(sha256sum "$content_private/handoff-message.bin" | awk '{print $1}')
    [ "$content_handoff_sha" = "$content_plaintext_digest" ] || fail CONTENT_HANDOFF_BYTES_CHANGED
    if [ "$(stat -Lc '%a:%u:%g' "$content_handoff_source")" != "700:$WORKER_UID:$WORKER_GID" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$content_handoff_return")" != "700:$WORKER_UID:$WORKER_GID" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$content_handoff_agent")" != "700:$AGENT_UID:$AGENT_GID" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$content_private/handoff-message.bin")" != "600:$WORKER_UID:$WORKER_GID" ]; then
        fail CONTENT_HANDOFF_OWNERSHIP_CHANGED
    fi
    if [ "$(sha256sum "$content_private/identity.key" | awk '{print $1}')" != "$content_identity_digest" ] \
        || [ "$(sha256sum "$content_private/wrong-identity.key" | awk '{print $1}')" != "$content_wrong_identity_digest" ]; then
        fail CONTENT_HANDOFF_IDENTITY_CHANGED
    fi
    content_handoff_cli content status >"$WORK/content-handoff-status-after.json" \
        2>"$WORK/content-handoff-status-after.err" || fail CONTENT_HANDOFF_CONTROL_UNAVAILABLE
    jq -n --argjson user_uid "$WORKER_UID" --argjson agent_uid "$AGENT_UID" \
        --argjson control_gid "$content_control_gid" --argjson agent_gid "$AGENT_GID" \
        --arg plaintext_sha256 "$content_handoff_sha" \
        '{user_uid:$user_uid,agent_uid:$agent_uid,control_gid:$control_gid,agent_gid:$agent_gid,
          agent_cannot_read_user_cache_or_secrets:true,user_cannot_read_agent_cache:true,
          all_cache_modes:"0700",private_output_mode:"0600",identities_unchanged:true,
          plaintext_sha256:$plaintext_sha256,local_only:true}' \
        >"$WORK/content-handoff-isolation.json"
}
