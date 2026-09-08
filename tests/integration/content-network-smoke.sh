#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the exact-build disposable KVM topology. No host networking actions.
# shellcheck disable=SC2154,SC2034 # Guarded parent owns process slots, identities and cleanup.

content_network_event_after() {
    awk -v baseline="$content_baseline_ms" -v event="event=$2" '
        $1 ~ /^[0-9]+$/ && $1 > baseline && $3 == event { found=1 }
        END { exit !found }
    ' "$WORK/logs-$1.txt"
}

content_network_recipient_cli() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" "$@"
}

content_network_recipient_init() {
    PHASE=content-recipient-init
    content_private=$content_client_root/private
    # New WORKER-only state, never the agent identity or a raw recipient private-key file.
    # shellcheck disable=SC2016 # Positional path is expanded only inside the WORKER shell.
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- sh -eu -c 'umask 077; mkdir -m 0700 -- "$1"; set -C;
            head -c 48 /dev/urandom | base64 > "$1/passphrase"' sh "$content_private" \
        >"$WORK/content-recipient-state.log" 2>&1 || fail CONTENT_RECIPIENT_STATE_FAILED
    for content_identity in identity.key wrong-identity.key; do
        content_network_recipient_cli init --identity "$content_private/$content_identity" \
            --passphrase-file "$content_private/passphrase" \
            >>"$WORK/content-recipient-init.log" 2>&1 || fail CONTENT_RECIPIENT_INIT_FAILED
    done
    [ "$(stat -Lc '%a:%u:%g' "$content_private")" = "700:$WORKER_UID:$WORKER_GID" ] \
        || fail CONTENT_RECIPIENT_KEY_PERMISSIONS_INVALID
    for content_secret in "$content_private/identity.key" "$content_private/wrong-identity.key" \
        "$content_private/passphrase"; do
        if [ -L "$content_secret" ] || [ ! -f "$content_secret" ] \
            || [ "$(stat -Lc '%a:%u:%g' "$content_secret")" != "600:$WORKER_UID:$WORKER_GID" ]; then
            fail CONTENT_RECIPIENT_KEY_PERMISSIONS_INVALID
        fi
        if setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$content_secret"; then
            fail CONTENT_PROVIDER_CAN_READ_RECIPIENT_KEY
        fi
    done
    content_identity_digest=$(sha256sum "$content_private/identity.key" | awk '{print $1}')
    content_wrong_identity_digest=$(sha256sum "$content_private/wrong-identity.key" | awk '{print $1}')
    content_network_recipient_cli content recipient-key --identity "$content_private/identity.key" \
        --passphrase-file "$content_private/passphrase" \
        >"$WORK/content-recipient.json" 2>"$WORK/content-recipient.log" \
        || fail CONTENT_RECIPIENT_PUBLIC_KEY_FAILED
    content_network_recipient_cli content recipient-key --identity "$content_private/wrong-identity.key" \
        --passphrase-file "$content_private/passphrase" \
        >"$WORK/content-wrong-recipient.json" 2>"$WORK/content-wrong-recipient.log" \
        || fail CONTENT_WRONG_RECIPIENT_PUBLIC_KEY_FAILED
    content_recipient_public=$(jq -er '.recipient_public_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/content-recipient.json") || fail CONTENT_RECIPIENT_PUBLIC_KEY_INVALID
    jq -e --arg intended "$content_recipient_public" \
        '.recipient_public_key_hex != $intended and .private_key_exported == false' \
        "$WORK/content-wrong-recipient.json" >/dev/null || fail CONTENT_WRONG_RECIPIENT_NOT_DISTINCT
    jq -n --argjson recipient_uid "$WORKER_UID" --argjson provider_uid "$AGENT_UID" \
        '{recipient_uid:$recipient_uid,provider_uid:$provider_uid,
          private_directory_mode:"0700",encrypted_identity_mode:"0600",passphrase_mode:"0600",
          identity_created_by_normal_cli:true,identity_storage:"encrypted_identity_store",
          key_owned_by_recipient:true,key_unreadable_by_provider:true,
          passphrase_unreadable_by_provider:true,raw_recipient_private_key_file:false}' \
        >"$WORK/content-recipient-isolation.json"
}

content_network_private_cleanup() {
    # Exact fixture-owned paths only, including after interruption; no recursive removal.
    content_private=$WORK/client-fixtures/content/private
    if [ -L "$content_private" ]; then return 1; fi
    if [ -e "$content_private" ]; then
        [ -d "$content_private" ] || return 1
        [ "$(stat -Lc '%a:%u:%g' "$content_private")" = "700:$WORKER_UID:$WORKER_GID" ] \
            || return 1
        for content_secret in "$content_private/identity.key" "$content_private/wrong-identity.key" \
            "$content_private/passphrase" "$content_private/message.bin" "$content_private/wrong-message.bin" \
            "$content_private/handoff-message.bin" "$content_private/handoff-public.bin"; do
            [ ! -L "$content_secret" ] || return 1
            if [ -e "$content_secret" ]; then
                [ -f "$content_secret" ] || return 1
                [ "$(stat -Lc '%a:%u:%g' "$content_secret")" = "600:$WORKER_UID:$WORKER_GID" ] \
                    || return 1
                rm -f -- "$content_secret" || return 1
            fi
        done
        # Unexpected leftover files are a failed fixture cleanup, never silently ignored.
        rmdir -- "$content_private" || return 1
    fi
    jq -n '{encrypted_identities_removed:true,passphrase_removed:true,
            plaintext_removed:true,private_directory_removed:true}' \
        >"$WORK/content-private-cleanup.json"
}

content_network_open_message() {
    PHASE=content-recipient-decryption
    content_private=$content_client_root/private
    if content_network_recipient_cli content open-message \
        --identity "$content_private/wrong-identity.key" --passphrase-file "$content_private/passphrase" \
        --manifest "$WORK/client-fixtures/content-manifest.bin" --sender-key "$content_publisher" \
        --cache "$content_client_root/cache" --output "$content_private/wrong-message.bin" \
        >"$WORK/content-wrong-message.out" 2>"$WORK/content-wrong-message.err"; then
        fail CONTENT_WRONG_RECIPIENT_ACCEPTED
    fi
    if [ -e "$content_private/wrong-message.bin" ] || [ -L "$content_private/wrong-message.bin" ]; then
        fail CONTENT_WRONG_RECIPIENT_OUTPUT_CREATED
    fi
    content_network_recipient_cli content open-message \
        --identity "$content_private/identity.key" --passphrase-file "$content_private/passphrase" \
        --manifest "$WORK/client-fixtures/content-manifest.bin" --sender-key "$content_publisher" \
        --cache "$content_client_root/cache" --output "$content_private/message.bin" \
        >"$WORK/content-message-cli-open.json" 2>"$WORK/content-message-open.log" \
        || fail CONTENT_RECIPIENT_DECRYPTION_FAILED
    content_plaintext=$content_client_root/private/message.bin
    if [ -L "$content_plaintext" ] || [ ! -f "$content_plaintext" ] \
        || [ "$(stat -Lc '%a:%u:%g' "$content_plaintext")" != "600:$WORKER_UID:$WORKER_GID" ]; then
        fail CONTENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID
    fi
    content_plaintext_digest=$(sha256sum "$content_plaintext" | awk '{print $1}')
    if content_network_recipient_cli content open-message \
        --identity "$content_private/identity.key" --passphrase-file "$content_private/passphrase" \
        --manifest "$WORK/client-fixtures/content-manifest.bin" --sender-key "$content_publisher" \
        --cache "$content_client_root/cache" --output "$content_plaintext" \
        >"$WORK/content-message-no-clobber.out" 2>"$WORK/content-message-no-clobber.err"; then
        fail CONTENT_PRIVATE_OUTPUT_OVERWRITTEN
    fi
    if [ "$(sha256sum "$content_plaintext" | awk '{print $1}')" != "$content_plaintext_digest" ] \
        || [ "$(sha256sum "$content_private/identity.key" | awk '{print $1}')" != "$content_identity_digest" ] \
        || [ "$(sha256sum "$content_private/wrong-identity.key" | awk '{print $1}')" != "$content_wrong_identity_digest" ]; then
        fail CONTENT_PRIVATE_IDENTITY_OR_OUTPUT_CHANGED
    fi
    jq -e '.operation == "offline_private_message_open" and .network_retrieval == false
        and .bytes == 2097275' "$WORK/content-message-cli-open.json" >/dev/null \
        || fail CONTENT_MESSAGE_CLI_RESULT_INVALID
    jq -n --arg sha256 "$content_plaintext_digest" \
        --argjson bytes "$(stat -Lc '%s' "$content_plaintext")" \
        '{plaintext_sha256:$sha256,plaintext_bytes:$bytes,normal_cli_open:true,
          wrong_recipient_rejected:true,wrong_recipient_output_absent:true,
          no_clobber_verified:true,encrypted_identities_unchanged:true}' \
        >"$WORK/content-message-open.json"
    # Only the hash/length of known public test bytes are exported, never the plaintext file.
    jq -n --arg sha256 "$(sha256sum "$content_plaintext" | awk '{print $1}')" \
        --argjson bytes "$(stat -Lc '%s' "$content_plaintext")" \
        '{plaintext_sha256:$sha256,plaintext_bytes:$bytes,private_output_mode:"0600",
          private_output_owned_by_recipient:true}' >"$WORK/content-message-object.json"
    content_network_handoff
    content_network_private_cleanup || fail CONTENT_PRIVATE_FIXTURE_CLEANUP_FAILED
}

content_network_phase() {
    content_replica=$1
    content_prefix=content-$content_replica
    PHASE=$content_prefix-selection
    benchmark_select_route "$content_prefix" mptcp || fail CONTENT_MPTCP_SELECTION_UNAVAILABLE
    benchmark_bind_slots "$WORK/$content_prefix-selection.json" \
        || fail CONTENT_MPTCP_SELECTION_INVALID
    content_context=$(jq -er '.route_context_id' "$WORK/$content_prefix-selection.json")

    PHASE=$content_prefix-provider
    content_provider_report=$WORK/destination/$content_prefix-provider.json
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$content_binary" serve "$content_root" "$content_replica" \
        47.163.4.2:18080 "$content_provider_report" \
        >"$WORK/$content_prefix-provider.log" 2>&1 &
    DESTINATION_PID=$!
    content_serving_pid=$DESTINATION_PID
    wait_observer "$DESTINATION_PID" "$content_provider_report.ready" \
        || fail CONTENT_PROVIDER_NOT_READY

    PHASE=$content_prefix-capture
    start_privacy_observers "$content_prefix-privacy" || fail CONTENT_PRIVACY_CAPTURE_UNAVAILABLE
    ip netns exec "$CLIENT" python3 "$WORK/bin/a02-observer.py" client \
        "$WORK/$content_prefix-client-capture.json" "$WORK/$content_prefix-client-capture.ready" - \
        --benchmark-relays "$BENCH_INDEX1" "$BENCH_INDEX2" \
        "$BENCH_CLIENT_IF1" "$BENCH_CLIENT_IF2" underlay \
        >"$WORK/$content_prefix-client-capture.log" 2>&1 &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a02-observer.py" exit \
        "$WORK/$content_prefix-exit-capture.json" "$WORK/$content_prefix-exit-capture.ready" - \
        --benchmark-relays "$BENCH_INDEX1" "$BENCH_INDEX2" \
        "$BENCH_EXIT_IF1" "$BENCH_EXIT_IF2" xd \
        >"$WORK/$content_prefix-exit-capture.log" 2>&1 &
    EXIT_OBSERVER_PID=$!
    if ! wait_observer "$CLIENT_OBSERVER_PID" "$WORK/$content_prefix-client-capture.ready" \
        || ! wait_observer "$EXIT_OBSERVER_PID" "$WORK/$content_prefix-exit-capture.ready"; then
        fail CONTENT_APPLICATION_CAPTURE_UNAVAILABLE
    fi
    capture_product_logs
    content_baseline_ms=$(client_log_baseline_ms) || fail CONTENT_EVENT_BASELINE_UNAVAILABLE

    PHASE=$content_prefix-fetch
    content_fetch_report=$WORK/client-fixtures/$content_prefix-fetch.json
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$content_binary" fetch "$content_client_root" \
        "$WORK/client-fixtures/content-manifest.bin" "$content_publisher" \
        47.163.4.2:18080 "$content_fetch_report" \
        >"$WORK/$content_prefix-fetch.log" 2>&1 &
    DOWNLOAD_CLIENT_PID=$!
    content_client_status=0
    wait "$DOWNLOAD_CLIENT_PID" || content_client_status=$?
    DOWNLOAD_CLIENT_PID=
    [ "$content_client_status" -eq 0 ] || fail CONTENT_NETWORK_FETCH_FAILED
    content_provider_status=0
    wait "$DESTINATION_PID" || content_provider_status=$?
    DESTINATION_PID=
    [ "$content_provider_status" -eq 0 ] || fail CONTENT_NETWORK_PROVIDER_FAILED
    if ! benchmark_capture_paths "$content_prefix-live" mptcp \
        || ! jq -e --arg context "$content_context" '.route_context_id == $context' \
            "$WORK/$content_prefix-live-selection.json" >/dev/null; then
        fail CONTENT_ROUTE_CHANGED_DURING_FETCH
    fi
    stop_observers || fail CONTENT_APPLICATION_CAPTURE_INCOMPLETE
    stop_privacy_observers || fail CONTENT_PRIVACY_CAPTURE_INCOMPLETE
    for content_attempt in 1 2 3 4 5 6 7 8 9 10; do
        capture_product_logs
        if content_network_event_after client INGRESS_TCP_STREAM_COMPLETED \
            && content_network_event_after exit MPTCP_EXIT_FLOW_COMPLETED; then
            break
        fi
        sleep 0.1
    done
    if ! content_network_event_after client INGRESS_TCP_STREAM_COMPLETED \
        || ! content_network_event_after exit MPTCP_EXIT_FLOW_COMPLETED; then
        fail CONTENT_PROTECTED_STREAM_NOT_PROVEN
    fi
    install -o root -g root -m 0600 "$content_fetch_report" "$WORK/$content_prefix-fetch.json"
    install -o root -g root -m 0600 "$content_provider_report" "$WORK/$content_prefix-provider.json"
    jq -n --argjson pid "$content_serving_pid" --argjson baseline "$content_baseline_ms" \
        '{serving_pid:$pid,publisher_process_exited_before_fetch:true,
          event_baseline_unix_ms:$baseline,ingress_completed:true,exit_mptcp_tls_open_completed:true}' \
        >"$WORK/$content_prefix-gates.json"
    # Close the exact completed route before choosing the next provider's protected route.
    benchmark_disconnect_route "$content_prefix" || fail CONTENT_ROUTE_CLEANUP_FAILED
}

content_network_run() {
    PHASE=content-seed
    content_binary=$binary_directory/examples/content-acceptance-fixture
    content_root=$WORK/content-seed/publication
    content_client_root=$WORK/client-fixtures/content
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$WORK/content-seed"
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$content_client_root"
    set -- seed "$content_root"
    if [ "$scenario" = content-message ]; then
        content_network_recipient_init
        set -- seed-private "$content_root" "$content_recipient_public"
    fi
    PHASE=content-seed
    # Persistent cache markers bind their creator UID and inode: do not chown a seeded store.
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- "$content_binary" "$@" \
        >"$WORK/content-seed.log" 2>&1 || fail CONTENT_SEED_FAILED
    install -o root -g root -m 0600 "$content_root/publication.json" "$WORK/content-publication.json"
    jq -e --arg scenario "$scenario" '.publisher_removed == true and .publisher_private_key_persisted == false
        and .chunks == 9 and .replica_a_chunks == 5 and .replica_b_chunks == 4
        and (if $scenario == "content-message" then .recipient_encrypted == true
                and .bytes >= 2097291 and .bytes <= 2098299
             else .bytes == 2097275 end)
        and (.publisher_hex | test("^[0-9a-f]{64}$"))
        and (.object_sha256 | test("^[0-9a-f]{64}$"))' \
        "$WORK/content-publication.json" >/dev/null || fail CONTENT_PUBLICATION_INVALID
    content_publisher=$(jq -er '.publisher_hex' "$WORK/content-publication.json")
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 "$content_root/manifest.bin" \
        "$WORK/client-fixtures/content-manifest.bin"
    if [ -e "$content_client_root/cache" ] || [ -e "$content_client_root/object.bin" ]; then
        fail CONTENT_CLIENT_CACHE_NOT_EMPTY
    fi
    # No client access to either replica or the removed publisher; only public trust metadata.
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$content_root/replica-a"; then
        fail CONTENT_REPLICA_ACCESS_NOT_ISOLATED
    fi
    kill -TERM "$DESTINATION_PID"
    wait "$DESTINATION_PID" 2>/dev/null || true
    DESTINATION_PID=
    content_network_phase a
    jq -e '.complete == false and .cached_chunks == 5 and .chunks_received == 5
        and .missing == 4 and .output_bytes == 0 and .object_sha256 == null' \
        "$WORK/content-a-fetch.json" >/dev/null || fail CONTENT_FIRST_REPLICA_NOT_PARTIAL
    [ ! -e "$content_client_root/object.bin" ] || fail CONTENT_PARTIAL_OUTPUT_PUBLISHED
    content_network_phase b
    sha256sum "$content_client_root/object.bin" | awk '{print $1}' >"$WORK/content-object-sha256.txt"
    jq -n --arg sha256 "$(cat "$WORK/content-object-sha256.txt")" \
        --argjson bytes "$(stat -Lc '%s' "$content_client_root/object.bin")" \
        '{sha256:$sha256,bytes:$bytes,client_cache_initially_absent:true,
          client_cannot_read_replica_stores:true,publisher_process_exited_before_fetch:true}' \
        >"$WORK/content-object.json"
    content_evidence_mode=evidence
    if [ "$scenario" = content-message ]; then
        content_network_open_message
        content_evidence_mode=message-evidence
    fi
    python3 -B "$source_directory/tests/integration/content-network-smoke.py" \
        "$content_evidence_mode" "$WORK" "$WORK/content-evidence.json" || fail CONTENT_NETWORK_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=content-complete
}

content_network_finalize_report() {
    content_status=$1
    content_evidence=$(optional_json_evidence "$WORK/content-evidence.json")
    content_host=$(optional_json_evidence "$WORK/a15-evidence.json")
    content_report_name=content-network-smoke.json
    content_report_kind=volparossa-native-content-network
    content_report_mode=report
    content_scope='two separate replica processes at one authorized destination through actual MPTCP/TLS/WireGuard; native signatures, not HTTPS origin authentication'
    if [ "$scenario" = content-message ]; then
        content_report_name=content-message-smoke.json
        content_report_kind=volparossa-native-private-content-network
        content_report_mode=message-report
        content_scope='ciphertext-only replicas over protected MPTCP with fixture network publisher; normal recipient CLI and separate private/public local publication handoff across operator/service UIDs; no mailbox runtime'
    fi
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --arg kind "$content_report_kind" --arg scope "$content_scope" --arg scenario "$scenario" \
        --argjson status "$content_status" --argjson evidence "$content_evidence" \
        --argjson host "$content_host" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:$kind,
       source_revision:$revision,run_id:$run_id,phase:$phase,
       success:($status == 0 and $evidence.success == true and $complete and
         $remaining == 0 and $host.unchanged == true),
       transfer:$evidence,runner_exit_status:$status,
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},
       host_state:($host | del(.acceptance_id)),
       scope:$scope,
       distinct_provider_nodes_claimed:false,provider_discovery_claimed:false,
       full_alpha_acceptance_claimed:false,https_authentication_claimed:false}
      + (if $scenario == "content-message" then
          {normal_recipient_cli_claimed:true,encrypted_identity_store_claimed:true,
           normal_publisher_cli_claimed:true,local_private_cache_handoff_claimed:true,
           local_public_cache_handoff_claimed:true,
           network_publisher_runtime_claimed:false,
           mailbox_runtime_claimed:false,full_c07_claimed:false}
         else {} end)
    ' >"$WORK/$content_report_name" || return 1
    for content_artifact in "$WORK"/content-*.json "$WORK"/content-*.txt \
        "$WORK"/content-*.log "$WORK"/content-*.out "$WORK"/content-*.err; do
        [ ! -f "$content_artifact" ] || [ -L "$content_artifact" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$content_artifact" \
                "$output_directory/$(basename -- "$content_artifact")"
    done
    python3 -B "$source_directory/tests/integration/content-network-smoke.py" \
        "$content_report_mode" "$WORK/$content_report_name" "$expected_commit"
}
