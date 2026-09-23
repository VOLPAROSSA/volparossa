#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only inside the explicitly disposable agent-jobs topology.
# shellcheck disable=SC2154,SC2034

agent_policy_assessment_cli() {
    policy_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $policy_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    timeout --signal=INT --kill-after=15s 3300s nsenter --target "$policy_cli_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_policy_cycle_cli() {
    set -- "$@"
    policy_authority=0
    for policy_node in relay3 relay4 relay5; do
        policy_authority_key=$(jq -er '.public_key_hex' "$WORK/agent-policy-assessment-object-authority-$policy_authority.json")
        policy_transport_key=$(jq -er '.identity_public_key_hex' "$WORK/agent-policy-assessment-authority-$policy_authority-public.json")
        set -- "$@" --authority "$policy_authority_key:$policy_transport_key:disposable-policy-reply-$policy_authority"
        policy_authority=$((policy_authority + 1))
    done
    agent_policy_assessment_cli compute peer policy-cycle \
        --policy-config "$WORK/config-client.yaml" --requester-key "$policy_requester" \
        --source-publisher-key "$jobs_publisher" --source-manifest-id "$policy_manifest" \
        --source-name disposable-policy-subject --cache "$jobs_source/policy-source-cache" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --model-profile smollm2-360m-v1 \
        --publication-key "$jobs_publisher" --identity "$jobs_source/identity.key" \
        --passphrase-file "$jobs_source/passphrase" --license CC0-1.0 \
        --request-name disposable-policy-request --publish-name disposable-object-policy --decision-revision 1 \
        --publication-provider-key "$jobs_key_a" --directory "$jobs_source/policy-cycle" \
        --worker-seconds 600 --round-seconds 600 --total-seconds 3000 --poll-seconds 1 \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 "$@"
}

agent_policy_object_probe() {
    policy_probe_phase=$1
    policy_probe_status=0
    agent_policy_assessment_cli content fetch-name --publisher-key "$jobs_publisher" \
        --name disposable-policy-subject --min-revision 1 --cache "$jobs_source/policy-source-cache" \
        --reuse-cache --cache-only --local-output "$jobs_source/policy-object-$policy_probe_phase.txt" \
        >"$WORK/agent-policy-assessment-object-$policy_probe_phase.json" \
        2>"$WORK/agent-policy-assessment-object-$policy_probe_phase.err" || policy_probe_status=$?
    python3 -B "$policy_script" object_probe "$WORK" "$policy_probe_phase" "$policy_probe_status" \
        || fail POLICY_OBJECT_ACCESS_DID_NOT_MATCH_REAL_OUTCOME
}

agent_policy_phase_start() {
    custody_phase=fetch
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail POLICY_CONTROL_BASELINE_MISSING
    start_privacy_observers content-custody-fetch-privacy || fail POLICY_PROTECTED_CAPTURE_FAILED
    content_provider_adaptive_start_control_observer content-provider-adaptive-policy-fetch-control \
        || fail POLICY_THREE_PROVIDER_CONTROL_CAPTURE_FAILED
}

agent_policy_authorities_start() {
    PHASE=agent-policy-assessment-authority-enrollment
    policy_authority_units=
    policy_authority=0
    for policy_node in relay3 relay4 relay5; do
        policy_owner_source=$WORK/state-$policy_node/compute-source
        policy_authority_root=$policy_owner_source/policy-authority-$policy_authority
        install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$policy_owner_source" "$policy_authority_root"
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/examples/acceptance-policy-fixture" "$policy_authority_root" \
            --authority-identity "$policy_authority" \
            >"$WORK/agent-policy-assessment-object-authority-$policy_authority.json" \
            2>"$WORK/agent-policy-assessment-object-authority-$policy_authority.err" \
            || fail POLICY_OBJECT_DEVELOPMENT_IDENTITY_FAILED
        policy_authority_key=$(jq -er '.public_key_hex' "$WORK/agent-policy-assessment-object-authority-$policy_authority.json")
        agent_jobs_cli "$policy_node" content recipient-key --identity "$WORK/state-$policy_node/identity.key" \
            --passphrase-file "$WORK/credential-$policy_node/identity-passphrase" \
            >"$WORK/agent-policy-assessment-authority-$policy_authority-public.json" || fail POLICY_AUTHORITY_TRANSPORT_KEY_FAILED
        policy_transport_key=$(jq -er '.identity_public_key_hex' "$WORK/agent-policy-assessment-authority-$policy_authority-public.json")
        content_provider_node "$policy_node" || fail POLICY_AUTHORITY_NODE_INVALID
        policy_unit=volparossa-alpha-policy-authority@$policy_node.service
        [ "$(unit_load_state "$policy_unit")" = not-found ] || fail POLICY_AUTHORITY_UNIT_COLLISION
        policy_authority_units="$policy_authority_units $policy_unit"
        jobs_units="$jobs_units $policy_unit"
        policy_hidden=$WORK/state-client
        for policy_other in relay3 relay4 relay5; do
            [ "$policy_other" = "$policy_node" ] || policy_hidden="$policy_hidden $WORK/state-$policy_other"
        done
        systemd-run --no-block --unit="$policy_unit" --slice=system.slice --service-type=exec \
            --property=CollectMode=inactive --property=Restart=no \
            --property=User=volparossa --property=Group=volparossa --property=UMask=0077 \
            --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
            --property="NetworkNamespacePath=/run/netns/$provider_ns" \
            --property=PrivateMounts=yes --property=PrivateTmp=yes --property=PrivateDevices=yes \
            --property=ProtectSystem=strict --property=ProtectHome=yes \
            --property="ReadWritePaths=$policy_owner_source" --property="InaccessiblePaths=$policy_hidden" \
            --property=KillMode=control-group --property=TimeoutStopSec=20s --property=RuntimeMaxSec=3600s \
            --property="StandardOutput=append:$WORK/agent-policy-assessment-authority-$policy_authority-summary.json" \
            --property="StandardError=append:$WORK/agent-policy-assessment-authority-$policy_authority-stderr.err" \
            -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-$policy_node/control/agent.sock" \
            compute peer policy-authority --policy-config "$WORK/config-$policy_node.yaml" \
            --authority-identity "$policy_authority_root/identity.key" --authority-passphrase-file "$policy_authority_root/passphrase" \
            --authority-key "$policy_authority_key" --identity "$WORK/state-$policy_node/identity.key" \
            --passphrase-file "$WORK/credential-$policy_node/identity-passphrase" --publication-key "$policy_transport_key" \
            --reply-name "disposable-policy-reply-$policy_authority" --request-publisher-key "$jobs_publisher" \
            --request-name disposable-policy-request --min-revision 1 --requester-key "$policy_requester" \
            --source-publisher-key "$jobs_publisher" --source-manifest-id "$policy_manifest" \
            --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --model-profile smollm2-360m-v1 \
            --directory "$policy_owner_source/policy-owner" --poll-seconds 1 \
            --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 --execute \
            || fail POLICY_AUTHORITY_START_FAILED
        policy_authority=$((policy_authority + 1))
    done
    python3 -B "$policy_script" round_before "$WORK" || fail POLICY_AUTHORITY_COLD_ENROLLMENT_INVALID
}

agent_policy_authorities_stop() {
    for policy_stop_unit in ${policy_authority_units:-}; do
        agent_jobs_stop_unit "$policy_stop_unit" || return 1
    done
}

agent_policy_owners_stop() {
    if [ -n "${policy_model_observer_pid:-}" ]; then
        if kill -0 "$policy_model_observer_pid" 2>/dev/null; then
            kill -TERM "$policy_model_observer_pid" || return 1
        fi
        wait "$policy_model_observer_pid" || true
        policy_model_observer_pid=
    fi
    if [ -n "${policy_follow_pid:-}" ]; then
        if kill -0 "$policy_follow_pid" 2>/dev/null; then
            kill -INT "$policy_follow_pid" || return 1
        fi
        wait "$policy_follow_pid" || true
        policy_follow_pid=
    fi
    agent_policy_authorities_stop
}

agent_policy_cycle_run() {
    PHASE=agent-policy-assessment-automatic-cycle
    agent_policy_cycle_cli --execute \
        >"$WORK/agent-policy-assessment-cycle.json" 2>"$WORK/agent-policy-assessment-cycle.err" &
    jobs_batch_pid=$!
    policy_round_pid=$jobs_batch_pid
    python3 -B "$policy_script" observe "$WORK" "$policy_round_pid" \
        >"$WORK/agent-policy-assessment-observer.log" 2>"$WORK/agent-policy-assessment-observer.err" &
    policy_model_observer_pid=$!
    policy_round_observer=0
    python3 -B "$policy_script" round_observe "$WORK" "$policy_round_pid" || policy_round_observer=$?
    if [ "$policy_round_observer" -eq 0 ]; then
        python3 -B "$policy_script" cycle_source_ready "$WORK" "$policy_round_pid" \
            || fail POLICY_CYCLE_ORIGINAL_SOURCE_NOT_OBSERVED
        agent_policy_object_probe before
    fi
    if [ "$policy_round_observer" -ne 0 ] && kill -0 "$policy_round_pid" 2>/dev/null; then
        kill -INT "$policy_round_pid" || true
    fi
    policy_observer_status=0
    wait "$policy_model_observer_pid" || policy_observer_status=$?
    policy_model_observer_pid=
    policy_round_status=0
    wait "$policy_round_pid" || policy_round_status=$?
    jobs_batch_pid=
    agent_policy_authorities_stop || fail POLICY_AUTHORITY_CLEANUP_FAILED
    python3 -B "$policy_script" collect "$WORK" \
        2>"$WORK/agent-policy-assessment-collect.err" || fail POLICY_RETAINED_EVIDENCE_INVALID
    [ "$policy_observer_status" -eq 0 ] || fail POLICY_FOUR_REAL_WORKERS_NOT_OBSERVED
    [ "$policy_round_status" -eq 0 ] || fail POLICY_AUTOMATIC_CYCLE_INCOMPLETE
    # Literal original product files, not reconstructed stand-in CLI reports.
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 "$policy_root/result.json" \
        "$WORK/agent-policy-assessment-result.json"
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 "$jobs_source/policy-cycle/round/result.json" \
        "$WORK/agent-policy-assessment-round.json"
    python3 -B "$policy_script" round_collect "$WORK" "$policy_round_pid" "$policy_round_status" \
        || fail POLICY_AUTOMATIC_QUORUM_ORIGINALS_INVALID
    python3 -B "$policy_script" cycle_collect "$WORK" "$policy_round_pid" "$policy_round_status" \
        || fail POLICY_AUTOMATIC_CYCLE_ORIGINALS_INVALID
    [ "$policy_round_observer" -eq 0 ] || fail POLICY_AUTHORITY_PROCESSES_NOT_OBSERVED
    [ "$policy_round_status" -eq 0 ] || fail POLICY_AUTOMATIC_QUORUM_INCOMPLETE
}

agent_policy_object_restart() {
    PHASE=agent-policy-assessment-object-restart
    policy_old_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $policy_old_pid in ''|0|*[!0-9]*) fail POLICY_OBJECT_OLD_AGENT_MISSING ;; esac
    systemctl restart volparossa-alpha-agent@client.service || fail POLICY_OBJECT_RESTART_FAILED
    policy_restart_attempt=0
    while [ "$policy_restart_attempt" -lt 300 ]; do
        policy_new_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
        case $policy_new_pid in ''|0|*[!0-9]*) policy_new_pid=0 ;; esac
        if [ "$policy_new_pid" != 0 ] && [ "$policy_new_pid" != "$policy_old_pid" ] \
            && [ "$(systemctl show --property=ActiveState --value volparossa-alpha-agent@client.service)" = active ] \
            && [ -S "$WORK/runtime-client/control/agent.sock" ]; then break; fi
        sleep 0.1
        policy_restart_attempt=$((policy_restart_attempt + 1))
    done
    [ "$policy_restart_attempt" -lt 300 ] || fail POLICY_OBJECT_RESTART_NOT_READY
    [ "$(readlink -f -- "/proc/$policy_new_pid/exe")" = "$binary_directory/volparossa-agent" ] \
        || fail POLICY_OBJECT_RESTART_EXECUTABLE_CHANGED
    [ "$(stat -Lc '%d:%i' "/proc/$policy_new_pid/ns/net")" = "$(stat -Lc '%d:%i' "/run/netns/$CLIENT")" ] \
        || fail POLICY_OBJECT_RESTART_NAMESPACE_CHANGED
    agent_policy_object_probe restarted
    python3 -B "$policy_script" object_collect "$WORK" after || fail POLICY_OBJECT_RESTART_EVIDENCE_INVALID
}

agent_policy_decision_cli() {
    policy_decision_node=$1
    policy_decision_command=$2
    shift 2
    agent_jobs_cli "$policy_decision_node" compute peer "$policy_decision_command" \
        --policy-config "$WORK/config-$policy_decision_node.yaml" \
        --subject-publisher-key "$policy_subject_publisher" --subject-manifest-id "$policy_manifest" \
        --subject-sha256 "$policy_subject_sha256" --decision-hash "$policy_decision_hash" \
        --evidence-sha256 "$policy_evidence_sha256" "$@"
}

agent_policy_object_peer_transfer() {
    PHASE=agent-policy-object-peer-transfer
    python3 -B "$policy_script" object_peer_pins "$WORK" || fail POLICY_OBJECT_PEER_PINS_INVALID
    policy_peer_pins=$WORK/agent-policy-assessment-remote-object-pins.json
    policy_subject_publisher=$(jq -er '.subject_publisher_key' "$policy_peer_pins")
    [ "$(jq -er '.subject_manifest_id' "$policy_peer_pins")" = "$policy_manifest" ] \
        || fail POLICY_OBJECT_PEER_SUBJECT_CHANGED
    policy_subject_sha256=$(jq -er '.subject_sha256' "$policy_peer_pins")
    policy_decision_hash=$(jq -er '.decision_hash' "$policy_peer_pins")
    policy_evidence_sha256=$(jq -er '.evidence_sha256' "$policy_peer_pins")
    policy_publication=$jobs_source/policy-cycle/round/publication
    policy_peer_root=$WORK/state-$provider_node_a/policy-object-receiver
    if [ -e "$policy_peer_root" ] || [ -L "$policy_peer_root" ]; then
        fail POLICY_OBJECT_PEER_NOT_FRESH
    fi
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$policy_peer_root"
    # Only public selection metadata is provisioned. Decision payload and policy signing keys
    # are never copied to the receiver; it must obtain payload through its original custody cache.
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 "$jobs_source/policy-subject.pb" \
        "$policy_peer_root/subject.manifest"
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 "$policy_publication/publication.manifest" \
        "$policy_peer_root/decision.manifest"
    python3 -B "$policy_script" object_peer_before "$WORK" || fail POLICY_OBJECT_PEER_NOT_COLD
    agent_jobs_cli "$provider_node_a" content export --manifest "$policy_peer_root/decision.manifest" \
        --publisher-key "$jobs_publisher" --agent-cache "$WORK/state-$provider_node_a/custody-cache" \
        --cache "$policy_peer_root/decision-cache" --public-content \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 \
        >"$WORK/agent-policy-assessment-remote-object-export.json" \
        2>"$WORK/agent-policy-assessment-remote-object-export.err" || fail POLICY_OBJECT_PEER_EXPORT_FAILED
    agent_jobs_cli "$provider_node_a" content assemble --manifest "$policy_peer_root/decision.manifest" \
        --publisher-key "$jobs_publisher" --cache "$policy_peer_root/decision-cache" \
        --output "$policy_peer_root/decision.bin" \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 \
        >"$WORK/agent-policy-assessment-remote-object-assemble.json" \
        2>"$WORK/agent-policy-assessment-remote-object-assemble.err" || fail POLICY_OBJECT_PEER_ASSEMBLE_FAILED
    python3 -B "$policy_script" object_peer_received "$WORK" || fail POLICY_OBJECT_PEER_BYTES_INVALID
}

agent_policy_object_peer_probe() {
    policy_peer_phase=$1
    policy_peer_status=0
    agent_jobs_cli "$provider_node_a" content export --manifest "$policy_peer_root/subject.manifest" \
        --publisher-key "$jobs_publisher" --agent-cache "$WORK/state-$provider_node_a/custody-cache" \
        --cache "$policy_peer_root/cache-$policy_peer_phase" --public-content \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 \
        >"$WORK/agent-policy-assessment-remote-object-$policy_peer_phase.json" \
        2>"$WORK/agent-policy-assessment-remote-object-$policy_peer_phase.err" || policy_peer_status=$?
    if [ "$policy_peer_status" -eq 0 ]; then
        agent_jobs_cli "$provider_node_a" content assemble --manifest "$policy_peer_root/subject.manifest" \
            --publisher-key "$jobs_publisher" --cache "$policy_peer_root/cache-$policy_peer_phase" \
            --output "$policy_peer_root/output-$policy_peer_phase.txt" \
            --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 \
            >"$WORK/agent-policy-assessment-remote-object-$policy_peer_phase-assemble.json" \
            2>"$WORK/agent-policy-assessment-remote-object-$policy_peer_phase-assemble.err" \
            || fail POLICY_OBJECT_PEER_SUBJECT_ASSEMBLE_FAILED
    fi
    python3 -B "$policy_script" object_peer_probe "$WORK" "$policy_peer_phase" "$policy_peer_status" \
        || fail POLICY_OBJECT_PEER_ACCESS_DID_NOT_MATCH_REAL_OUTCOME
}

agent_policy_object_follow_start() {
    PHASE=agent-policy-object-follow-cold
    [ -z "${jobs_batch_pid:-}" ] || fail POLICY_FOLLOW_OWNER_ALREADY_RUNNING
    policy_follow_directory=$jobs_source/policy-object-follow
    policy_follow_cache=$jobs_source/policy-object-follow-cache
    policy_follow_publication=$jobs_source/policy-cycle/round/publication
    policy_subject_publisher=$jobs_publisher
    policy_subject_sha256=$(jq -er '.sha256' "$WORK/agent-policy-assessment-input.json")
    policy_framework=$(jq -er '.framework_sha256' "$WORK/agent-policy-assessment-cycle-preview.json")
    policy_follow_agent=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $policy_follow_agent in ''|0|*[!0-9]*) fail POLICY_FOLLOW_CLIENT_MISSING ;; esac
    # GNU timeout owns one original unprivileged coordinator, in the real Client's masked
    # mount/network namespaces. The policy cleanup owns this PID separately from the coordinator.
    timeout --signal=INT --kill-after=15s 3600s nsenter --target "$policy_follow_agent" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        compute peer policy-follow --policy-config "$WORK/config-client.yaml" \
        --publisher-key "$jobs_publisher" --name disposable-object-policy --min-revision 1 \
        --subject-publisher-key "$policy_subject_publisher" --subject-manifest-id "$policy_manifest" \
        --subject-sha256 "$policy_subject_sha256" --framework-sha256 "$policy_framework" \
        --directory "$policy_follow_directory" --cache "$policy_follow_cache" --poll-seconds 1 \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 --execute \
        >"$WORK/agent-policy-assessment-follow-summary.json" \
        2>"$WORK/agent-policy-assessment-follow-stderr.err" &
    policy_follow_pid=$!
    python3 -B "$policy_script" object_follow_before "$WORK" "$policy_follow_pid" \
        || fail POLICY_FOLLOW_COLD_POLL_NOT_OBSERVED
}

agent_policy_object_follow_finish() {
    PHASE=agent-policy-object-follow-application
    python3 -B "$policy_script" object_follow_applied "$WORK" "$policy_follow_pid" \
        || fail POLICY_FOLLOW_AUTOMATIC_APPLICATION_MISSING
    kill -INT "$policy_follow_pid" || fail POLICY_FOLLOW_STOP_FAILED
    policy_follow_status=0
    wait "$policy_follow_pid" || policy_follow_status=$?
    python3 -B "$policy_script" object_follow_collect "$WORK" "$policy_follow_pid" "$policy_follow_status" \
        || fail POLICY_FOLLOW_ORIGINALS_INVALID
    policy_follow_pid=
    [ "$policy_follow_status" -eq 0 ] || fail POLICY_FOLLOW_REAP_FAILED
    agent_policy_object_probe applied
    python3 -B "$policy_script" object_collect "$WORK" before || fail POLICY_OBJECT_ORIGINALS_INVALID
}

agent_policy_object_peer_activate() {
    PHASE=agent-policy-object-peer-activation
    agent_policy_object_peer_probe before
    agent_policy_decision_cli "$provider_node_a" policy-import \
        --decision "$policy_peer_root/decision.bin" --output "$policy_peer_root/import" --execute --apply \
        >"$WORK/agent-policy-assessment-remote-object-import.json" \
        2>"$WORK/agent-policy-assessment-remote-object-import.err" || fail POLICY_OBJECT_PEER_IMPORT_FAILED
    agent_policy_object_peer_probe applied
    python3 -B "$policy_script" object_peer_collect "$WORK" before || fail POLICY_OBJECT_PEER_ORIGINALS_INVALID
    PHASE=agent-policy-object-peer-restart
    policy_peer_unit=volparossa-alpha-agent@$provider_node_a.service
    case " $AGENT_UNITS " in *" $policy_peer_unit "*) ;; *) fail POLICY_OBJECT_PEER_UNIT_NOT_OWNED ;; esac
    policy_peer_old_pid=$(systemctl show --property=MainPID --value "$policy_peer_unit")
    case $policy_peer_old_pid in ''|0|*[!0-9]*) fail POLICY_OBJECT_PEER_OLD_AGENT_MISSING ;; esac
    policy_peer_old_cache=$(stat -Lc '%d:%i' "$WORK/state-$provider_node_a/custody-cache")
    systemctl restart "$policy_peer_unit" || fail POLICY_OBJECT_PEER_RESTART_FAILED
    policy_peer_attempt=0
    while [ "$policy_peer_attempt" -lt 300 ]; do
        policy_peer_new_pid=$(systemctl show --property=MainPID --value "$policy_peer_unit")
        case $policy_peer_new_pid in ''|0|*[!0-9]*) policy_peer_new_pid=0 ;; esac
        if [ "$policy_peer_new_pid" != 0 ] && [ "$policy_peer_new_pid" != "$policy_peer_old_pid" ] \
            && [ "$(systemctl show --property=ActiveState --value "$policy_peer_unit")" = active ] \
            && [ -S "$WORK/runtime-$provider_node_a/control/agent.sock" ]; then break; fi
        sleep 0.1
        policy_peer_attempt=$((policy_peer_attempt + 1))
    done
    [ "$policy_peer_attempt" -lt 300 ] || fail POLICY_OBJECT_PEER_RESTART_NOT_READY
    content_provider_node "$provider_node_a" || fail POLICY_OBJECT_PEER_UNKNOWN
    [ "$(readlink -f -- "/proc/$policy_peer_new_pid/exe")" = "$binary_directory/volparossa-agent" ] \
        || fail POLICY_OBJECT_PEER_EXECUTABLE_CHANGED
    [ "$(stat -Lc '%d:%i' "/proc/$policy_peer_new_pid/ns/net")" = "$(stat -Lc '%d:%i' "/run/netns/$provider_ns")" ] \
        || fail POLICY_OBJECT_PEER_NAMESPACE_CHANGED
    [ "$policy_peer_old_cache" = "$(stat -Lc '%d:%i' "$WORK/state-$provider_node_a/custody-cache")" ] \
        || fail POLICY_OBJECT_PEER_CACHE_REPLACED
    agent_policy_object_peer_probe restarted
    python3 -B "$policy_script" object_peer_collect "$WORK" after || fail POLICY_OBJECT_PEER_RESTART_EVIDENCE_INVALID
}

agent_policy_assessment_run() {
    policy_script=$source_directory/tests/integration/agent-policy-assessment-smoke.py
    policy_root=$jobs_source/policy-cycle/assessment
    PHASE=agent-policy-assessment-publication
    printf '%s\n' \
        'Disposable guest only: publish one synthetic CC0 text, fetch its exact chunks through a protected peer route, execute two bounded principle assessments and two cross-reviews with the pinned 360M/JSON runtime, and retain original signed results and actual JSON-boundary/EOS termination.' \
        'Three separately enrolled authority owners on R3/R4/R5 each hold exactly one existing development policy identity; the Client cycle owner has none.' \
        'Start the enrolled Client follower cold, then one policy-cycle command fetches the selected source, completes four original model jobs, verifies their portable bundle and automatically delivers the original request through protected custody to three local inboxes, retrieves endorsements, verifies quorum and deposits the original named wrapper on R4.' \
        'After the cycle completes, publish/deposit/fetch its unchanged assessment bundle as a separate transport check without further model jobs.' \
        'Require automatic follower retrieval/application, stop and reap all authority/follower owners, replay the original four model jobs offline, test cached access and independent Client/provider restart persistence, and clean all owned resources.' \
        'No canned verdicts, additional model tasks, private signing-key transfer, production policy keys, global-policy activation or legal-correctness claim.'
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-policy-assessment-smoke.py" prepare "$WORK" \
        >"$WORK/agent-policy-assessment-input.json" || fail POLICY_PUBLIC_INPUT_FAILED
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" content recipient-key --identity "$WORK/state-client/identity.key" \
        --passphrase-file "$WORK/credential-client/identity-passphrase" \
        >"$WORK/agent-policy-assessment-requester.json" || fail POLICY_REQUESTER_KEY_FAILED
    # This field is the node's Ed25519 identity, not recipient_public_key_hex (X25519).
    policy_requester=$(jq -er '.identity_public_key_hex' "$WORK/agent-policy-assessment-requester.json")
    agent_jobs_cli client content publish --input "$jobs_source/policy-input.txt" \
        --name disposable-policy-subject --revision 1 --content-type text/plain \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$jobs_source/policy-publication-cache" --manifest "$jobs_source/policy-subject.pb" \
        --lifetime-seconds 7200 >"$WORK/agent-policy-assessment-publication.json" \
        2>"$WORK/agent-policy-assessment-publication.err" || fail POLICY_PUBLICATION_FAILED
    policy_manifest=$(sha256sum "$jobs_source/policy-subject.pb" | cut -d ' ' -f 1)
    agent_policy_phase_start
    agent_jobs_cli client content custody deposit --manifest "$jobs_source/policy-subject.pb" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$jobs_source/policy-publication-cache" --provider-key "$jobs_key_a" \
        >"$WORK/agent-policy-assessment-deposit.json" 2>"$WORK/agent-policy-assessment-deposit.err" \
        || fail POLICY_SUBJECT_DEPOSIT_FAILED
    agent_policy_authorities_start
    agent_policy_cycle_cli >"$WORK/agent-policy-assessment-cycle-preview.json" \
        2>"$WORK/agent-policy-assessment-cycle-preview.err" || fail POLICY_CYCLE_PREVIEW_INVALID
    agent_policy_object_follow_start
    agent_policy_cycle_run
    agent_policy_object_follow_finish
    agent_policy_object_peer_transfer
    PHASE=agent-policy-assessment-bundle-roundtrip
    policy_pack=$jobs_source/policy-bundle-publication
    agent_policy_assessment_cli compute peer policy-pack --assessment "$policy_root" --output "$policy_pack" \
        --requester-key "$policy_requester" --identity "$jobs_source/identity.key" \
        --passphrase-file "$jobs_source/passphrase" --execute \
        >"$WORK/agent-policy-assessment-pack.json" 2>"$WORK/agent-policy-assessment-pack.err" \
        || fail POLICY_BUNDLE_PACK_FAILED
    policy_bundle_name=$(jq -er '.name' "$WORK/agent-policy-assessment-pack.json")
    policy_bundle_manifest=$(jq -er '.manifest_id' "$WORK/agent-policy-assessment-pack.json")
    policy_bundle_publisher=$(jq -er '.publisher_key' "$WORK/agent-policy-assessment-pack.json")
    python3 -B "$policy_script" bundle_before "$WORK" || fail POLICY_BUNDLE_FRESH_TARGET_FAILED
    agent_jobs_cli client content custody deposit --manifest "$policy_pack/assessment.manifest" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$policy_pack/cache" --provider-key "$jobs_key_a" \
        >"$WORK/agent-policy-assessment-bundle-deposit.json" 2>"$WORK/agent-policy-assessment-bundle-deposit.err" \
        || fail POLICY_BUNDLE_DEPOSIT_FAILED
    agent_policy_assessment_cli compute peer policy-fetch --publisher-key "$policy_bundle_publisher" \
        --name "$policy_bundle_name" --manifest-id "$policy_bundle_manifest" --requester-key "$policy_requester" \
        --source-publisher-key "$jobs_publisher" --source-manifest-id "$policy_manifest" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --cache "$jobs_source/policy-bundle-cache" --output "$jobs_source/policy-bundle-fetch" --execute \
        >"$WORK/agent-policy-assessment-fetch.json" 2>"$WORK/agent-policy-assessment-fetch.err" \
        || fail POLICY_BUNDLE_FETCH_FAILED
    python3 -B "$policy_script" transfer "$WORK" || fail POLICY_BUNDLE_ROUNDTRIP_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail POLICY_ROUTE_CLEANUP_FAILED
    PHASE=agent-policy-assessment-offline-replay
    agent_jobs_stop || fail POLICY_BROKERS_STOP_FAILED
    python3 -B "$policy_script" stopped "$WORK" || fail POLICY_WORKER_STILL_ALIVE
    agent_policy_assessment_cli compute peer policy-assess --output "$policy_root" --resume --execute \
        >"$WORK/agent-policy-assessment-resume.json" 2>"$WORK/agent-policy-assessment-resume.err" \
        || fail POLICY_OFFLINE_REPLAY_FAILED
    python3 -B "$policy_script" replay "$WORK" || fail POLICY_OFFLINE_HISTORY_CHANGED
    agent_policy_object_restart
    agent_policy_object_peer_activate
    agent_jobs_cleanup || fail POLICY_PRIVATE_CLEANUP_FAILED
    python3 -B "$policy_script" evidence "$WORK" "$expected_commit" || fail POLICY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-policy-assessment-complete
}

agent_policy_assessment_finalize_report() {
    # Fixed prefix contains only the synthetic source and explicitly selected public proof.
    for policy_file in "$WORK"/agent-policy-assessment-*.json "$WORK"/agent-policy-assessment-*.err \
        "$WORK"/agent-policy-assessment-*.log "$WORK"/content-provider-adaptive-control-*.json \
        "$WORK"/content-provider-adaptive-policy-fetch-control.json \
        "$WORK"/content-provider-adaptive-policy-fetch-control.log; do
        [ ! -f "$policy_file" ] || [ -L "$policy_file" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$policy_file" "$output_directory/$(basename -- "$policy_file")"
    done
    python3 -B "$source_directory/tests/integration/agent-policy-assessment-smoke.py" finalize "$WORK" \
        "$expected_commit" "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-policy-assessment-smoke.json" \
        "$output_directory/agent-policy-assessment-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-policy-assessment-smoke.py" \
        report "$WORK/agent-policy-assessment-smoke.json" "$expected_commit"
}
