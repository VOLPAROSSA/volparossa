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

agent_policy_object_cli() {
    policy_object_command=$1
    shift
    agent_policy_assessment_cli compute peer "$policy_object_command" \
        --assessment-bundle "$jobs_source/policy-bundle-fetch/assessment.bundle" \
        --policy-config "$WORK/config-client.yaml" --requester-key "$policy_requester" \
        --source-publisher-key "$jobs_publisher" --source-manifest-id "$policy_manifest" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --model-profile smollm2-360m-v1 "$@"
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

agent_policy_object_run() {
    PHASE=agent-policy-assessment-object-quorum
    agent_policy_object_probe before
    agent_policy_object_cli policy-propose --output "$jobs_source/policy-object-proposal" \
        --decision-revision 1 --execute >"$WORK/agent-policy-assessment-object-proposal.json" \
        2>"$WORK/agent-policy-assessment-object-proposal.err" || fail POLICY_OBJECT_PROPOSAL_FAILED
    # Three invocations, each loading only one already-configured development key.
    for policy_authority in 0 1 2; do
        policy_authority_root=$jobs_source/policy-authority-$policy_authority
        install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$policy_authority_root"
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/examples/acceptance-policy-fixture" "$policy_authority_root" \
            --authority-identity "$policy_authority" \
            >"$WORK/agent-policy-assessment-object-authority-$policy_authority.json" \
            2>"$WORK/agent-policy-assessment-object-authority-$policy_authority.err" \
            || fail POLICY_OBJECT_DEVELOPMENT_IDENTITY_FAILED
        agent_policy_object_cli policy-endorse --proposal "$jobs_source/policy-object-proposal/proposal.bin" \
            --output "$jobs_source/policy-object-endorsement-$policy_authority" \
            --identity "$policy_authority_root/identity.key" --passphrase-file "$policy_authority_root/passphrase" \
            --execute >"$WORK/agent-policy-assessment-object-endorsement-$policy_authority.json" \
            2>"$WORK/agent-policy-assessment-object-endorsement-$policy_authority.err" \
            || fail POLICY_OBJECT_INDEPENDENT_ENDORSEMENT_FAILED
    done
    agent_policy_object_cli policy-combine --proposal "$jobs_source/policy-object-proposal/proposal.bin" \
        --endorsement "$jobs_source/policy-object-endorsement-0/endorsement.bin" \
        --endorsement "$jobs_source/policy-object-endorsement-1/endorsement.bin" \
        --endorsement "$jobs_source/policy-object-endorsement-2/endorsement.bin" \
        --output "$jobs_source/policy-object-combined" --execute --apply \
        >"$WORK/agent-policy-assessment-object-combined.json" \
        2>"$WORK/agent-policy-assessment-object-combined.err" || fail POLICY_OBJECT_QUORUM_APPLY_FAILED
    agent_policy_object_probe applied
    python3 -B "$policy_script" object_collect "$WORK" before || fail POLICY_OBJECT_ORIGINALS_INVALID
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

agent_policy_assessment_run() {
    policy_script=$source_directory/tests/integration/agent-policy-assessment-smoke.py
    policy_root=$jobs_source/policy-assessment
    PHASE=agent-policy-assessment-publication
    printf '%s\n' 'Disposable guest only: publish one new synthetic CC0 public text, deposit its exact chunks on a peer, fetch the selected native object, execute two bounded principle assessments and two cross-reviews using signed dataset-v4 contracts on two explicitly enabled peers and the pinned JSON decoder, retain original provider-signed replies with truthful JSON-boundary/EOS termination, publish/deposit their bundle and fetch it into a new cache and directory on the SAME client, replay completed evidence offline, let three separately invoked existing development authorities replay and endorse its unchanged actual outcome, apply the exact-object quorum locally, test cached access and Client-agent restart persistence, and clean all owned resources. No canned verdicts, new model tasks, production policy keys, global-policy activation or legal-correctness claim.'
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
    content_custody_phase_start fetch
    agent_jobs_cli client content custody deposit --manifest "$jobs_source/policy-subject.pb" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$jobs_source/policy-publication-cache" --provider-key "$jobs_key_a" \
        >"$WORK/agent-policy-assessment-deposit.json" 2>"$WORK/agent-policy-assessment-deposit.err" \
        || fail POLICY_SUBJECT_DEPOSIT_FAILED
    PHASE=agent-policy-assessment-peer-reasoning
    agent_policy_assessment_cli compute peer policy-assess --output "$policy_root" \
        --source-publisher-key "$jobs_publisher" --source-name disposable-policy-subject \
        --source-manifest-id "$policy_manifest" --cache "$jobs_source/policy-source-cache" \
        --publisher-key "$jobs_publisher" --identity "$jobs_source/identity.key" \
        --passphrase-file "$jobs_source/passphrase" --license CC0-1.0 \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --max-seconds 600 --portable-receipts --execute \
        >"$WORK/agent-policy-assessment-result.json" 2>"$WORK/agent-policy-assessment-result.err" &
    jobs_batch_pid=$!
    policy_observer_status=0
    python3 -B "$policy_script" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-policy-assessment-observer.log" 2>"$WORK/agent-policy-assessment-observer.err" \
        || policy_observer_status=$?
    if [ "$policy_observer_status" -ne 0 ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        kill -INT "$jobs_batch_pid" 2>/dev/null || true
    fi
    policy_owner_status=0
    wait "$jobs_batch_pid" || policy_owner_status=$?
    jobs_batch_pid=
    python3 -B "$policy_script" collect "$WORK" \
        2>"$WORK/agent-policy-assessment-collect.err" || fail POLICY_RETAINED_EVIDENCE_INVALID
    [ "$policy_observer_status" -eq 0 ] || fail POLICY_FOUR_REAL_WORKERS_NOT_OBSERVED
    [ "$policy_owner_status" -eq 0 ] || fail POLICY_REASONING_INCOMPLETE
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
    agent_policy_object_run
    agent_jobs_cleanup || fail POLICY_PRIVATE_CLEANUP_FAILED
    python3 -B "$policy_script" evidence "$WORK" "$expected_commit" || fail POLICY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-policy-assessment-complete
}

agent_policy_assessment_finalize_report() {
    # Fixed prefix contains only the synthetic source and explicitly selected public proof.
    for policy_file in "$WORK"/agent-policy-assessment-*.json "$WORK"/agent-policy-assessment-*.err \
        "$WORK"/agent-policy-assessment-*.log; do
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
