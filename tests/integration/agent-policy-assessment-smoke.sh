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

agent_policy_assessment_run() {
    policy_script=$source_directory/tests/integration/agent-policy-assessment-smoke.py
    policy_root=$jobs_source/policy-assessment
    PHASE=agent-policy-assessment-publication
    printf '%s\n' 'Disposable guest only: publish one new synthetic CC0 public text, deposit its exact chunks on a peer, fetch the selected native object into a distinct consumer cache, execute two bounded principle assessments and two cross-reviews on the two actual selected peers, replay completed evidence offline, and clean all owned resources. No production policy keys, network-policy activation or legal-correctness claim.'
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-policy-assessment-smoke.py" prepare "$WORK" \
        >"$WORK/agent-policy-assessment-input.json" || fail POLICY_PUBLIC_INPUT_FAILED
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
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --max-seconds 600 --execute \
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
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail POLICY_ROUTE_CLEANUP_FAILED
    PHASE=agent-policy-assessment-offline-replay
    agent_jobs_stop || fail POLICY_BROKERS_STOP_FAILED
    python3 -B "$policy_script" stopped "$WORK" || fail POLICY_WORKER_STILL_ALIVE
    agent_policy_assessment_cli compute peer policy-assess --output "$policy_root" --resume --execute \
        >"$WORK/agent-policy-assessment-resume.json" 2>"$WORK/agent-policy-assessment-resume.err" \
        || fail POLICY_OFFLINE_REPLAY_FAILED
    python3 -B "$policy_script" replay "$WORK" || fail POLICY_OFFLINE_HISTORY_CHANGED
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
