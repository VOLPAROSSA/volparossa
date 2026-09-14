#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit public-question variant of the real two-node jobs topology.
# shellcheck disable=SC2154,SC2034

agent_public_task_run() {
    task_question='What does this public context say about a normal network path?'
    task_directory=$jobs_source/public-task
    task_attempt=$task_directory/work/package-0000/attempt-0000
    task_manifest=$(jq -er '.manifest.sha256' "$WORK/agent-jobs-source.json")
    PHASE=agent-public-task-protected-source
    content_custody_phase_start fetch
    # The task frontend must retrieve the original signed source through the real
    # provider protocol. Its new agent cache is not the publisher's offline cache.
    agent_jobs_cli client content custody deposit --manifest "$jobs_source/manifest.pb" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$jobs_source/cache" --provider-key "$jobs_key_a" \
        >"$WORK/agent-public-task-deposit.json" 2>"$WORK/agent-public-task-deposit.err" || fail PUBLIC_TASK_SOURCE_DEPOSIT_FAILED
    PHASE=agent-public-task-admission-and-execution
    agent_jobs_cli client compute peer task --publisher-key "$jobs_publisher" \
        --dataset-name disposable-agent-jobs --dataset-manifest-id "$task_manifest" \
        --cache "$jobs_source/task-agent-cache" --public-question "$task_question" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --directory "$task_directory" --max-batches 1 --max-seconds 600 --execute \
        >"$WORK/agent-public-task-result.json" 2>"$WORK/agent-public-task-result.err" &
    jobs_batch_pid=$!
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-jobs-observer.log" 2>"$WORK/agent-jobs-observer.err" || fail PUBLIC_TASK_ADMISSION_OR_WORKERS_NOT_OBSERVED
    wait "$jobs_batch_pid" || fail PUBLIC_TASK_EXECUTION_INCOMPLETE
    jobs_batch_pid=
    for jobs_index in 0 1; do
        agent_jobs_cli client compute peer poll --handle "$task_attempt/job-$jobs_index.json" \
            >"$WORK/agent-jobs-status-$jobs_index.json" 2>"$WORK/agent-jobs-status-$jobs_index.err" || fail PUBLIC_TASK_FINAL_RECEIPT_UNAVAILABLE
    done
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" collect "$WORK" \
        || fail PUBLIC_TASK_RETAINED_FILES_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail PUBLIC_TASK_ROUTE_CLEANUP_FAILED
    # Completed receipt-only resume is deliberately tested with no active route
    # and with both actual compute executors stopped, not another inference run.
    PHASE=agent-public-task-retained-result-resume
    agent_jobs_stop || fail PUBLIC_TASK_BROKER_STOP_FAILED
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" stopped "$WORK" \
        || fail PUBLIC_TASK_BROKER_STILL_RUNNING
    agent_jobs_cli client compute peer task --directory "$task_directory" --resume --execute \
        >"$WORK/agent-public-task-resume.json" 2>"$WORK/agent-public-task-resume.err" || fail PUBLIC_TASK_RETAINED_RESUME_FAILED
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" resumed "$WORK" \
        || fail PUBLIC_TASK_RESUME_FILES_CHANGED
    agent_jobs_cleanup || fail PUBLIC_TASK_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" evidence "$WORK" "$expected_commit" \
        || fail PUBLIC_TASK_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-public-task-complete
}

agent_public_task_finalize_report() {
    for task_log in "$WORK"/agent-public-task-*.json "$WORK"/agent-public-task-*.err; do
        [ ! -f "$task_log" ] || [ -L "$task_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$task_log" "$output_directory/$(basename -- "$task_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-public-task-smoke.json" "$output_directory/agent-public-task-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-public-task-smoke.py" report "$WORK/agent-public-task-smoke.json" "$expected_commit"
}
