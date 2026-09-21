#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit guest-only scheduling stimulus, never a production pause or lease extension.
# shellcheck disable=SC2154,SC2034

agent_jobs_ready_queue_private() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-jobs-ready-queue-smoke.py" "$@"
}

agent_jobs_ready_queue_cli() {
    ready_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $ready_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Four independent <=600s leases. This fixture owner bound grants no worker extra time.
    timeout --signal=INT --kill-after=15s 1800s nsenter --target "$ready_cli_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_jobs_ready_queue_run() {
    ready_script=$source_directory/tests/integration/agent-jobs-ready-queue-smoke.py
    PHASE=agent-jobs-ready-queue-enrollment
    agent_jobs_ready_queue_private prepare "$jobs_source" "$jobs_publisher" || fail READY_QUEUE_PLAN_FAILED
    content_custody_phase_start fetch
    agent_jobs_ready_queue_cli compute peer workflow --plan "$jobs_source/ready-queue-plan.json" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --directory "$jobs_source/ready-queue" \
        --follow --max-batches 1 --max-seconds 600 --execute \
        >"$WORK/agent-jobs-ready-queue-output.jsonl" 2>"$WORK/agent-jobs-ready-queue-result.err" &
    jobs_batch_pid=$!
    PHASE=agent-jobs-ready-queue-owned-pause
    python3 -B "$ready_script" pause "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-jobs-ready-queue-observer.log" 2>"$WORK/agent-jobs-ready-queue-observer.err" \
        || fail READY_QUEUE_FIRST_WORKERS_MISSING
    python3 -B "$ready_script" observe-ready "$WORK" \
        >>"$WORK/agent-jobs-ready-queue-observer.log" 2>>"$WORK/agent-jobs-ready-queue-observer.err" \
        || fail READY_QUEUE_REFILL_NOT_OBSERVED
    agent_jobs_cli client compute peer poll --handle "$jobs_source/ready-queue/package-0000/attempt-0000/job-0.json" \
        >"$WORK/agent-jobs-ready-queue-running-status.json" 2>"$WORK/agent-jobs-ready-queue-running-status.err" \
        || fail READY_QUEUE_ORIGINAL_STATUS_UNAVAILABLE
    python3 -B "$ready_script" continue-worker "$WORK" || fail READY_QUEUE_ORIGINAL_CONTINUE_FAILED
    PHASE=agent-jobs-ready-queue-completion
    wait "$jobs_batch_pid" || fail READY_QUEUE_EXECUTION_INCOMPLETE
    jobs_batch_pid=
    python3 -B "$ready_script" capture "$WORK" || fail READY_QUEUE_RETAINED_FILES_INVALID
    # A completed resume must need neither broker nor a new execution authority.
    agent_jobs_stop || fail READY_QUEUE_BROKER_STOP_FAILED
    python3 -B "$ready_script" before-resume "$WORK" || fail READY_QUEUE_STOPPED_BROKERS_NOT_PROVEN
    agent_jobs_ready_queue_cli compute peer workflow --resume --directory "$jobs_source/ready-queue" \
        --follow --max-batches 1 --max-seconds 600 --execute \
        >"$WORK/agent-jobs-ready-queue-resume-output.jsonl" 2>"$WORK/agent-jobs-ready-queue-resume.err" \
        || fail READY_QUEUE_COMPLETED_RESUME_FAILED
    python3 -B "$ready_script" after-resume "$WORK" || fail READY_QUEUE_COMPLETED_HISTORY_CHANGED
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail READY_QUEUE_ROUTE_CLEANUP_FAILED
    agent_jobs_cleanup || fail READY_QUEUE_PRIVATE_CLEANUP_FAILED
    python3 -B "$ready_script" evidence "$WORK" "$expected_commit" || fail READY_QUEUE_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-jobs-ready-queue-complete
}

agent_jobs_ready_queue_finalize_report() {
    for ready_log in "$WORK"/agent-jobs-ready-queue-*.json "$WORK"/agent-jobs-ready-queue-*.jsonl \
        "$WORK"/agent-jobs-ready-queue-*.err "$WORK"/agent-jobs-ready-queue-*.log; do
        [ ! -f "$ready_log" ] || [ -L "$ready_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$ready_log" "$output_directory/$(basename -- "$ready_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-jobs-ready-queue-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-jobs-ready-queue-smoke.json" \
        "$output_directory/agent-jobs-ready-queue-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-jobs-ready-queue-smoke.py" report \
        "$WORK/agent-jobs-ready-queue-smoke.json" "$expected_commit"
}
