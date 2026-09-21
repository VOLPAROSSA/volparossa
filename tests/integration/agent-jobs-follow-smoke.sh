#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# One owner invocation recovers an observed worker loss in the disposable guest.
# shellcheck disable=SC2154,SC2034

agent_jobs_follow_cli() {
    follow_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $follow_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Two distinct <=600-second worker leases fit this bounded fixture-owner window.
    # This does not change either original job's deadline or the normal CLI helper.
    timeout --signal=INT --kill-after=15s 1320s nsenter --target "$follow_cli_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_jobs_follow_run() {
    PHASE=agent-jobs-follow-enrollment
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-jobs-follow-smoke.py" prepare "$jobs_source" "$jobs_publisher" \
        || fail JOBS_FOLLOW_PLAN_FAILED
    content_custody_phase_start fetch
    PHASE=agent-jobs-follow-worker-loss
    agent_jobs_follow_cli compute peer workflow --batch-barrier --plan "$jobs_source/follow-plan.json" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --directory "$jobs_source/follow" --follow --max-batches 1 --max-seconds 600 --execute \
        >"$WORK/agent-jobs-follow-output.jsonl" 2>"$WORK/agent-jobs-follow-result.err" &
    jobs_batch_pid=$!
    # This observer injects exactly one owned worker fault while the SAME owner
    # command stays alive. It never invokes a resume, submit or replacement CLI.
    python3 -B "$source_directory/tests/integration/agent-jobs-follow-smoke.py" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-jobs-follow-observer.log" 2>"$WORK/agent-jobs-follow-observer.err" \
        || fail JOBS_FOLLOW_ACTUAL_RECOVERY_NOT_OBSERVED
    wait "$jobs_batch_pid" || fail JOBS_FOLLOW_EXECUTION_INCOMPLETE
    jobs_batch_pid=
    python3 -B "$source_directory/tests/integration/agent-jobs-follow-smoke.py" capture "$WORK" \
        || fail JOBS_FOLLOW_RETAINED_FILES_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail JOBS_FOLLOW_ROUTE_CLEANUP_FAILED
    agent_jobs_cleanup || fail JOBS_FOLLOW_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/agent-jobs-follow-smoke.py" evidence "$WORK" "$expected_commit" \
        || fail JOBS_FOLLOW_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-jobs-follow-complete
}

agent_jobs_follow_finalize_report() {
    for follow_log in "$WORK"/agent-jobs-follow-*.json "$WORK"/agent-jobs-follow-*.jsonl "$WORK"/agent-jobs-follow-*.err "$WORK"/agent-jobs-follow-*.log; do
        [ ! -f "$follow_log" ] || [ -L "$follow_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$follow_log" "$output_directory/$(basename -- "$follow_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-jobs-follow-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-jobs-follow-smoke.json" "$output_directory/agent-jobs-follow-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-jobs-follow-smoke.py" report "$WORK/agent-jobs-follow-smoke.json" "$expected_commit"
}
