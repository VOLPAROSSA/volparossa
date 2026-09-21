#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit guest-only scheduling stimulus, never a production pause or lease extension.
# shellcheck disable=SC2154,SC2034

agent_jobs_package_queue_private() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-jobs-package-queue-smoke.py" "$@"
}

agent_jobs_package_queue_cli() {
    package_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $package_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Four independent <=600s leases. This fixture owner bound grants no worker extra time.
    timeout --signal=INT --kill-after=15s 1800s nsenter --target "$package_cli_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_jobs_package_queue_run() {
    package_script=$source_directory/tests/integration/agent-jobs-package-queue-smoke.py
    PHASE=agent-jobs-package-queue-enrollment
    # A and B are published once, before enrollment, by the existing trusted signer.
    agent_jobs_package_queue_private second-source "$jobs_source" || fail PACKAGE_QUEUE_SECOND_SOURCE_FAILED
    agent_jobs_cli client content publish --input "$jobs_source/dataset-b.json" \
        --name disposable-agent-jobs-package-b --revision 1 --content-type application/vnd.volparossa.agent-dataset.v1+json \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$jobs_source/cache-b" --manifest "$jobs_source/manifest-b.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-jobs-package-queue-publish-b.json" 2>"$WORK/agent-jobs-package-queue-publish-b.err" \
        || fail PACKAGE_QUEUE_SECOND_PUBLICATION_FAILED
    agent_jobs_package_queue_private publication-b "$jobs_source" >"$WORK/agent-jobs-package-queue-source-b.json" \
        || fail PACKAGE_QUEUE_SECOND_SOURCE_HASH_FAILED
    agent_jobs_package_queue_private prepare "$jobs_source" "$jobs_publisher" || fail PACKAGE_QUEUE_PLAN_FAILED
    content_custody_phase_start fetch
    agent_jobs_package_queue_cli compute peer workflow --plan "$jobs_source/package-queue-plan.json" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --directory "$jobs_source/package-queue" \
        --follow --max-batches 2 --max-seconds 600 --execute \
        >"$WORK/agent-jobs-package-queue-output.jsonl" 2>"$WORK/agent-jobs-package-queue-result.err" &
    jobs_batch_pid=$!
    PHASE=agent-jobs-package-queue-owned-pause
    python3 -B "$package_script" pause "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-jobs-package-queue-observer.log" 2>"$WORK/agent-jobs-package-queue-observer.err" \
        || fail PACKAGE_QUEUE_FIRST_WORKERS_MISSING
    python3 -B "$package_script" observe-ready "$WORK" \
        >>"$WORK/agent-jobs-package-queue-observer.log" 2>>"$WORK/agent-jobs-package-queue-observer.err" \
        || fail PACKAGE_QUEUE_REFILL_NOT_OBSERVED
    agent_jobs_cli client compute peer poll --handle "$jobs_source/package-queue/package-0000/attempt-0000/job-0.json" \
        >"$WORK/agent-jobs-package-queue-running-status.json" 2>"$WORK/agent-jobs-package-queue-running-status.err" \
        || fail PACKAGE_QUEUE_ORIGINAL_STATUS_UNAVAILABLE
    python3 -B "$package_script" continue-worker "$WORK" || fail PACKAGE_QUEUE_ORIGINAL_CONTINUE_FAILED
    PHASE=agent-jobs-package-queue-completion
    wait "$jobs_batch_pid" || fail PACKAGE_QUEUE_EXECUTION_INCOMPLETE
    jobs_batch_pid=
    python3 -B "$package_script" capture "$WORK" || fail PACKAGE_QUEUE_RETAINED_FILES_INVALID
    # A completed resume must need neither broker nor a new execution authority.
    agent_jobs_stop || fail PACKAGE_QUEUE_BROKER_STOP_FAILED
    python3 -B "$package_script" before-resume "$WORK" || fail PACKAGE_QUEUE_STOPPED_BROKERS_NOT_PROVEN
    agent_jobs_package_queue_cli compute peer workflow --resume --directory "$jobs_source/package-queue" \
        --follow --max-batches 2 --max-seconds 600 --execute \
        >"$WORK/agent-jobs-package-queue-resume-output.jsonl" 2>"$WORK/agent-jobs-package-queue-resume.err" \
        || fail PACKAGE_QUEUE_COMPLETED_RESUME_FAILED
    python3 -B "$package_script" after-resume "$WORK" || fail PACKAGE_QUEUE_COMPLETED_HISTORY_CHANGED
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail PACKAGE_QUEUE_ROUTE_CLEANUP_FAILED
    agent_jobs_cleanup || fail PACKAGE_QUEUE_PRIVATE_CLEANUP_FAILED
    python3 -B "$package_script" evidence "$WORK" "$expected_commit" || fail PACKAGE_QUEUE_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-jobs-package-queue-complete
}

agent_jobs_package_queue_finalize_report() {
    for package_log in "$WORK"/agent-jobs-package-queue-*.json "$WORK"/agent-jobs-package-queue-*.jsonl \
        "$WORK"/agent-jobs-package-queue-*.err "$WORK"/agent-jobs-package-queue-*.log; do
        [ ! -f "$package_log" ] || [ -L "$package_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$package_log" "$output_directory/$(basename -- "$package_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-jobs-package-queue-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-jobs-package-queue-smoke.json" \
        "$output_directory/agent-jobs-package-queue-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-jobs-package-queue-smoke.py" report \
        "$WORK/agent-jobs-package-queue-smoke.json" "$expected_commit"
}
