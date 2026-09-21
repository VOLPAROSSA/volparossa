#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Disposable ready dependencies; the B-only CPU pressure fixture stays in the guest.
# shellcheck disable=SC2154,SC2034

agent_ready_dag_cli() {
    # Same guest client-netns owner boundary and fixed 1800s wall cap as the manual graph.
    agent_task_graph_cli "$@"
}

agent_ready_dag_run() {
    dag_root=$jobs_source/ready-dag
    dag_script=$source_directory/tests/integration/agent-ready-dag-smoke.py
    PHASE=agent-ready-dag-owner-inputs
    printf '%s\n' 'Disposable guest only: one literal public README excerpt, two source tasks A/B, C<-A, D<-B and E<-C,D. Verify B owns a mountnamespace distinct from the guest and every other broker; bind only a labelled CPU100 PSI floor in that namespace without shared-mount changes. Observe actual Pause ACK and live B, require real C completion before the original B lease expires, poll protected Running status, unmount the exact floor, wait for real quiet-hold Resume ACK and finish D/E. No SIGSTOP or synthetic low pressure. Remove the exact owned original inputs, stop route/brokers, verify unchanged offline resume and full cleanup.'
    install -o root -g root -m 0444 "$source_directory/README.md" "$WORK/bin/ready-dag-source-README.md"
    for dag_part in venv model; do
        dag_name=ready-dag-model
        [ "$dag_part" != venv ] || dag_name=ready-dag-runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$dag_part" "$jobs_source/$dag_name" \
            || fail READY_DAG_OWNER_PROVISION_FAILED
    done
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-ready-dag-smoke.py" prepare "$WORK" \
        >"$WORK/agent-ready-dag-input.json" || fail READY_DAG_PUBLIC_INPUT_FAILED
    content_custody_phase_start fetch
    PHASE=agent-ready-dag-two-source-workers
    # Empty log/inode plus original broker/worker identity binds the upcoming
    # first startup ACK; no historical broker progress can authorize the floor.
    python3 -B "$dag_script" fresh-brokers "$WORK" || fail READY_DAG_BROKERS_NOT_FRESH
    agent_ready_dag_cli compute peer document --task-plan "$jobs_source/ready-dag-task-plan.json" \
        --model-profile smollm2-360m-v1 \
        --input "$jobs_source/ready-dag-input.txt" --public-content --license GPL-3.0-only \
        --runtime-root "$jobs_source/ready-dag-runtime" --model-root "$jobs_source/ready-dag-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --publisher-key "$jobs_publisher" --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --directory "$dag_root" --lifetime-seconds 7200 --max-batches 32 --max-seconds 600 --follow --execute \
        >"$WORK/agent-ready-dag-output.jsonl" 2>"$WORK/agent-ready-dag-result.err" &
    jobs_batch_pid=$!
    python3 -B "$dag_script" pause "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-ready-dag-observer.log" 2>"$WORK/agent-ready-dag-observer.err" \
        || fail READY_DAG_INITIAL_WORKERS_NOT_OBSERVED
    PHASE=agent-ready-dag-c-before-paused-b
    python3 -B "$dag_script" observe-ready "$WORK" \
        >>"$WORK/agent-ready-dag-observer.log" 2>>"$WORK/agent-ready-dag-observer.err" \
        || fail READY_DAG_C_DID_NOT_FINISH_BEFORE_B
    agent_jobs_cli client compute peer poll \
        --handle "$dag_root/node-0001/package-0000/work/package-0000/attempt-0000/job-0.json" \
        >"$WORK/agent-ready-dag-running-status.json" 2>"$WORK/agent-ready-dag-running-status.err" \
        || fail READY_DAG_ORIGINAL_RUNNING_STATUS_MISSING
    python3 -B "$dag_script" continue-worker "$WORK" || fail READY_DAG_ORIGINAL_CONTINUE_FAILED
    PHASE=agent-ready-dag-d-and-e-completion
    dag_observer_status=0
    python3 -B "$dag_script" observe-rest "$WORK" \
        >>"$WORK/agent-ready-dag-observer.log" 2>>"$WORK/agent-ready-dag-observer.err" \
        || dag_observer_status=$?
    if [ "$dag_observer_status" -ne 0 ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        kill -INT "$jobs_batch_pid" 2>/dev/null || true
    fi
    dag_owner_status=0
    wait "$jobs_batch_pid" || dag_owner_status=$?
    jobs_batch_pid=
    if [ "$dag_owner_status" -ne 0 ] || [ "$dag_observer_status" -ne 0 ]; then
        python3 -B "$dag_script" collect "$WORK" result 2>"$WORK/agent-ready-dag-partial-files.err" || true
        fail READY_DAG_REAL_EXECUTION_INCOMPLETE
    fi
    python3 -B "$dag_script" collect "$WORK" result || fail READY_DAG_RETAINED_FILES_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail READY_DAG_ROUTE_CLEANUP_FAILED
    PHASE=agent-ready-dag-offline-completed-resume
    agent_jobs_stop || fail READY_DAG_BROKERS_STOP_FAILED
    python3 -B "$dag_script" remove-inputs "$WORK" || fail READY_DAG_ORIGINAL_INPUT_REMOVAL_FAILED
    python3 -B "$dag_script" stopped "$WORK" || fail READY_DAG_PROCESS_CLEANUP_FAILED
    agent_ready_dag_cli compute peer document --directory "$dag_root" --resume --execute \
        >"$WORK/agent-ready-dag-resume.json" 2>"$WORK/agent-ready-dag-resume.err" \
        || fail READY_DAG_OFFLINE_RESUME_FAILED
    python3 -B "$dag_script" resumed "$WORK" || fail READY_DAG_OFFLINE_HISTORY_CHANGED
    agent_jobs_cleanup || fail READY_DAG_PRIVATE_CLEANUP_FAILED
    python3 -B "$dag_script" evidence "$WORK" "$expected_commit" || fail READY_DAG_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-ready-dag-complete
}

agent_ready_dag_finalize_report() {
    for dag_log in "$WORK"/agent-ready-dag-*.json "$WORK"/agent-ready-dag-*.jsonl \
        "$WORK"/agent-ready-dag-*.err "$WORK"/agent-ready-dag-*.log; do
        [ ! -f "$dag_log" ] || [ -L "$dag_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$dag_log" "$output_directory/$(basename -- "$dag_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-ready-dag-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-ready-dag-smoke.json" "$output_directory/agent-ready-dag-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-ready-dag-smoke.py" \
        report "$WORK/agent-ready-dag-smoke.json" "$expected_commit"
}
