#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Guest-only explicit public task graph; no model or network action on the host.
# shellcheck disable=SC2154,SC2034

agent_task_graph_cli() {
    graph_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $graph_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # The owner tokenizer needs its normal mount/proc view, inside the client network.
    # This fixed wall bound does not change any original 600s worker lease or source expiry.
    timeout --signal=INT --kill-after=15s 1800s nsenter --target "$graph_cli_pid" --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_task_graph_wait() {
    graph_observer_status=0
    python3 -B "$graph_script" observe "$WORK" "$jobs_batch_pid" "$1" \
        >"$WORK/agent-task-graph-$1-observer.log" 2>"$WORK/agent-task-graph-$1-observer.err" \
        || graph_observer_status=$?
    if [ "$graph_observer_status" -ne 0 ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        kill -INT "$jobs_batch_pid" 2>/dev/null || true
    fi
    graph_owner_status=0
    wait "$jobs_batch_pid" || graph_owner_status=$?
    jobs_batch_pid=
    if [ "$graph_observer_status" -ne 0 ]; then
        python3 -B "$graph_script" collect "$WORK" "$1" \
            2>"$WORK/agent-task-graph-$1-partial-files.err" || true
        fail GRAPH_REAL_WORKERS_NOT_OBSERVED
    fi
    # The first bounded invocation deliberately prints an incomplete graph and exits 1.
    # Its exact two-completed-parent/no-dependent-work state is checked before resume.
    if [ "$1" = partial ]; then
        [ "$graph_owner_status" -eq 1 ] || fail GRAPH_EXPECTED_PARTIAL_BOUNDARY_MISSING
    else
        [ "$graph_owner_status" -eq 0 ] || fail GRAPH_DEPENDENT_EXECUTION_INCOMPLETE
    fi
    python3 -B "$graph_script" collect "$WORK" "$1" || fail GRAPH_RETAINED_FILES_INVALID
}

agent_task_graph_run() {
    graph_root=$jobs_source/public-task-graph
    graph_script=$source_directory/tests/integration/agent-task-graph-smoke.py
    PHASE=agent-task-graph-owner-inputs
    printf '%s\n' 'Disposable guest only: stage one literal 128-byte public README excerpt and an explicit four-node task DAG; copy pinned owner tokenizer assets; execute two parallel source questions, stop at the exact two-package budget, then resume real comparison and single-parent refinement jobs. Remove only the two owned original input files, stop brokers and route, verify immutable completed offline resume, and clean all owned resources.'
    install -o root -g root -m 0444 "$source_directory/README.md" "$WORK/bin/graph-source-README.md"
    for graph_part in venv model; do
        graph_name=graph-model
        [ "$graph_part" != venv ] || graph_name=graph-runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$graph_part" "$jobs_source/$graph_name" \
            || fail GRAPH_OWNER_PROVISION_FAILED
    done
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-task-graph-smoke.py" prepare "$WORK" \
        >"$WORK/agent-task-graph-input.json" || fail GRAPH_PUBLIC_INPUT_FAILED
    content_custody_phase_start fetch
    PHASE=agent-task-graph-first-two-source-tasks
    agent_task_graph_cli compute peer document --task-plan "$jobs_source/graph-task-plan.json" \
        --input "$jobs_source/graph-input.txt" --public-content --license GPL-3.0-only \
        --runtime-root "$jobs_source/graph-runtime" --model-root "$jobs_source/graph-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --publisher-key "$jobs_publisher" --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --directory "$graph_root" --lifetime-seconds 7200 --max-batches 2 --max-seconds 600 --execute \
        >"$WORK/agent-task-graph-partial.json" 2>"$WORK/agent-task-graph-partial.err" &
    jobs_batch_pid=$!
    agent_task_graph_wait partial
    PHASE=agent-task-graph-real-dependent-instructions
    agent_task_graph_cli compute peer document --directory "$graph_root" --resume \
        --runtime-root "$jobs_source/graph-runtime" --model-root "$jobs_source/graph-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --max-batches 8 --max-seconds 600 --execute \
        >"$WORK/agent-task-graph-result.json" 2>"$WORK/agent-task-graph-result.err" &
    jobs_batch_pid=$!
    agent_task_graph_wait result
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail GRAPH_ROUTE_CLEANUP_FAILED
    PHASE=agent-task-graph-offline-completed-resume
    agent_jobs_stop || fail GRAPH_BROKERS_STOP_FAILED
    python3 -B "$graph_script" remove-inputs "$WORK" || fail GRAPH_ORIGINAL_INPUT_REMOVAL_FAILED
    python3 -B "$graph_script" stopped "$WORK" || fail GRAPH_PROCESS_CLEANUP_FAILED
    agent_task_graph_cli compute peer document --directory "$graph_root" --resume --execute \
        >"$WORK/agent-task-graph-resume.json" 2>"$WORK/agent-task-graph-resume.err" \
        || fail GRAPH_OFFLINE_RESUME_FAILED
    python3 -B "$graph_script" resumed "$WORK" || fail GRAPH_OFFLINE_HISTORY_CHANGED
    agent_jobs_cleanup || fail GRAPH_PRIVATE_CLEANUP_FAILED
    python3 -B "$graph_script" evidence "$WORK" "$expected_commit" || fail GRAPH_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-task-graph-complete
}

agent_task_graph_finalize_report() {
    for graph_log in "$WORK"/agent-task-graph-*.json "$WORK"/agent-task-graph-*.jsonl \
        "$WORK"/agent-task-graph-*.err "$WORK"/agent-task-graph-*.log; do
        [ ! -f "$graph_log" ] || [ -L "$graph_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$graph_log" "$output_directory/$(basename -- "$graph_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-task-graph-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-task-graph-smoke.json" "$output_directory/agent-task-graph-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-task-graph-smoke.py" \
        report "$WORK/agent-task-graph-smoke.json" "$expected_commit"
}
