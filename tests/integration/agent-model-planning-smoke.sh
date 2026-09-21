#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Guest-only model-proposed public task graph; no host model/network execution.
# shellcheck disable=SC2154,SC2034

agent_model_planning_cli() {
    planning_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $planning_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Preserve the owner mount/proc view for nested private planner/tokenizer workers.
    # The fixed wall bound never extends their 600s leases or the original source expiry.
    timeout --signal=INT --kill-after=15s 1800s nsenter --target "$planning_cli_pid" --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_model_planning_wait() {
    planning_observer_status=0
    python3 -B "$planning_script" "$1" "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-model-planning-$2-observer.log" 2>"$WORK/agent-model-planning-$2-observer.err" \
        || planning_observer_status=$?
    if [ "$planning_observer_status" -ne 0 ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        kill -INT "$jobs_batch_pid" 2>/dev/null || true
    fi
    planning_owner_status=0
    wait "$jobs_batch_pid" || planning_owner_status=$?
    jobs_batch_pid=
    if [ "$planning_observer_status" -ne 0 ] || [ "$planning_owner_status" -ne 0 ]; then
        # Exact error output remains diagnostic, never substituted with a canned task plan.
        # A failed planner has no graph authority: retain its bounded, text-free
        # original metadata independently, before the ordinary private cleanup.
        python3 -B "$planning_script" collect-failure "$WORK" \
            2>"$WORK/agent-model-planning-planner-failure-export.err" || true
        python3 -B "$planning_script" collect "$WORK" "$2" \
            2>"$WORK/agent-model-planning-$2-partial-files.err" || true
        [ "$planning_observer_status" -eq 0 ] || fail MODEL_PLANNING_REAL_WORKER_NOT_OBSERVED
        fail MODEL_PLANNING_REAL_EXECUTION_INCOMPLETE
    fi
    python3 -B "$planning_script" collect "$WORK" "$2" || fail MODEL_PLANNING_RETAINED_FILES_INVALID
}

agent_model_planning_run() {
    planning_root=$jobs_source/model-planning
    planning_script=$source_directory/tests/integration/agent-model-planning-smoke.py
    PHASE=agent-model-planning-owner-inputs
    printf '%s\n' 'Disposable guest only: stage the complete literal public README introduction before its navigation and the same original question, copy pinned owner assets, observe one real isolated model reading the source prefix and proposing two question-form subquestions with at most four charged attempts within the shared 384-token bound, enroll those exact questions without peer work, execute all real tokenized protected peer source/join tasks, remove the owned original input and prove unchanged completed offline resume after broker/route teardown. Exhausted recovery fails with bounded text-free diagnostics; there is no canned-plan fallback or claim of semantic relevance from source metadata.'
    install -o root -g root -m 0444 "$source_directory/README.md" "$WORK/bin/model-planning-source-README.md"
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$jobs_source/planner-provision"
    for planning_part in venv model; do
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$planning_part" "$jobs_source/planner-provision/$planning_part" \
            || fail MODEL_PLANNING_OWNER_PROVISION_FAILED
    done
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-model-planning-smoke.py" prepare "$WORK" \
        >"$WORK/agent-model-planning-input.json" || fail MODEL_PLANNING_PUBLIC_INPUT_FAILED
    PHASE=agent-model-planning-real-model-enrollment
    agent_model_planning_cli compute peer document --plan-tasks \
        --model-profile smollm2-360m-v1 \
        --input "$jobs_source/model-planning-input.txt" --public-content --license GPL-3.0-only \
        --public-question 'What requirements and risks does this project describe?' \
        --runtime-root "$jobs_source/planner-provision/venv" --model-root "$jobs_source/planner-provision/model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --publisher-key "$jobs_publisher" --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --directory "$planning_root" --lifetime-seconds 7200 --enroll-only --max-seconds 600 --execute \
        >"$WORK/agent-model-planning-enrollment.json" 2>"$WORK/agent-model-planning-enrollment.err" &
    jobs_batch_pid=$!
    agent_model_planning_wait observe-planner enrolled
    PHASE=agent-model-planning-model-derived-peer-tasks
    content_custody_phase_start fetch
    agent_model_planning_cli compute peer document --directory "$planning_root" --resume \
        --model-profile smollm2-360m-v1 \
        --runtime-root "$jobs_source/planner-provision/venv" --model-root "$jobs_source/planner-provision/model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --max-batches 16 --max-seconds 600 --execute \
        >"$WORK/agent-model-planning-result.json" 2>"$WORK/agent-model-planning-result.err" &
    jobs_batch_pid=$!
    agent_model_planning_wait observe-peers result
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail MODEL_PLANNING_ROUTE_CLEANUP_FAILED
    PHASE=agent-model-planning-offline-completed-resume
    agent_jobs_stop || fail MODEL_PLANNING_BROKERS_STOP_FAILED
    python3 -B "$planning_script" remove-input "$WORK" || fail MODEL_PLANNING_ORIGINAL_INPUT_REMOVAL_FAILED
    python3 -B "$planning_script" stopped "$WORK" || fail MODEL_PLANNING_PROCESS_CLEANUP_FAILED
    agent_model_planning_cli compute peer document --directory "$planning_root" --resume --execute \
        >"$WORK/agent-model-planning-resume.json" 2>"$WORK/agent-model-planning-resume.err" \
        || fail MODEL_PLANNING_OFFLINE_RESUME_FAILED
    python3 -B "$planning_script" resumed "$WORK" || fail MODEL_PLANNING_OFFLINE_HISTORY_CHANGED
    agent_jobs_cleanup || fail MODEL_PLANNING_PRIVATE_CLEANUP_FAILED
    python3 -B "$planning_script" evidence "$WORK" "$expected_commit" || fail MODEL_PLANNING_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-model-planning-complete
}

agent_model_planning_finalize_report() {
    for planning_log in "$WORK"/agent-model-planning-*.json "$WORK"/agent-model-planning-*.jsonl \
        "$WORK"/agent-model-planning-*.err "$WORK"/agent-model-planning-*.log; do
        [ ! -f "$planning_log" ] || [ -L "$planning_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$planning_log" "$output_directory/$(basename -- "$planning_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-model-planning-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-model-planning-smoke.json" "$output_directory/agent-model-planning-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-model-planning-smoke.py" \
        report "$WORK/agent-model-planning-smoke.json" "$expected_commit"
}
