#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit public-document variant; sourced only by the disposable KVM runner.
# shellcheck disable=SC2154,SC2034

agent_public_document_cli() {
    document_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $document_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # A document invocation includes planning and several independent worker
    # leases. This fixture has its own bounded 1320-second owner window; it does
    # not promise 32 maximally long jobs or extend any original 600-second lease.
    # This trusted owner CLI must retain its own mount/resource view, like the
    # train-loop owner: the agent's masked /proc prevents the nested unprivileged
    # worker sandbox from mounting its private procfs. Enter only Client's netns;
    # keep the agent service protections and the fixed worker sandbox unchanged.
    timeout --signal=INT --kill-after=15s 1320s nsenter --target "$document_cli_pid" --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_public_document_run() {
    document_root=$jobs_source/public-document
    document_script=$source_directory/tests/integration/agent-public-document-smoke.py
    document_attempt=$document_root/package-0000/work/package-0000/attempt-0000
    PHASE=agent-public-document-owner-tokenizer
    printf '%s\n' 'Disposable guest: copy the pinned runtime/model into the Client-owned compute-source; discover suitable public executors over the protected route, retain their identities/model, tokenize an explicit public README excerpt and execute fragments plus synthesis on two isolated peers; remove every owned copy during normal cleanup.'
    # The unprivileged Client cannot traverse /home/vpci/source. Install only this
    # public helper beside its already staged dependencies, never chmod the source.
    install -o root -g root -m 0555 "$document_script" "$WORK/bin/agent-public-document-smoke.py"
    install -o root -g root -m 0555 "$source_directory/tests/integration/agent-document-synthesis.py" "$WORK/bin/agent-document-synthesis.py"
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$source_directory/README.md" "$jobs_source/document-README.md"
    # Client's real service mount intentionally hides agent-jobs-user. These are
    # independent private copies, not hardlinks or artifact transfer substitutes.
    for document_part in venv model; do
        document_name=document-model
        [ "$document_part" != venv ] || document_name=document-runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$document_part" "$jobs_source/$document_name" \
            || fail DOCUMENT_OWNER_PROVISION_COPY_FAILED
    done
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-public-document-smoke.py" prepare "$WORK" >"$WORK/agent-public-document-input.json" \
        || fail DOCUMENT_PUBLIC_INPUT_FAILED
    PHASE=agent-public-document-executor-discovery
    content_custody_phase_start executor-discovery
    python3 -B "$document_script" enrollment-start "$WORK" || fail DOCUMENT_ENROLLMENT_START_UNAVAILABLE
    agent_public_document_cli compute peer document --input "$jobs_source/document-input.txt" \
        --public-content --license GPL-3.0-only --public-question 'Summarize the provided public context.' \
        --runtime-root "$jobs_source/document-runtime" --model-root "$jobs_source/document-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --publisher-key "$jobs_publisher" --discover-peers \
        --directory "$document_root" --synthesize --enroll-only --max-seconds 600 --execute \
        >"$WORK/agent-public-document-enrollment.json" 2>"$WORK/agent-public-document-enrollment.err" \
        || fail DOCUMENT_EXECUTOR_ENROLLMENT_FAILED
    python3 -B "$document_script" enrolled "$WORK" || fail DOCUMENT_ENROLLMENT_STARTED_UNEXPECTED_JOBS
    content_custody_phase_finish 2
    PHASE=agent-public-document-fragment-execution
    content_custody_phase_start fetch
    agent_public_document_cli compute peer document --directory "$document_root" --resume \
        --max-batches 1 --max-seconds 600 --execute \
        >"$WORK/agent-public-document-first.json" 2>"$WORK/agent-public-document-first.err" &
    jobs_batch_pid=$!
    python3 -B "$document_script" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-jobs-observer.log" 2>"$WORK/agent-jobs-observer.err" || fail DOCUMENT_INITIAL_WORKERS_NOT_OBSERVED
    # This bounded first invocation must retain one finished package, not claim
    # the entire document finished or treat any arbitrary failure as progress.
    if wait "$jobs_batch_pid"; then fail DOCUMENT_FIRST_INVOCATION_UNEXPECTEDLY_COMPLETE; fi
    jobs_batch_pid=
    python3 -B "$document_script" first "$WORK" || fail DOCUMENT_FIRST_PACKAGE_NOT_RETAINED
    # Preserve the actual original terminal polls now, before subsequent levels
    # can outlive their finite broker receipt-retention window.
    for document_index in 0 1; do
        agent_jobs_cli client compute peer poll --handle "$document_attempt/job-$document_index.json" \
            >"$WORK/agent-jobs-status-$document_index.json" 2>"$WORK/agent-jobs-status-$document_index.err" \
            || fail DOCUMENT_ORIGINAL_RECEIPT_UNAVAILABLE
    done
    PHASE=agent-public-document-hierarchical-synthesis
    agent_public_document_cli compute peer document --directory "$document_root" --resume \
        --runtime-root "$jobs_source/document-runtime" --model-root "$jobs_source/document-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --max-batches 32 --max-seconds 600 --execute \
        >"$WORK/agent-public-document-result.json" 2>"$WORK/agent-public-document-result.err" &
    jobs_batch_pid=$!
    document_observer_status=0
    python3 -B "$source_directory/tests/integration/agent-document-synthesis.py" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-public-document-synthesis-observer.log" 2>"$WORK/agent-public-document-synthesis-observer.err" \
        || document_observer_status=$?
    if [ "$document_observer_status" -ne 0 ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        # Preserve the existing owner cancellation/deadline instead of dropping its future.
        kill -INT "$jobs_batch_pid" 2>/dev/null || true
    fi
    document_owner_status=0
    wait "$jobs_batch_pid" || document_owner_status=$?
    jobs_batch_pid=
    if [ "$document_observer_status" -ne 0 ] || [ "$document_owner_status" -ne 0 ]; then
        document_partial_reason=synthesis_owner_failed
        [ "$document_observer_status" -eq 0 ] || document_partial_reason=synthesis_observer_failed
        # This is expressly PARTIAL, after owner return and before private cleanup.
        # It never satisfies collect/evidence gates or changes the original failure.
        if ! python3 -B "$document_script" partial "$WORK" "$expected_commit" \
            "$document_partial_reason" "$document_owner_status" \
            2>"$WORK/agent-public-document-partial-files.err"; then
            printf '%s\n' 'DOCUMENT_PARTIAL_SNAPSHOT_UNAVAILABLE' >"$WORK/agent-public-document-partial-files.log"
        fi
        [ "$document_observer_status" -eq 0 ] || fail DOCUMENT_ACTUAL_SYNTHESIS_WORKERS_NOT_OBSERVED
        fail DOCUMENT_REMAINING_PACKAGES_OR_SYNTHESIS_INCOMPLETE
    fi
    python3 -B "$document_script" collect "$WORK" || fail DOCUMENT_RETAINED_FILES_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail DOCUMENT_ROUTE_CLEANUP_FAILED
    PHASE=agent-public-document-offline-resume
    agent_jobs_stop || fail DOCUMENT_BROKER_STOP_FAILED
    python3 -B "$document_script" stopped "$WORK" || fail DOCUMENT_BROKER_STILL_RUNNING
    agent_public_document_cli compute peer document --directory "$document_root" --resume --execute \
        >"$WORK/agent-public-document-resume.json" 2>"$WORK/agent-public-document-resume.err" \
        || fail DOCUMENT_COMPLETED_RESUME_FAILED
    python3 -B "$document_script" resumed "$WORK" || fail DOCUMENT_RESUME_CHANGED_RETAINED_FILES
    agent_jobs_cleanup || fail DOCUMENT_PRIVATE_CLEANUP_FAILED
    python3 -B "$document_script" evidence "$WORK" "$expected_commit" || fail DOCUMENT_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-public-document-complete
}

agent_public_document_finalize_report() {
    for document_log in "$WORK"/agent-public-document-*.json "$WORK"/agent-public-document-*.err "$WORK"/agent-public-document-*.log; do
        [ ! -f "$document_log" ] || [ -L "$document_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$document_log" "$output_directory/$(basename -- "$document_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-public-document-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-public-document-smoke.json" "$output_directory/agent-public-document-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-public-document-smoke.py" report "$WORK/agent-public-document-smoke.json" "$expected_commit"
}
