#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Guest-only public source collections; no model or network action on the host.
# shellcheck disable=SC2154,SC2034

agent_public_collection_cli() {
    collection_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $collection_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Keep the owner mount view required by its nested unprivileged tokenizer sandbox.
    # This owner wall limit never renews a worker's 600s lease or the source's expiry.
    timeout --signal=INT --kill-after=15s 1800s nsenter --target "$collection_cli_pid" --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_public_collection_run() {
    collection_root=$jobs_source/public-collection
    collection_script=$source_directory/tests/integration/agent-public-collection-smoke.py
    PHASE=agent-public-collection-owner-inputs
    printf '%s\n' 'Disposable guest only: stage three public repository documents, retain literal 768-byte prefixes, copy the pinned owner tokenizer assets, sign their exact compilation, run real protected peer fragment/synthesis jobs, remove the four original fixture input files, prove completed offline resume and clean all owned resources.'
    collection_index=0
    for collection_source in README.md docs/PROTOCOL.md docs/DECENTRALIZED_AGENTS.md; do
        install -o root -g root -m 0444 "$source_directory/$collection_source" "$WORK/bin/collection-source-$collection_index.md"
        collection_index=$((collection_index + 1))
    done
    for collection_part in venv model; do
        collection_name=collection-model
        [ "$collection_part" != venv ] || collection_name=collection-runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$collection_part" "$jobs_source/$collection_name" \
            || fail COLLECTION_OWNER_PROVISION_FAILED
    done
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-public-collection-smoke.py" prepare "$WORK" \
        >"$WORK/agent-public-collection-input.json" || fail COLLECTION_PUBLIC_INPUT_FAILED
    PHASE=agent-public-collection-tokenizer-enrollment
    agent_public_collection_cli compute peer document --source-plan "$jobs_source/collection-source-plan.json" \
        --public-content --license GPL-3.0-only --public-question 'Summarize the provided public context.' \
        --runtime-root "$jobs_source/collection-runtime" --model-root "$jobs_source/collection-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" --publisher-key "$jobs_publisher" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --directory "$collection_root" \
        --synthesize --enroll-only --lifetime-seconds 7200 --max-seconds 600 --execute \
        >"$WORK/agent-public-collection-enrollment.json" 2>"$WORK/agent-public-collection-enrollment.err" \
        || fail COLLECTION_TOKENIZER_ENROLLMENT_FAILED
    python3 -B "$collection_script" enrolled "$WORK" || fail COLLECTION_PRE_JOB_BOUNDARY_FAILED
    PHASE=agent-public-collection-fragments-and-synthesis
    content_custody_phase_start fetch
    agent_public_collection_cli compute peer document --directory "$collection_root" --resume \
        --runtime-root "$jobs_source/collection-runtime" --model-root "$jobs_source/collection-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --max-batches 32 --max-seconds 600 --execute \
        >"$WORK/agent-public-collection-result.json" 2>"$WORK/agent-public-collection-result.err" &
    jobs_batch_pid=$!
    collection_observer_status=0
    python3 -B "$collection_script" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-public-collection-observer.log" 2>"$WORK/agent-public-collection-observer.err" \
        || collection_observer_status=$?
    if [ "$collection_observer_status" -ne 0 ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        kill -INT "$jobs_batch_pid" 2>/dev/null || true
    fi
    collection_owner_status=0
    wait "$jobs_batch_pid" || collection_owner_status=$?
    jobs_batch_pid=
    if [ "$collection_observer_status" -ne 0 ] || [ "$collection_owner_status" -ne 0 ]; then
        # Diagnostic snapshot only; no failed/partial execution can satisfy evidence.
        python3 -B "$collection_script" collect "$WORK" 2>"$WORK/agent-public-collection-partial-files.err" || true
        [ "$collection_observer_status" -eq 0 ] || fail COLLECTION_REAL_WORKERS_OR_LEVELS_NOT_OBSERVED
        fail COLLECTION_EXECUTION_INCOMPLETE
    fi
    python3 -B "$collection_script" collect "$WORK" || fail COLLECTION_RETAINED_FILES_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail COLLECTION_ROUTE_CLEANUP_FAILED
    PHASE=agent-public-collection-offline-resume
    agent_jobs_stop || fail COLLECTION_BROKERS_STOP_FAILED
    python3 -B "$collection_script" remove-inputs "$WORK" || fail COLLECTION_ORIGINAL_INPUT_REMOVAL_FAILED
    python3 -B "$collection_script" stopped "$WORK" || fail COLLECTION_PROCESS_CLEANUP_FAILED
    agent_public_collection_cli compute peer document --directory "$collection_root" --resume --execute \
        >"$WORK/agent-public-collection-resume.json" 2>"$WORK/agent-public-collection-resume.err" \
        || fail COLLECTION_OFFLINE_RESUME_FAILED
    python3 -B "$collection_script" resumed "$WORK" || fail COLLECTION_OFFLINE_HISTORY_CHANGED
    agent_jobs_cleanup || fail COLLECTION_PRIVATE_CLEANUP_FAILED
    python3 -B "$collection_script" evidence "$WORK" "$expected_commit" || fail COLLECTION_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-public-collection-complete
}

agent_public_collection_finalize_report() {
    for collection_log in "$WORK"/agent-public-collection-*.json "$WORK"/agent-public-collection-*.jsonl \
        "$WORK"/agent-public-collection-*.err "$WORK"/agent-public-collection-*.log; do
        [ ! -f "$collection_log" ] || [ -L "$collection_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$collection_log" "$output_directory/$(basename -- "$collection_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-public-collection-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-public-collection-smoke.json" "$output_directory/agent-public-collection-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-public-collection-smoke.py" report "$WORK/agent-public-collection-smoke.json" "$expected_commit"
}
