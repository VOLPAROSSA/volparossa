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

agent_public_collection_check() {
    if [ "${agent_public_network_sources:-no}" = yes ]; then
        python3 -B "$source_directory/tests/integration/agent-public-collection-smoke.py" "$@" --network
    else
        python3 -B "$source_directory/tests/integration/agent-public-collection-smoke.py" "$@"
    fi
}

agent_public_collection_native_sources() {
    PHASE=agent-public-collection-native-publications
    printf '%s\n' 'Disposable guest only: create a separate encrypted public-source signer inside the owned job root; sign two literal excerpts for 7200s, deposit them on two real peers, warm only the first in a distinct consumer cache, and let source-plan v2 retrieve the second through its protected path.'
    agent_jobs_cli client init --identity "$jobs_source/collection-native-identity.key" \
        --passphrase-file "$jobs_source/passphrase" >"$WORK/agent-public-collection-network-init.log" \
        2>"$WORK/agent-public-collection-network-init.err" || fail COLLECTION_NATIVE_PUBLISHER_FAILED
    for collection_native_index in 1 2; do
        set -- content publish --input "$jobs_source/collection-input-$collection_native_index.txt" \
            --name "disposable-collection-source-$collection_native_index" --revision 1 --content-type text/plain \
            --identity "$jobs_source/collection-native-identity.key" --passphrase-file "$jobs_source/passphrase" \
            --cache "$jobs_source/collection-native-cache" --manifest "$jobs_source/collection-native-$collection_native_index.pb" \
            --lifetime-seconds 7200
        [ "$collection_native_index" != 2 ] || set -- "$@" --reuse-cache
        agent_jobs_cli client "$@" >"$WORK/agent-public-collection-network-publish-$collection_native_index.json" \
            2>"$WORK/agent-public-collection-network-publish-$collection_native_index.err" || fail COLLECTION_NATIVE_PUBLICATION_FAILED
    done
    agent_public_collection_check network-plan "$WORK" || fail COLLECTION_NATIVE_PLAN_FAILED
    content_custody_phase_start fetch
    PHASE=agent-public-collection-native-deposits
    for collection_native_index in 1 2; do
        collection_native_provider=$jobs_key_a
        [ "$collection_native_index" != 2 ] || collection_native_provider=$jobs_key_b
        agent_jobs_cli client content custody deposit --manifest "$jobs_source/collection-native-$collection_native_index.pb" \
            --identity "$jobs_source/collection-native-identity.key" --passphrase-file "$jobs_source/passphrase" \
            --cache "$jobs_source/collection-native-cache" --provider-key "$collection_native_provider" \
            >"$WORK/agent-public-collection-network-deposit-$collection_native_index.json" \
            2>"$WORK/agent-public-collection-network-deposit-$collection_native_index.err" || fail COLLECTION_NATIVE_DEPOSIT_FAILED
    done
    PHASE=agent-public-collection-native-warm-source-one
    if [ -e "$jobs_source/collection-source-cache" ] || [ -L "$jobs_source/collection-source-cache" ]; then
        fail COLLECTION_CONSUMER_CACHE_NOT_NEW
    fi
    collection_native_publisher=$(jq -er '.publisher_key_hex' "$WORK/agent-public-collection-network-publish-1.json")
    agent_jobs_cli client content fetch-name --publisher-key "$collection_native_publisher" \
        --name disposable-collection-source-1 --min-revision 1 --cache "$jobs_source/collection-source-cache" \
        --local-output "$jobs_source/collection-warmed-1.txt" \
        >"$WORK/agent-public-collection-network-warm.json" 2>"$WORK/agent-public-collection-network-warm.err" \
        || fail COLLECTION_NATIVE_WARMUP_FAILED
    agent_public_collection_check cache-before "$WORK" || fail COLLECTION_NATIVE_WARM_COLD_SPLIT_FAILED
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
    set -- prepare "$WORK"
    [ "${agent_public_network_sources:-no}" != yes ] || set -- "$@" --network
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-public-collection-smoke.py" "$@" \
        >"$WORK/agent-public-collection-input.json" || fail COLLECTION_PUBLIC_INPUT_FAILED
    if [ "${agent_public_network_sources:-no}" = yes ]; then
        agent_public_collection_native_sources
    fi
    PHASE=agent-public-collection-tokenizer-enrollment
    set -- compute peer document --source-plan "$jobs_source/collection-source-plan.json" \
        --public-content --license GPL-3.0-only --public-question 'Summarize the provided public context.' \
        --runtime-root "$jobs_source/collection-runtime" --model-root "$jobs_source/collection-model" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" --publisher-key "$jobs_publisher" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --directory "$collection_root" \
        --synthesize --enroll-only --lifetime-seconds 7200 --max-seconds 600 --execute
    if [ "${agent_public_network_sources:-no}" = yes ]; then
        set -- "$@" --source-cache "$jobs_source/collection-source-cache" --reuse-source-cache
    fi
    agent_public_collection_cli "$@" \
        >"$WORK/agent-public-collection-enrollment.json" 2>"$WORK/agent-public-collection-enrollment.err" \
        || fail COLLECTION_TOKENIZER_ENROLLMENT_FAILED
    agent_public_collection_check enrolled "$WORK" || fail COLLECTION_PRE_JOB_BOUNDARY_FAILED
    PHASE=agent-public-collection-fragments-and-synthesis
    if [ "${agent_public_network_sources:-no}" != yes ]; then
        content_custody_phase_start fetch
    fi
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
    agent_public_collection_check remove-inputs "$WORK" || fail COLLECTION_ORIGINAL_INPUT_REMOVAL_FAILED
    agent_public_collection_check stopped "$WORK" || fail COLLECTION_PROCESS_CLEANUP_FAILED
    agent_public_collection_cli compute peer document --directory "$collection_root" --resume --execute \
        >"$WORK/agent-public-collection-resume.json" 2>"$WORK/agent-public-collection-resume.err" \
        || fail COLLECTION_OFFLINE_RESUME_FAILED
    agent_public_collection_check resumed "$WORK" || fail COLLECTION_OFFLINE_HISTORY_CHANGED
    agent_jobs_cleanup || fail COLLECTION_PRIVATE_CLEANUP_FAILED
    agent_public_collection_check evidence "$WORK" "$expected_commit" || fail COLLECTION_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-public-collection-complete
}

agent_public_collection_finalize_report() {
    for collection_log in "$WORK"/agent-public-collection-*.json "$WORK"/agent-public-collection-*.jsonl \
        "$WORK"/agent-public-collection-*.err "$WORK"/agent-public-collection-*.log; do
        [ ! -f "$collection_log" ] || [ -L "$collection_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$collection_log" "$output_directory/$(basename -- "$collection_log")"
    done
    agent_public_collection_check finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-public-collection-smoke.json" "$output_directory/agent-public-collection-smoke.json"
    agent_public_collection_check report "$WORK/agent-public-collection-smoke.json" "$expected_commit"
}
