#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only inside the owned disposable guest. No model runs on the host.
# shellcheck disable=SC2154,SC2034

agent_active_recovery_python() {
    python3 -B "$source_directory/tests/integration/agent-active-recovery-smoke.py" "$@"
}

agent_active_recovery_publish() {
    recovery_name=$1
    agent_jobs_cli "$provider_node_b" content publish --input "$recovery_source/$recovery_name.json" \
        --name "disposable-recovery-$recovery_name" --revision 1 \
        --content-type application/vnd.volparossa.agent-dataset.v1+json \
        --identity "$WORK/state-$provider_node_b/identity.key" \
        --passphrase-file "$WORK/credential-$provider_node_b/identity-passphrase" \
        --cache "$recovery_source/$recovery_name-cache" --manifest "$recovery_source/$recovery_name.pb" \
        --lifetime-seconds 7200 --contribute >"$WORK/agent-active-recovery-$recovery_name-publish.json" \
        2>"$WORK/agent-active-recovery-$recovery_name-publish.err" || fail RECOVERY_SOURCE_PUBLICATION_FAILED
}

agent_active_recovery_cache() {
    recovery_cache_node=$1; recovery_cache_key=$2; recovery_cache_name=$3
    # Only the producing peer is owner-provisioned. R4's coordinator fetches
    # its sources and Q itself through the protected node-local API.
    [ "$recovery_cache_node" = relay5 ] || fail RECOVERY_LEARNER_CACHE_RELOCATION_FORBIDDEN
    recovery_cache_label=$4
    recovery_cache_revision=${5:-1}
    agent_active_recovery_python cache-out "$WORK" "$recovery_cache_node" "$recovery_cache_label" \
        || fail RECOVERY_CACHE_PROVISION_FAILED
    set --
    [ ! -d "$jobs_source/recovery-cache" ] || set -- --reuse-cache
    agent_jobs_cli client content fetch-name --publisher-key "$recovery_cache_key" \
        --name "$recovery_cache_name" --min-revision "$recovery_cache_revision" --cache "$jobs_source/recovery-cache" "$@" \
        --local-output "$jobs_source/recovery-$recovery_cache_label.bin" \
        >"$WORK/agent-active-recovery-$recovery_cache_label-fetch.json" \
        2>"$WORK/agent-active-recovery-$recovery_cache_label-fetch.err" || fail RECOVERY_PROTECTED_SOURCE_FETCH_FAILED
    agent_active_recovery_python cache-in "$WORK" "$recovery_cache_node" "$recovery_cache_label" \
        || fail RECOVERY_CACHE_PROVISION_FAILED
}

agent_active_recovery_catalog() {
    recovery_catalog_revision=$1
    agent_active_recovery_python catalog "$WORK" "$recovery_catalog_revision" || fail RECOVERY_CATALOG_INPUT_FAILED
    agent_jobs_cli "$provider_node_b" content publish --input "$recovery_source/catalog-$recovery_catalog_revision.json" \
        --name disposable-recovery-catalog --revision "$recovery_catalog_revision" \
        --content-type application/vnd.volparossa.agent-source-catalog.v1+json \
        --identity "$WORK/state-$provider_node_b/identity.key" \
        --passphrase-file "$WORK/credential-$provider_node_b/identity-passphrase" \
        --cache "$recovery_source/catalog-$recovery_catalog_revision-cache" --manifest "$recovery_source/catalog-$recovery_catalog_revision.pb" \
        --lifetime-seconds 7200 --contribute >"$WORK/agent-active-recovery-catalog-$recovery_catalog_revision-publish.json" \
        2>"$WORK/agent-active-recovery-catalog-$recovery_catalog_revision-publish.err" || fail RECOVERY_CATALOG_PUBLICATION_FAILED
}

agent_active_recovery_network_start() {
    recovery_network_node=$1; recovery_network_label=$2
    [ -z "${jobs_batch_pid:-}" ] || fail RECOVERY_NETWORK_PHASE_WORKER_ACTIVE
    [ -z "$PRIVACY_CLIENT_PID$PRIVACY_RELAY0_PID$PRIVACY_RELAY1_PID$PRIVACY_RELAY2_PID$PRIVACY_EXIT_PID$PROVIDER_CONTROL_PID" ] \
        || fail RECOVERY_CAPTURE_OVERLAP
    case $recovery_network_node in
        relay4) recovery_network_phase=uptake; recovery_other_node=client ;;
        client) recovery_network_phase=reserve-fetch; recovery_other_node=relay4 ;;
        *) fail RECOVERY_NETWORK_NODE_INVALID ;;
    esac
    content_replication_disconnect "$recovery_other_node" "agent-active-recovery-$recovery_network_label-other" \
        || fail RECOVERY_OTHER_ROUTE_NOT_IDLE
    recovery_network_prefix=agent-active-recovery-path-$recovery_network_label
    content_replication_select "$recovery_network_node" "$recovery_network_prefix" \
        || fail RECOVERY_PROTECTED_ROUTE_UNAVAILABLE
    content_replication_capture "$recovery_network_phase" "$recovery_network_prefix" \
        "$WORK/$recovery_network_prefix-selection.json" || fail RECOVERY_CAPTURE_UNAVAILABLE
}

agent_active_recovery_network_finish() {
    [ -z "${jobs_batch_pid:-}" ] || fail RECOVERY_NETWORK_PHASE_WORKER_ACTIVE
    content_replication_snapshot "$recovery_network_node" "$recovery_network_prefix-live" \
        || fail RECOVERY_LIVE_ROUTE_MISSING
    stop_privacy_observers || fail RECOVERY_CAPTURE_INCOMPLETE
    content_replication_disconnect "$recovery_network_node" "$recovery_network_prefix" \
        || fail RECOVERY_ROUTE_CLEANUP_FAILED
    agent_active_recovery_python network-path "$WORK" "$recovery_network_label" \
        || fail RECOVERY_NETWORK_EVIDENCE_FAILED
}

agent_active_recovery_loop_start() {
    recovery_node=$1; recovery_label=$2; recovery_mode=$3
    recovery_private=$WORK/state-$recovery_node/compute
    recovery_node_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$recovery_node.service")
    case $recovery_node_pid in ''|0|*[!0-9]*) fail RECOVERY_NODE_NOT_RUNNING ;; esac
    set --
    if [ "$recovery_node" = "$provider_node_a" ]; then
        set -- --peer-updates "$recovery_private/channels.json" --serving-directory "$recovery_private/serving"
        recovery_publication=disposable-recovery-p; recovery_key=$jobs_key_a
    else
        set -- --seed "$recovery_private/seed.json"
        recovery_publication=disposable-recovery-q; recovery_key=$jobs_key_b
    fi
    case $recovery_mode in
        initial) set -- "$@" --max-cycles 1 ;;
        observe) set -- "$@" --resume ;;
        train) set -- "$@" --resume --max-cycles 1 ;;
        *) fail RECOVERY_LOOP_MODE ;;
    esac
    PHASE=agent-active-recovery-$recovery_label
    timeout --signal=INT --kill-after=15s 1200s nsenter --target "$recovery_node_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-$recovery_node/control/agent.sock" \
        compute train-loop --plan "$recovery_private/plan.json" --directory "$recovery_private/loop" \
        --validation-source "$recovery_private/validation.json" \
        --runtime-root "$recovery_private/runtime" --model-root "$jobs_root/provision/model" \
        --cache "$recovery_private/source-cache" --steps 8 --threads 2 --max-seconds 600 --poll-seconds 1 \
        --publish-name "$recovery_publication" --publication-key "$recovery_key" \
        --identity "$WORK/state-$recovery_node/identity.key" \
        --passphrase-file "$WORK/credential-$recovery_node/identity-passphrase" \
        --publish-cache "$recovery_private/publish-cache" "$@" --execute \
        >"$WORK/agent-active-recovery-$recovery_label-loop.jsonl" \
        2>"$WORK/agent-active-recovery-$recovery_label-loop.err" &
    jobs_batch_pid=$!
    agent_active_recovery_python owner "$WORK" "$recovery_label" "$jobs_batch_pid" \
        || fail RECOVERY_COORDINATOR_IDENTITY_FAILED
}

agent_active_recovery_loop_stop() {
    kill -INT "$jobs_batch_pid" || fail RECOVERY_COORDINATOR_STOP_FAILED
    # GNU timeout forwards this signal to its original child; the coordinator
    # drains/reaps the worker before returning. No PID reconstruction or restart.
    wait "$jobs_batch_pid" || fail RECOVERY_COORDINATOR_REAP_FAILED
    jobs_batch_pid=
}

agent_active_recovery_job() {
    recovery_job_label=$1
    agent_active_recovery_python wait-ready "$WORK" "$recovery_job_label" "$binary_directory/volparossa" \
        || fail RECOVERY_BROKER_NOT_READY
    agent_jobs_cli client compute peer submit --provider-key "$jobs_key_a" \
        --dataset "$jobs_source/dataset.json" --dataset-manifest "$jobs_source/manifest.pb" \
        --publisher-key "$jobs_publisher" --row 0 --max-seconds 600 \
        --handle "$jobs_source/recovery-$recovery_job_label-handle.json" --execute \
        >"$WORK/agent-active-recovery-$recovery_job_label-submit.json" \
        2>"$WORK/agent-active-recovery-$recovery_job_label-submit.err" &
    recovery_submit_pid=$!
    agent_active_recovery_python observe-job "$WORK" "$recovery_job_label" \
        || fail RECOVERY_INFERENCE_WORKER_NOT_OBSERVED
    wait "$recovery_submit_pid" || fail RECOVERY_SUBMIT_FAILED
    recovery_submit_pid=
    recovery_poll=0
    while [ "$recovery_poll" -lt 600 ]; do
        agent_jobs_cli client compute peer poll --handle "$jobs_source/recovery-$recovery_job_label-handle.json" \
            >"$WORK/agent-active-recovery-$recovery_job_label-status.json" \
            2>"$WORK/agent-active-recovery-$recovery_job_label-status.err" || fail RECOVERY_POLL_FAILED
        case $(jq -er '.state' "$WORK/agent-active-recovery-$recovery_job_label-status.json") in
            complete) return 0 ;; running) ;; *) fail RECOVERY_INFERENCE_FAILED ;;
        esac
        sleep 0.5; recovery_poll=$((recovery_poll + 1))
    done
    fail RECOVERY_INFERENCE_DEADLINE
}

agent_active_recovery_run() {
    [ "$provider_node_a" = relay4 ] || fail RECOVERY_NODE_LAYOUT_CHANGED
    [ "$provider_node_b" = relay5 ] || fail RECOVERY_NODE_LAYOUT_CHANGED
    recovery_source=$WORK/state-$provider_node_b/compute/recovery-source
    agent_active_recovery_python sources "$WORK" "$expected_commit" || fail RECOVERY_SOURCE_SETUP_FAILED
    agent_active_recovery_publish train
    agent_active_recovery_publish validation
    agent_active_recovery_cache "$provider_node_b" "$jobs_key_b" disposable-recovery-train relay5-train
    agent_active_recovery_cache "$provider_node_b" "$jobs_key_b" disposable-recovery-validation relay5-validation
    agent_active_recovery_catalog 1
    agent_active_recovery_python enroll "$WORK" || fail RECOVERY_ENROLLMENT_FAILED
    for recovery_seed_node in "$provider_node_a" "$provider_node_b"; do
        agent_jobs_cli "$recovery_seed_node" content publish --input "$WORK/state-$recovery_seed_node/compute/plan.json" \
            --name disposable-recovery-enrollment --revision 1 --content-type application/json \
            --identity "$WORK/state-$recovery_seed_node/identity.key" \
            --passphrase-file "$WORK/credential-$recovery_seed_node/identity-passphrase" \
            --cache "$WORK/state-$recovery_seed_node/compute/publish-cache" \
            --manifest "$WORK/state-$recovery_seed_node/compute/enrollment.pb" --lifetime-seconds 7200 \
            >"$WORK/agent-active-recovery-$recovery_seed_node-owner-cache.json" || fail RECOVERY_OWNER_CACHE_FAILED
    done
    # The existing train-loop API reopens an owner-created cache. Initialize it
    # with only the learner's own public enrollment, never a dataset or peer Q.
    agent_jobs_cli "$provider_node_a" content publish --input "$WORK/state-$provider_node_a/compute/plan.json" \
        --name disposable-recovery-cache-init --revision 1 --content-type application/json \
        --identity "$WORK/state-$provider_node_a/identity.key" \
        --passphrase-file "$WORK/credential-$provider_node_a/identity-passphrase" \
        --cache "$WORK/state-$provider_node_a/compute/source-cache" \
        --manifest "$WORK/state-$provider_node_a/compute/source-cache-init.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-active-recovery-learner-cache-init.json" || fail RECOVERY_LEARNER_EMPTY_CACHE_FAILED
    agent_active_recovery_python learner-isolation "$WORK" || fail RECOVERY_LEARNER_SOURCE_SHORTCUT
    agent_active_recovery_network_start relay4 p
    agent_active_recovery_loop_start "$provider_node_a" p initial
    agent_active_recovery_python observe-training "$WORK" p "$provider_node_a" 1 "$jobs_batch_pid" \
        || fail RECOVERY_P_REAL_TRAINING_MISSING
    wait "$jobs_batch_pid" || fail RECOVERY_P_LOOP_FAILED
    jobs_batch_pid=
    agent_active_recovery_python capture-cycle "$WORK" p "$provider_node_a" 1 || fail RECOVERY_P_NOT_APPROVED
    agent_active_recovery_network_finish
    agent_active_recovery_network_start client job-p
    agent_active_recovery_job p
    agent_active_recovery_cache "$provider_node_b" "$jobs_key_a" disposable-recovery-p q-seed
    agent_active_recovery_network_finish
    agent_active_recovery_loop_start "$provider_node_b" q initial
    agent_active_recovery_python observe-training "$WORK" q "$provider_node_b" 1 "$jobs_batch_pid" \
        || fail RECOVERY_Q_REAL_TRAINING_MISSING
    wait "$jobs_batch_pid" || fail RECOVERY_Q_LOOP_FAILED
    jobs_batch_pid=
    agent_active_recovery_python capture-cycle "$WORK" q "$provider_node_b" 1 || fail RECOVERY_Q_NOT_APPROVED
    agent_active_recovery_network_start relay4 adoption
    agent_active_recovery_loop_start "$provider_node_a" adoption observe
    agent_active_recovery_python await "$WORK" active "$jobs_batch_pid" || fail RECOVERY_REAL_Q_ADOPTION_MISSING
    agent_active_recovery_loop_stop
    agent_active_recovery_network_finish
    agent_active_recovery_network_start client job-q
    agent_active_recovery_job q
    agent_active_recovery_network_finish
    # Resume the same durable Q approval before injecting the fault. This
    # keeps Client inference and learner fetching in separate measured phases;
    # no worker is frozen and no approval or deadline is regenerated.
    agent_active_recovery_loop_start "$provider_node_a" recovery observe
    agent_active_recovery_python await "$WORK" armed "$jobs_batch_pid" || fail RECOVERY_Q_RESTART_CHANGED
    agent_active_recovery_python inject "$WORK" || fail RECOVERY_LOCAL_EXTRACTION_FAULT_FAILED
    agent_active_recovery_python await "$WORK" restored "$jobs_batch_pid" || fail RECOVERY_AUTOMATIC_ROLLBACK_MISSING
    agent_active_recovery_loop_stop
    agent_active_recovery_network_start client job-restored
    agent_active_recovery_job restored
    agent_active_recovery_network_finish
    agent_active_recovery_loop_start "$provider_node_a" restart observe
    agent_active_recovery_python await "$WORK" restarted "$jobs_batch_pid" || fail RECOVERY_RESTART_NOT_IDEMPOTENT
    agent_active_recovery_loop_stop
    agent_active_recovery_publish next
    agent_active_recovery_catalog 2
    agent_active_recovery_network_start relay4 continued
    agent_active_recovery_loop_start "$provider_node_a" continued train
    agent_active_recovery_python observe-training "$WORK" continued "$provider_node_a" 2 "$jobs_batch_pid" \
        || fail RECOVERY_RESTORED_WARMSTART_NOT_OBSERVED
    wait "$jobs_batch_pid" || fail RECOVERY_CONTINUED_TRAINING_FAILED
    jobs_batch_pid=
    agent_active_recovery_python capture-cycle "$WORK" continued "$provider_node_a" 2 || fail RECOVERY_CONTINUED_TRAINING_INVALID
    agent_active_recovery_network_finish
    agent_active_recovery_network_start client receipts
    for recovery_receipt in p q; do
        agent_jobs_cli client compute peer poll --handle "$jobs_source/recovery-$recovery_receipt-handle.json" \
            >"$WORK/agent-active-recovery-$recovery_receipt-retained.json" || fail RECOVERY_ORIGINAL_RECEIPT_MISSING
    done
    agent_active_recovery_python capture "$WORK" || fail RECOVERY_ORIGINALS_CHANGED
    agent_active_recovery_network_finish
    agent_jobs_cleanup || fail RECOVERY_PRIVATE_CLEANUP_FAILED
    agent_active_recovery_python evidence "$WORK" "$expected_commit" || fail RECOVERY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-active-recovery-complete
}

agent_active_recovery_finalize_report() {
    agent_active_recovery_python finalize "$WORK" "$expected_commit" "$1" "$CLEANUP_COMPLETE" \
        "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    for recovery_log in "$WORK"/agent-active-recovery-*.json "$WORK"/agent-active-recovery-*.jsonl \
        "$WORK"/agent-active-recovery-*.err "$WORK"/agent-active-recovery-*.log; do
        [ ! -f "$recovery_log" ] || [ -L "$recovery_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$recovery_log" "$output_directory/$(basename -- "$recovery_log")"
    done
    agent_active_recovery_python report "$WORK/agent-active-recovery-smoke.json" "$expected_commit"
}
