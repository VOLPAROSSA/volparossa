#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the owned disposable KVM topology. No host model execution.
# shellcheck disable=SC2154,SC2034

agent_successor_serving_private() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-successor-serving-smoke.py" "$@"
}

agent_successor_serving_wait_ready() {
    case $successor_label in base) successor_caps=base-caps ;; adapted) successor_caps=active-caps ;; invalid) successor_caps=invalid-caps ;; *) return 1 ;; esac
    # Readiness is only a hint, never a reserved slot. One fixed monotonic bound
    # covers all probes; no job exists yet and no accepted lease is retried.
    successor_deadline=$(python3 -c 'import time; print(time.monotonic() + 120)') || return 1
    while :; do
        successor_client=$(timeout --kill-after=1s 2s systemctl show --property=MainPID --value volparossa-alpha-agent@client.service) || return 1
        case $successor_client in ''|0|*[!0-9]*) return 1 ;; esac
        successor_remaining=$(python3 -c 'import sys,time; print(min(10.0, max(0.0, float(sys.argv[1]) - time.monotonic())))' "$successor_deadline") || return 1
        [ "$successor_remaining" != 0.0 ] || fail SUCCESSOR_READINESS_DEADLINE
        # Same protected client namespace and unprivileged CLI as agent_jobs_cli,
        # with each probe capped at 10s and by the remaining 120s readiness budget.
        timeout --signal=INT --kill-after=2s "${successor_remaining}s" nsenter --target "$successor_client" --mount --net \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
            compute peer capabilities --provider-key "$jobs_key_a" \
            >"$WORK/agent-successor-serving-$successor_caps.json" \
            2>"$WORK/agent-successor-serving-$successor_caps.err" || fail SUCCESSOR_CAPABILITIES_UNCONFIRMED
        successor_ready=$(python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" ready \
            "$WORK" "$successor_label") || fail SUCCESSOR_CAPABILITIES_INVALID
        python3 -c 'import sys,time; sys.exit(0 if time.monotonic() < float(sys.argv[1]) else 1)' \
            "$successor_deadline" || fail SUCCESSOR_READINESS_DEADLINE
        if [ "$successor_ready" = true ]; then return 0; fi
        [ "$successor_ready" = false ] || fail SUCCESSOR_CAPABILITIES_INVALID
        sleep 0.5
    done
}

agent_successor_serving_job() {
    successor_label=$1
    agent_successor_serving_wait_ready || fail SUCCESSOR_READINESS_FAILED
    # Submit stays concurrent with the observer, so observing a fast real worker
    # never depends on waiting for the submit command to return first.
    agent_jobs_cli client compute peer submit --provider-key "$jobs_key_a" \
        --dataset "$jobs_source/dataset.json" --dataset-manifest "$jobs_source/manifest.pb" \
        --publisher-key "$jobs_publisher" --row 0 --max-seconds 600 \
        --handle "$jobs_source/successor-$successor_label.json" --execute \
        >"$WORK/agent-successor-serving-$successor_label-submit.json" \
        2>"$WORK/agent-successor-serving-$successor_label-submit.err" &
    jobs_batch_pid=$!
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" observe-job \
        "$WORK" "$successor_label" || fail SUCCESSOR_ACTUAL_WORKER_NOT_OBSERVED
    wait "$jobs_batch_pid" || fail SUCCESSOR_SUBMIT_UNCONFIRMED
    jobs_batch_pid=
    successor_poll=0
    while [ "$successor_poll" -lt 600 ]; do
        agent_jobs_cli client compute peer poll --handle "$jobs_source/successor-$successor_label.json" \
            >"$WORK/agent-successor-serving-$successor_label-status.json" \
            2>"$WORK/agent-successor-serving-$successor_label-status.err" || fail SUCCESSOR_POLL_UNCONFIRMED
        successor_state=$(jq -er '.state' "$WORK/agent-successor-serving-$successor_label-status.json")
        case $successor_state in complete) return 0 ;; running) ;; *) fail SUCCESSOR_JOB_FAILED ;; esac
        sleep 0.5
        successor_poll=$((successor_poll + 1))
    done
    fail SUCCESSOR_JOB_INCOMPLETE
}

agent_successor_serving_run() {
    [ "$provider_node_a" = relay4 ] || fail SUCCESSOR_STATIC_LEARNER_MISMATCH
    successor_private=$WORK/state-$provider_node_a/compute
    successor_source=$WORK/state-$provider_node_b/compute/successor-source
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$successor_source"
    PHASE=agent-successor-serving-base
    content_custody_phase_start fetch
    agent_successor_serving_job base
    PHASE=agent-successor-serving-public-source
    agent_successor_serving_private source "$successor_source" "$expected_commit" || fail SUCCESSOR_SOURCE_FAILED
    agent_jobs_cli "$provider_node_b" content publish --input "$successor_source/dataset.json" \
        --name disposable-successor-training --revision 1 --content-type application/vnd.volparossa.agent-dataset.v1+json \
        --identity "$WORK/state-$provider_node_b/identity.key" \
        --passphrase-file "$WORK/credential-$provider_node_b/identity-passphrase" \
        --cache "$successor_source/cache" --manifest "$successor_source/manifest.pb" \
        --lifetime-seconds 7200 --contribute >"$WORK/agent-successor-serving-publish.json" \
        2>"$WORK/agent-successor-serving-publish.err" || fail SUCCESSOR_SOURCE_PUBLICATION_FAILED
    agent_jobs_cli client content fetch-name --publisher-key "$jobs_key_b" --name disposable-successor-training \
        --min-revision 1 --cache "$jobs_source/successor-cache" --local-output "$jobs_source/successor-source.json" \
        >"$WORK/agent-successor-serving-source-fetch.json" \
        2>"$WORK/agent-successor-serving-source-fetch.err" || fail SUCCESSOR_SOURCE_FETCH_FAILED
    # Same-owner inode-preserving cache relocation, not learner-side network retrieval.
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" seed "$WORK" || fail SUCCESSOR_CACHE_PROVISION_FAILED
    PHASE=agent-successor-serving-local-source
    agent_jobs_cli "$provider_node_a" role show >"$WORK/agent-successor-serving-learner-roles.log" \
        2>"$WORK/agent-successor-serving-learner-roles.err" || fail SUCCESSOR_LEARNER_ROLES_UNCONFIRMED
    agent_jobs_cli "$provider_node_a" content fetch-name --publisher-key "$jobs_key_b" --name disposable-successor-training \
        --min-revision 1 --cache "$successor_private/source-cache" --reuse-cache --cache-only \
        --local-output "$successor_private/source-preflight.json" \
        >"$WORK/agent-successor-serving-local-source.json" \
        2>"$WORK/agent-successor-serving-local-source.err" || fail SUCCESSOR_LEARNER_LOCAL_SOURCE_UNAVAILABLE
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" local-source "$WORK" \
        || fail SUCCESSOR_LEARNER_LOCAL_SOURCE_INVALID
    PHASE=agent-successor-serving-train
    successor_node_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$provider_node_a.service")
    case $successor_node_pid in ''|0|*[!0-9]*) fail SUCCESSOR_NODE_NOT_RUNNING ;; esac
    # Keep the guest cgroup view for the real spare-capacity probe, but enter the exact node network.
    timeout --signal=INT --kill-after=15s 660s nsenter --target "$successor_node_pid" --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-$provider_node_a/control/agent.sock" \
        compute train-loop --plan "$successor_private/plan.json" --directory "$successor_private/loop" \
        --runtime-root "$successor_private/runtime" --model-root "$jobs_root/provision/model" \
        --cache "$successor_private/source-cache" --serving-directory "$successor_private/serving" \
        --max-cycles 1 --steps 8 --threads 2 --max-seconds 600 --poll-seconds 1 --execute \
        >"$WORK/agent-successor-serving-loop.jsonl" 2>"$WORK/agent-successor-serving-loop.err" &
    jobs_batch_pid=$!
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" observe-training \
        "$WORK" "$jobs_batch_pid" || fail SUCCESSOR_REAL_TRAINING_NOT_OBSERVED
    wait "$jobs_batch_pid" || fail SUCCESSOR_TRAIN_LOOP_FAILED
    jobs_batch_pid=
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" capture-loop "$WORK" \
        || fail SUCCESSOR_APPROVED_SELECTION_MISSING
    PHASE=agent-successor-serving-activation
    agent_successor_serving_job adapted
    agent_jobs_cli client compute peer poll --handle "$jobs_source/successor-base.json" \
        >"$WORK/agent-successor-serving-base-retained.json" || fail SUCCESSOR_OLD_RECEIPT_UNAVAILABLE
    PHASE=agent-successor-serving-invalid-selection
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" invalidate "$WORK" || fail SUCCESSOR_INVALID_CONTROL_FAILED
    sleep 2.1
    successor_label=invalid
    agent_successor_serving_wait_ready || fail SUCCESSOR_INVALID_CAPABILITIES_FAILED
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" capture "$WORK" \
        || fail SUCCESSOR_TRANSITION_INVALID
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail SUCCESSOR_ROUTE_CLEANUP_FAILED
    agent_jobs_cleanup || fail SUCCESSOR_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" evidence "$WORK" "$expected_commit" \
        || fail SUCCESSOR_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-successor-serving-complete
}

agent_successor_serving_finalize_report() {
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    for successor_log in "$WORK"/agent-successor-serving-*.json "$WORK"/agent-successor-serving-*.jsonl \
        "$WORK"/agent-successor-serving-*.err "$WORK"/agent-successor-serving-*.log; do
        [ ! -f "$successor_log" ] || [ -L "$successor_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$successor_log" "$output_directory/$(basename -- "$successor_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-successor-serving-smoke.py" report \
        "$WORK/agent-successor-serving-smoke.json" "$expected_commit"
}
