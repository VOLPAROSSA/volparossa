#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Guest-only coordinator lifecycle; the manual fixture supplies three originals.
# shellcheck disable=SC2154,SC2034

agent_autonomous_aggregation_python() {
    python3 -B "$source_directory/tests/integration/agent-autonomous-aggregation-smoke.py" "$@"
}

agent_autonomous_aggregation_loop() {
    auto_label=$1
    shift
    auto_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay4.service)
    case $auto_pid in ''|0|*[!0-9]*) fail AUTONOMOUS_LEARNER_NOT_RUNNING ;; esac
    PHASE=agent-autonomous-aggregation-$auto_label
    auto_bound=4000s
    [ "$auto_label" != resume ] || auto_bound=150s
    timeout --signal=INT --kill-after=15s "$auto_bound" nsenter --target "$auto_pid" --mount --net \
        unshare --mount --propagation private --mount-proc=/proc \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay4/control/agent.sock" \
        compute train-loop --plan "$aa_r4/source-plan.json" --aggregate-plan "$aa_r4/plan.json" \
        --validation-source "$aa_r4/validation-source.json" --directory "$aa_r4/autonomous-loop" \
        --runtime-root "$aa_r4/runtime" --model-root "$jobs_root/provision/model" --cache "$aa_r4/source-cache" \
        --serving-directory "$aa_r4/serving" --max-cycles 1 --steps 8 --threads 2 --max-seconds 600 \
        --poll-seconds 2 --execute "$@" \
        >"$WORK/agent-autonomous-aggregation-$auto_label.jsonl" \
        2>"$WORK/agent-autonomous-aggregation-$auto_label.err" &
    jobs_batch_pid=$!
    if [ "$auto_label" = resume ]; then
        agent_autonomous_aggregation_python observe-resume "$WORK" "$jobs_batch_pid" \
            || fail AUTONOMOUS_RESTART_NOT_OBSERVED
    else
        agent_autonomous_aggregation_python observe-loop "$WORK" "$jobs_batch_pid" \
            || fail AUTONOMOUS_ACTUAL_WORKER_MISSING
    fi
    wait "$jobs_batch_pid" || fail AUTONOMOUS_LOOP_FAILED
    jobs_batch_pid=
}

agent_autonomous_aggregation_wait_ready() {
    auto_deadline=$(python3 -c 'import time; print(time.monotonic() + 120)') || return 1
    while :; do
        auto_client=$(timeout --kill-after=1s 2s systemctl show --property=MainPID --value volparossa-alpha-agent@client.service) || return 1
        case $auto_client in ''|0|*[!0-9]*) return 1 ;; esac
        auto_remaining=$(python3 -c 'import sys,time; print(min(10.0, max(0.0, float(sys.argv[1]) - time.monotonic())))' "$auto_deadline") || return 1
        [ "$auto_remaining" != 0.0 ] || fail AUTONOMOUS_READINESS_DEADLINE
        timeout --signal=INT --kill-after=2s "${auto_remaining}s" nsenter --target "$auto_client" --mount --net \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
            compute peer capabilities --provider-key "$jobs_key_a" \
            >"$WORK/agent-autonomous-aggregation-capabilities.json" \
            2>"$WORK/agent-autonomous-aggregation-capabilities.err" || fail AUTONOMOUS_CAPABILITIES_FAILED
        auto_ready=$(agent_autonomous_aggregation_python ready "$WORK") || fail AUTONOMOUS_CAPABILITIES_INVALID
        if [ "$auto_ready" = true ]; then return 0; fi
        [ "$auto_ready" = false ] || fail AUTONOMOUS_CAPABILITIES_INVALID
        sleep 0.5
    done
}

agent_autonomous_aggregation_job() {
    agent_autonomous_aggregation_wait_ready || fail AUTONOMOUS_READINESS_FAILED
    agent_jobs_cli client compute peer submit --provider-key "$jobs_key_a" \
        --dataset "$jobs_source/dataset.json" --dataset-manifest "$jobs_source/manifest.pb" \
        --publisher-key "$jobs_publisher" --row 0 --max-seconds 600 \
        --handle "$jobs_source/autonomous-job.json" --execute \
        >"$WORK/agent-autonomous-aggregation-submit.json" \
        2>"$WORK/agent-autonomous-aggregation-submit.err" &
    jobs_batch_pid=$!
    agent_autonomous_aggregation_python observe-job "$WORK" || fail AUTONOMOUS_SERVING_WORKER_MISSING
    wait "$jobs_batch_pid" || fail AUTONOMOUS_SUBMIT_FAILED
    jobs_batch_pid=
    auto_poll=0
    while [ "$auto_poll" -lt 600 ]; do
        agent_jobs_cli client compute peer poll --handle "$jobs_source/autonomous-job.json" \
            >"$WORK/agent-autonomous-aggregation-status.json" \
            2>"$WORK/agent-autonomous-aggregation-status.err" || fail AUTONOMOUS_POLL_FAILED
        auto_state=$(jq -er '.state' "$WORK/agent-autonomous-aggregation-status.json")
        case $auto_state in complete) return 0 ;; running) ;; *) fail AUTONOMOUS_PEER_JOB_FAILED ;; esac
        sleep 0.5
        auto_poll=$((auto_poll + 1))
    done
    fail AUTONOMOUS_PEER_JOB_INCOMPLETE
}

agent_autonomous_aggregation_run() {
    agent_adapter_aggregation_prepare
    agent_autonomous_aggregation_python setup "$WORK" || fail AUTONOMOUS_SETUP_FAILED
    agent_adapter_aggregation_network_start uptake 4200
    agent_autonomous_aggregation_loop first
    agent_autonomous_aggregation_python capture "$WORK" || fail AUTONOMOUS_ORIGINAL_CAPTURE_FAILED
    # The unchanged owner enrollment resumes with the original supplier alive.
    # The observer stops it only after its original cohort was polled again.
    agent_autonomous_aggregation_loop resume --resume
    agent_autonomous_aggregation_python capture-resume "$WORK" || fail AUTONOMOUS_RESTART_CAPTURE_FAILED
    agent_adapter_aggregation_network_finish
    agent_adapter_aggregation_stop_supplier relay5
    agent_adapter_aggregation_network_start receiver
    PHASE=agent-autonomous-aggregation-serving
    agent_autonomous_aggregation_job
    agent_autonomous_aggregation_python capture-job "$WORK" || fail AUTONOMOUS_SERVING_CAPTURE_FAILED
    agent_adapter_aggregation_network_finish
    agent_jobs_cleanup || fail AUTONOMOUS_PRIVATE_CLEANUP_FAILED
    agent_autonomous_aggregation_python evidence "$WORK" "$expected_commit" || fail AUTONOMOUS_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-autonomous-aggregation-complete
}

agent_autonomous_aggregation_finalize_report() {
    agent_autonomous_aggregation_python finalize "$WORK" "$expected_commit" "$1" "$CLEANUP_COMPLETE" \
        "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    for auto_log in "$WORK"/agent-adapter-aggregation-*.json "$WORK"/agent-adapter-aggregation-*.err \
        "$WORK"/agent-autonomous-aggregation-*.json "$WORK"/agent-autonomous-aggregation-*.jsonl \
        "$WORK"/agent-autonomous-aggregation-*.err; do
        [ ! -f "$auto_log" ] || [ -L "$auto_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$auto_log" "$output_directory/$(basename -- "$auto_log")"
    done
    agent_autonomous_aggregation_python report "$WORK/agent-autonomous-aggregation-smoke.json" "$expected_commit"
}
