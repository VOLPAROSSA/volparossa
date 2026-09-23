#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive disposable-guest proof; never invoked outside the existing scenario.
# shellcheck disable=SC2154,SC2034

agent_aggregate_recovery_python() {
    python3 -B "$source_directory/tests/integration/agent-aggregate-recovery-smoke.py" "$@"
}

agent_aggregate_recovery_loop() {
    recovery_label=$1
    agent_autonomous_aggregation_loop_start "recovery-$recovery_label" --resume
    if [ "$recovery_label" != blocked ]; then
        agent_aggregate_recovery_python observe-loop "$WORK" "$recovery_label" "$jobs_batch_pid" \
            || fail AGGREGATE_RECOVERY_NOT_OBSERVED
    fi
    recovery_status=0
    wait "$jobs_batch_pid" || recovery_status=$?
    jobs_batch_pid=
    agent_aggregate_recovery_python capture "$WORK" "$recovery_label" "$recovery_status" \
        || fail AGGREGATE_RECOVERY_EXIT_INVALID
}

agent_aggregate_recovery_wait_ready() {
    recovery_ready_label=$1
    recovery_deadline=$(python3 -c 'import time; print(time.monotonic() + 120)') || return 1
    while :; do
        recovery_client=$(timeout --kill-after=1s 2s systemctl show --property=MainPID --value volparossa-alpha-agent@client.service) || return 1
        case $recovery_client in ''|0|*[!0-9]*) return 1 ;; esac
        recovery_remaining=$(python3 -c 'import sys,time; print(min(10.0, max(0.0, float(sys.argv[1]) - time.monotonic())))' "$recovery_deadline") || return 1
        [ "$recovery_remaining" != 0.0 ] || fail AGGREGATE_RECOVERY_READINESS_DEADLINE
        timeout --signal=INT --kill-after=2s "${recovery_remaining}s" nsenter --target "$recovery_client" --mount --net \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
            compute peer capabilities --provider-key "$jobs_key_a" \
            >"$WORK/agent-aggregate-recovery-$recovery_ready_label-capabilities.json" \
            2>"$WORK/agent-aggregate-recovery-$recovery_ready_label-capabilities.err" || fail AGGREGATE_RECOVERY_CAPABILITIES_FAILED
        recovery_ready=$(agent_aggregate_recovery_python ready "$WORK" "$recovery_ready_label") \
            || fail AGGREGATE_RECOVERY_CAPABILITIES_INVALID
        if [ "$recovery_ready" = true ]; then return 0; fi
        [ "$recovery_ready" = false ] || fail AGGREGATE_RECOVERY_CAPABILITIES_INVALID
        sleep 0.5
    done
}

agent_aggregate_recovery_job() {
    agent_aggregate_recovery_wait_ready restored || fail AGGREGATE_RECOVERY_READINESS_FAILED
    agent_jobs_cli client compute peer submit --provider-key "$jobs_key_a" \
        --dataset "$jobs_source/dataset.json" --dataset-manifest "$jobs_source/manifest.pb" \
        --publisher-key "$jobs_publisher" --row 0 --max-seconds 600 \
        --handle "$jobs_source/aggregate-recovery-job.json" --execute \
        >"$WORK/agent-aggregate-recovery-submit.json" \
        2>"$WORK/agent-aggregate-recovery-submit.err" &
    jobs_batch_pid=$!
    agent_aggregate_recovery_python observe-job "$WORK" || fail AGGREGATE_RECOVERY_WORKER_MISSING
    wait "$jobs_batch_pid" || fail AGGREGATE_RECOVERY_SUBMIT_FAILED
    jobs_batch_pid=
    recovery_poll=0
    while [ "$recovery_poll" -lt 600 ]; do
        agent_jobs_cli client compute peer poll --handle "$jobs_source/aggregate-recovery-job.json" \
            >"$WORK/agent-aggregate-recovery-status.json" \
            2>"$WORK/agent-aggregate-recovery-status.err" || fail AGGREGATE_RECOVERY_POLL_FAILED
        recovery_state=$(jq -er '.state' "$WORK/agent-aggregate-recovery-status.json")
        case $recovery_state in
            complete) agent_aggregate_recovery_python capture-job "$WORK" || fail AGGREGATE_RECOVERY_JOB_CAPTURE_FAILED; return 0 ;;
            running) ;;
            *) fail AGGREGATE_RECOVERY_PEER_JOB_FAILED ;;
        esac
        sleep 0.5
        recovery_poll=$((recovery_poll + 1))
    done
    fail AGGREGATE_RECOVERY_PEER_JOB_INCOMPLETE
}

agent_aggregate_recovery_network_start() {
    [ -z "${jobs_batch_pid:-}" ] || fail AGGREGATE_RECOVERY_WORKER_STILL_ACTIVE
    [ -z "$PRIVACY_CLIENT_PID$PRIVACY_RELAY0_PID$PRIVACY_RELAY1_PID$PRIVACY_RELAY2_PID$PRIVACY_EXIT_PID$PROVIDER_CONTROL_PID" ] \
        || fail AGGREGATE_RECOVERY_CAPTURE_OVERLAP
    recovery_prefix=agent-aggregate-recovery-path
    content_replication_disconnect relay4 "$recovery_prefix-other" || fail AGGREGATE_RECOVERY_OTHER_ROUTE_ACTIVE
    content_replication_select client "$recovery_prefix" || fail AGGREGATE_RECOVERY_ROUTE_UNAVAILABLE
    content_replication_capture reserve-fetch "$recovery_prefix" "$WORK/$recovery_prefix-selection.json" \
        || fail AGGREGATE_RECOVERY_CAPTURE_UNAVAILABLE
}

agent_aggregate_recovery_network_finish() {
    [ -z "${jobs_batch_pid:-}" ] || fail AGGREGATE_RECOVERY_WORKER_STILL_ACTIVE
    content_replication_snapshot client "$recovery_prefix-live" || fail AGGREGATE_RECOVERY_LIVE_ROUTE_MISSING
    stop_privacy_observers || fail AGGREGATE_RECOVERY_CAPTURE_INCOMPLETE
    content_replication_disconnect client "$recovery_prefix" || fail AGGREGATE_RECOVERY_ROUTE_CLEANUP_FAILED
    agent_aggregate_recovery_python network "$WORK" || fail AGGREGATE_RECOVERY_PATH_EVIDENCE_INVALID
}

agent_aggregate_recovery_run() {
    PHASE=agent-aggregate-recovery-originals
    agent_aggregate_recovery_python prepare "$WORK" || fail AGGREGATE_RECOVERY_APPROVED_SUCCESSOR_REQUIRED
    # Serving reconciliation precedes the next due metadata poll. Prepare its
    # ordinary protected route now, so owner cancellation cannot leave an agent
    # bootstrap Connecting while the later Client capture is being selected.
    # This preparatory route is not counted as restored-inference packet proof.
    content_replication_select relay4 agent-aggregate-recovery-loop || fail AGGREGATE_RECOVERY_LOOP_ROUTE_UNAVAILABLE
    agent_aggregate_recovery_python inject "$WORK" local || fail AGGREGATE_RECOVERY_LOCAL_FAULT_INVALID
    agent_aggregate_recovery_loop local
    agent_aggregate_recovery_loop resume
    agent_aggregate_recovery_network_start
    PHASE=agent-aggregate-recovery-protected-inference
    agent_aggregate_recovery_job
    agent_aggregate_recovery_python inject "$WORK" aggregate || fail AGGREGATE_RECOVERY_AGGREGATE_FAULT_INVALID
    agent_aggregate_recovery_loop blocked
    agent_aggregate_recovery_wait_ready blocked || fail AGGREGATE_RECOVERY_ADMISSION_NOT_WITHDRAWN
    agent_aggregate_recovery_network_finish
    PHASE=agent-aggregate-recovery-complete
}
