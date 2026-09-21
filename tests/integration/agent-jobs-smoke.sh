#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Two real node-local executors; sourced only by the disposable KVM runner.
# shellcheck disable=SC2154,SC2034

agent_jobs_private() {
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-jobs-smoke.py" "$@"
}

agent_jobs_cli() {
    jobs_cli_node=$1
    shift
    jobs_cli_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$jobs_cli_node.service")
    case $jobs_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Use the real node's mount as well as network namespace, excluding local shortcuts.
    timeout --signal=INT --kill-after=15s 660s nsenter --target "$jobs_cli_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-$jobs_cli_node/control/agent.sock" "$@"
}

agent_jobs_prepare() {
    PHASE=agent-jobs-provision
    jobs_root=$WORK/agent-jobs-user
    jobs_units=
    jobs_batch_pid=
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$jobs_root"
    agent_jobs_private prepare "$jobs_root" >"$WORK/agent-jobs-provision.log" \
        2>"$WORK/agent-jobs-provision.err" || fail JOBS_PROVISION_FAILED
    install -m 0600 "$jobs_root/provision/provision-report.json" "$WORK/agent-jobs-provision.json"
}

agent_jobs_broker_startup() {
    # Fixed properties only: no journal, command line, environment or private paths.
    # Capture before stop/reset-failed can discard the original startup outcome.
    timeout --signal=TERM --kill-after=1s 2s systemctl show \
        --property=LoadState,ActiveState,SubState,Result,CollectMode,MainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,CPUUsageNSec \
        "$jobs_unit" 2>/dev/null \
        | python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" broker-startup \
            "$jobs_node" "$1" "$jobs_attempt" "$jobs_started" \
        >"$WORK/agent-jobs-$jobs_node-broker-startup.json"
}

agent_jobs_broker() {
    jobs_node=$1
    content_provider_node "$jobs_node" || return 1
    jobs_namespace=$provider_ns
    jobs_private=$WORK/state-$jobs_node/compute
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$jobs_private" "$jobs_private/work"
    # A full independent venv gets its own regular lock inode. Reflink is optional;
    # a normal private copy is the explicit fallback, never hardlinks or redownloads.
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- cp --archive --reflink=auto -- "$jobs_root/provision/venv" "$jobs_private/runtime" || return 1
    jobs_unit=volparossa-alpha-compute@$jobs_node.service
    [ "$(unit_load_state "$jobs_unit")" = not-found ] || return 1
    jobs_units="$jobs_units $jobs_unit"
    jobs_hidden="$WORK/state-client"
    for jobs_other in relay3 relay4 relay5; do
        [ "$jobs_other" = "$jobs_node" ] || jobs_hidden="$jobs_hidden $WORK/state-$jobs_other"
    done
    jobs_attempt=0
    jobs_started=$(python3 -c 'import time; print(time.monotonic_ns())') || return 1
    systemd-run --no-block --unit="$jobs_unit" --slice=system.slice --service-type=exec \
        --property=CollectMode=inactive --property=Restart=no \
        --property=User=volparossa --property=Group=volparossa --property=UMask=0077 \
        --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
        --property="NetworkNamespacePath=/run/netns/$jobs_namespace" \
        --property=PrivateMounts=yes --property=PrivateTmp=yes --property=PrivateDevices=yes \
        --property=ProtectSystem=strict --property=ProtectHome=yes \
        --property="ReadWritePaths=$jobs_private" --property="InaccessiblePaths=$jobs_hidden" \
        --property=KillMode=control-group --property=TimeoutStopSec=20s \
        --property="StandardOutput=append:$WORK/agent-jobs-$jobs_node-broker.log" \
        --property="StandardError=append:$WORK/agent-jobs-$jobs_node-broker.err" \
        -- "$binary_directory/volparossa" compute serve \
        --runtime-root "$jobs_private/runtime" --model-root "$jobs_root/provision/model" \
        --work-root "$jobs_private/work" --socket "$jobs_private/broker.sock" --execute || {
            agent_jobs_broker_startup start_failed || true
            return 1
        }
    while [ "$jobs_attempt" -lt 150 ]; do
        [ ! -S "$jobs_private/broker.sock" ] || break
        if [ "$(systemctl show --property=ActiveState --value "$jobs_unit")" = failed ]; then
            agent_jobs_broker_startup unit_failed || true
            return 1
        fi
        sleep 0.1
        jobs_attempt=$((jobs_attempt + 1))
    done
    if [ ! -S "$jobs_private/broker.sock" ]; then
        agent_jobs_broker_startup socket_timeout || true
        return 1
    fi
    agent_jobs_broker_startup socket_ready || return 1
    content_custody_endpoint "$jobs_node" || return 1
    agent_jobs_cli "$jobs_node" compute peer attach --broker-socket "$jobs_private/broker.sock" \
        --bind "$custody_address:18080" --advertised-hostname "$custody_hostname" \
        --trusted-dataset-publisher "$jobs_publisher" >"$WORK/agent-jobs-$jobs_node-attach.json" \
        2>"$WORK/agent-jobs-$jobs_node-attach.err" || return 1
}

agent_jobs_cgroup_empty() {
    # cgroup.events covers descendants too; an empty cgroup.procs alone does not.
    [ -d "$(dirname -- "$1")" ] && [ ! -L "$1" ] || return 1
    [ -e "$1" ] || return 0
    if [ -d "$1" ] && [ -f "$1/cgroup.events" ] && [ ! -L "$1/cgroup.events" ] \
        && grep -Fx 'populated 0' "$1/cgroup.events" >/dev/null; then
        return 0
    fi
    # A collected empty cgroup may disappear between these read-only checks.
    [ -d "$(dirname -- "$1")" ] && [ ! -L "$1" ] && [ ! -e "$1" ]
}

agent_jobs_stop_unit() {
    jobs_stop_unit=$1
    case $jobs_stop_unit in volparossa-alpha-compute@relay[345].service) ;; *) return 1 ;; esac
    jobs_load_state=$(systemctl show --property=LoadState --value "$jobs_stop_unit") || return 1
    case $jobs_load_state in
        loaded)
            if ! systemctl stop "$jobs_stop_unit"; then
                # Collection can race the first query. A failed stop is not
                # proof of cleanup: accept only collection, then check below.
                jobs_load_state=$(systemctl show --property=LoadState --value "$jobs_stop_unit") || return 1
                [ "$jobs_load_state" = not-found ] || return 1
            fi
            ;;
        # CollectMode=inactive can unload a broker stopped at the earlier cutover.
        not-found) ;;
        *) return 1 ;;
    esac
    jobs_stop_state=$(systemctl show --property=ActiveState --value "$jobs_stop_unit") || return 1
    case $jobs_stop_state in inactive|failed) ;; *) return 1 ;; esac
    jobs_stop_pid=$(systemctl show --property=MainPID --value "$jobs_stop_unit") || return 1
    [ "$jobs_stop_pid" = 0 ] || return 1
    agent_jobs_cgroup_empty "/sys/fs/cgroup/system.slice/$jobs_stop_unit" || return 1
    systemctl reset-failed "$jobs_stop_unit" >/dev/null 2>&1 || true
}

agent_jobs_stop() {
    if [ "${agent_jobs_peer_recovery:-no}" = yes ]; then
        python3 -B "$source_directory/tests/integration/agent-jobs-peer-recovery-smoke.py" cleanup-owner "$WORK" || return 1
    fi
    if [ -n "${jobs_batch_pid:-}" ] && kill -0 "$jobs_batch_pid" 2>/dev/null; then
        kill -INT "$jobs_batch_pid" || return 1
        wait "$jobs_batch_pid" || true
        jobs_batch_pid=
    fi
    for jobs_stop_unit in ${jobs_units:-}; do
        agent_jobs_stop_unit "$jobs_stop_unit" || return 1
    done
    jobs_units=
}

agent_jobs_cleanup() {
    agent_jobs_stop || return 1
    [ -n "${jobs_root:-}" ] && [ -f "$WORK/bin/agent-jobs-smoke.py" ] || return 0
    if [ ! -f "$WORK/agent-jobs-private-cleanup.json" ]; then
        python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" cleanup "$WORK" \
            >"$WORK/agent-jobs-private-cleanup.json" || return 1
    fi
}

agent_jobs_setup() {
    PHASE=agent-jobs-source
    jobs_source=$WORK/state-client/compute-source
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$jobs_source"
    agent_jobs_private source "$jobs_source" "$expected_commit" || fail JOBS_PUBLIC_SOURCE_FAILED
    agent_jobs_cli client init --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        >"$WORK/agent-jobs-init.log" 2>"$WORK/agent-jobs-init.err" || fail JOBS_PUBLISHER_FAILED
    agent_jobs_cli client content publish --input "$jobs_source/dataset.json" \
        --name disposable-agent-jobs --revision 1 --content-type application/vnd.volparossa.agent-dataset.v1+json \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$jobs_source/cache" --manifest "$jobs_source/manifest.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-jobs-publish.json" 2>"$WORK/agent-jobs-publish.err" || fail JOBS_PUBLICATION_FAILED
    jobs_publisher=$(jq -er '.publisher_key_hex' "$WORK/agent-jobs-publish.json")
    agent_jobs_private publication "$jobs_source" >"$WORK/agent-jobs-source.json" || fail JOBS_SOURCE_HASH_FAILED
    benchmark_select_route agent-jobs mptcp || fail JOBS_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/agent-jobs-selection.json" || fail JOBS_ROUTE_INVALID
    custody_context=$(jq -er '.route_context_id' "$WORK/agent-jobs-selection.json")
    agent_jobs_cli client content status >"$WORK/agent-jobs-client-status.json" || fail JOBS_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id' "$WORK/agent-jobs-client-status.json")
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '. as $p | ["relay4","relay5","relay3"]
        | map(select($p[.] != $control)) | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") || fail JOBS_PEERS_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    if [ "${agent_jobs_peer_recovery:-no}" = yes ]; then
        jq -e --arg control "$provider_control_peer" '[.relay0,.relay1,.relay2] | index($control) != null' \
            "$WORK/a01-expected-peers.json" >/dev/null || fail PEER_RECOVERY_CONTROL_NOT_INDEPENDENT
        content_provider_adaptive_control_underlay "$provider_control_peer" || fail PEER_RECOVERY_CONTROL_UNDERLAY_FAILED
    else
        content_provider_control_underlay
    fi
    for jobs_node in "$provider_node_a" "$provider_node_b"; do
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" content recipient-key --identity "$WORK/state-$jobs_node/identity.key" \
            --passphrase-file "$WORK/credential-$jobs_node/identity-passphrase" \
            >"$WORK/agent-jobs-$jobs_node-public.json" || fail JOBS_PEER_KEY_FAILED
        agent_jobs_broker "$jobs_node" || fail JOBS_BROKER_UNAVAILABLE
    done
    jobs_key_a=$(jq -er '.identity_public_key_hex' "$WORK/agent-jobs-$provider_node_a-public.json")
    jobs_key_b=$(jq -er '.identity_public_key_hex' "$WORK/agent-jobs-$provider_node_b-public.json")
    if [ "${agent_jobs_peer_recovery:-no}" = yes ]; then
        # Product discovery orders a same-model cohort by the actual public key.
        # Preserve real node identities, never assume R4 sorts before R5.
        provider_nodes=$(jq -cn --arg a "$provider_node_a" --arg b "$provider_node_b" \
            --arg ka "$jobs_key_a" --arg kb "$jobs_key_b" \
            '[{node:$a,key:$ka},{node:$b,key:$kb}] | sort_by(.key) | map(.node)')
    fi
    jq -n --argjson nodes "$provider_nodes" --arg context "$custody_context" --arg control "$provider_control_peer" \
        --arg a "$provider_node_a" --arg b "$provider_node_b" --arg ka "$jobs_key_a" --arg kb "$jobs_key_b" \
        '{provider_nodes:$nodes,route_context_id:$context,control_relay_peer_id:$control,
          provider_keys:{($a):$ka,($b):$kb}}' >"$WORK/agent-jobs-layout.json"
}

agent_jobs_run() {
    agent_jobs_setup
    if [ "${agent_jobs_peer_recovery:-no}" = yes ]; then
        agent_jobs_peer_recovery_run
        return
    fi
    if [ "${agent_jobs_follow:-no}" = yes ]; then
        agent_jobs_follow_run
        return
    fi
    if [ "${agent_public_document:-no}" = yes ]; then
        agent_public_document_run
        return
    fi
    if [ "${agent_public_task:-no}" = yes ]; then
        agent_public_task_run
        return
    fi
    PHASE=agent-jobs-concurrent-execution
    # Existing fetch capture classification is used only for the same exact provider graph;
    # payloads here are signed compute RPCs, not a content download claim.
    content_custody_phase_start fetch
    agent_jobs_cli client compute peer distribute --dataset "$jobs_source/dataset.json" \
        --dataset-manifest "$jobs_source/manifest.pb" --publisher-key "$jobs_publisher" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --output "$jobs_source/batch" --max-seconds 600 --execute \
        >"$WORK/agent-jobs-result.json" 2>"$WORK/agent-jobs-result.err" &
    jobs_batch_pid=$!
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" observe "$WORK" \
        >"$WORK/agent-jobs-observer.log" 2>"$WORK/agent-jobs-observer.err" || fail JOBS_CONCURRENT_WORKERS_NOT_OBSERVED
    if [ "${agent_jobs_loss:-no}" = yes ]; then
        PHASE=agent-jobs-owned-worker-loss
        python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" inject-loss "$WORK" \
            >"$WORK/agent-jobs-loss-injection.log" 2>"$WORK/agent-jobs-loss-injection.err" || fail JOBS_OWNED_WORKER_LOSS_FAILED
        if wait "$jobs_batch_pid"; then fail JOBS_WORKER_LOSS_FALSE_SUCCESS; fi
    else
        wait "$jobs_batch_pid" || fail JOBS_DISTRIBUTION_INCOMPLETE
    fi
    jobs_batch_pid=
    for jobs_index in 0 1; do
        agent_jobs_cli client compute peer poll --handle "$jobs_source/batch/job-$jobs_index.json" \
            >"$WORK/agent-jobs-status-$jobs_index.json" 2>"$WORK/agent-jobs-status-$jobs_index.err" || fail JOBS_FINAL_REPORT_UNAVAILABLE
    done
    if [ "${agent_jobs_loss:-no}" = yes ]; then
        agent_jobs_resume_failed || fail JOBS_FAILED_ROWS_RESUME_INCOMPLETE
    fi
    content_custody_phase_finish 4
    benchmark_disconnect_route agent-jobs || fail JOBS_ROUTE_CLEANUP_FAILED
    agent_jobs_cleanup || fail JOBS_PRIVATE_CLEANUP_FAILED
    jobs_evidence_command=evidence
    [ "${agent_jobs_loss:-no}" != yes ] || jobs_evidence_command=loss-evidence
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" "$jobs_evidence_command" "$WORK" "$expected_commit" \
        || fail JOBS_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-jobs-complete
}

agent_jobs_resume_failed() {
    PHASE=agent-jobs-failed-rows-reassignment
    # Terminal original receipts precede explicit reassignment; missing/unconfirmed is not
    # accepted in this proof. The original successful result must already be retained.
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" arm-resume "$WORK" || return 1
    agent_jobs_cli client compute peer resume --dataset "$jobs_source/dataset.json" \
        --dataset-manifest "$jobs_source/manifest.pb" --publisher-key "$jobs_publisher" \
        --handle "$jobs_source/batch/job-0.json" --handle "$jobs_source/batch/job-1.json" \
        --replacement-provider-key "$jobs_key_b" --output "$jobs_source/resumed" \
        --max-seconds 600 --execute \
        >"$WORK/agent-jobs-resume-result.json" 2>"$WORK/agent-jobs-resume-result.err" &
    jobs_batch_pid=$!
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" observe-replacement "$WORK" \
        >"$WORK/agent-jobs-replacement-observer.log" 2>"$WORK/agent-jobs-replacement-observer.err" || return 1
    wait "$jobs_batch_pid" || return 1
    jobs_batch_pid=
    agent_jobs_cli client compute peer poll --handle "$jobs_source/resumed/job-0.json" \
        >"$WORK/agent-jobs-replacement-status.json" 2>"$WORK/agent-jobs-replacement-status.err" || return 1
    agent_jobs_cli client compute peer poll --handle "$jobs_source/batch/job-1.json" \
        >"$WORK/agent-jobs-retained-status.json" 2>"$WORK/agent-jobs-retained-status.err" || return 1
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" capture-resume "$WORK"
}

agent_jobs_finalize_report() {
    jobs_status=$1
    for jobs_log in "$WORK"/agent-jobs-*.json "$WORK"/agent-jobs-*.err "$WORK"/agent-jobs-*.log \
        "$WORK"/content-custody-fetch-*.json "$WORK"/content-provider-custody-fetch-*.json \
        "$WORK"/content-custody-executor-discovery-*.json \
        "$WORK"/content-provider-custody-executor-discovery-*.json \
        "$WORK"/content-provider-control-*.json; do
        [ ! -f "$jobs_log" ] || [ -L "$jobs_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$jobs_log" "$output_directory/$(basename -- "$jobs_log")"
    done
    if [ "${agent_jobs_peer_recovery:-no}" = yes ]; then
        agent_jobs_peer_recovery_finalize_report "$jobs_status"
        return
    fi
    if [ "${agent_jobs_follow:-no}" = yes ]; then
        agent_jobs_follow_finalize_report "$jobs_status"
        return
    fi
    if [ "${agent_public_document:-no}" = yes ]; then
        agent_public_document_finalize_report "$jobs_status"
        return
    fi
    if [ "${agent_public_task:-no}" = yes ]; then
        agent_public_task_finalize_report "$jobs_status"
        return
    fi
    jobs_finalize_command=finalize
    jobs_report=agent-jobs-smoke.json
    [ "${agent_jobs_loss:-no}" != yes ] || { jobs_finalize_command=loss-finalize; jobs_report=agent-jobs-loss-smoke.json; }
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" "$jobs_finalize_command" "$WORK" "$expected_commit" \
        "$jobs_status" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/$jobs_report" "$output_directory/$jobs_report"
    python3 -B "$source_directory/tests/integration/agent-jobs-smoke.py" report "$WORK/$jobs_report" "$expected_commit"
}
