#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the explicit disposable Code topology scenario. No dispatch here.
# shellcheck disable=SC2154,SC2034

agent_cooperative_code_run() {
    PHASE=agent-cooperative-code-provision
    code_script=$source_directory/tests/integration/agent-cooperative-code.py
    code_root=$jobs_root/code
    code_state=$jobs_source/public-code
    code_socket=$jobs_source/public.sock
    if [ -z "${COOPERATIVE_CODE_BUNDLE:-}" ] || [ -z "${COOPERATIVE_CODE_MANIFEST_SHA256:-}" ]; then
        fail COOPERATIVE_CODE_EXPLICIT_BUNDLE_REQUIRED
    fi
    python3 -B "$code_script" provision "$WORK" "$COOPERATIVE_CODE_BUNDLE" "$COOPERATIVE_CODE_MANIFEST_SHA256" \
        || fail COOPERATIVE_CODE_PROVISION_FAILED
    # Same concrete owner runtime and public-serve lifecycle as the browser proof.
    # Only this small service declaration is repeated; workers, receipts, routes,
    # packet proof and teardown are the existing JOBS/CUSTODY implementation.
    for code_part in venv model; do
        code_name=document-model
        [ "$code_part" != venv ] || code_name=document-runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$code_part" "$jobs_source/$code_name" \
            || fail COOPERATIVE_CODE_OWNER_MODEL_FAILED
    done
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$code_state"
    code_unit=volparossa-alpha-public-code.service
    [ "$(unit_load_state "$code_unit")" = not-found ] || fail COOPERATIVE_CODE_SERVICE_COLLISION
    jobs_units="$jobs_units $code_unit"
    code_hidden="$WORK/agent-jobs-user"
    for code_node in relay3 relay4 relay5; do code_hidden="$code_hidden $WORK/state-$code_node"; done
    PHASE=agent-cooperative-code-service
    systemd-run --no-block --unit="$code_unit" --slice=system.slice --service-type=exec \
        --property=CollectMode=inactive --property=Restart=no --property=UMask=0077 \
        --property=User=volparossa --property=Group=volparossa --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
        --property="NetworkNamespacePath=/run/netns/$CLIENT" \
        --property=PrivateMounts=yes --property=PrivateTmp=yes --property=PrivateDevices=yes \
        --property=ProtectSystem=strict --property=ProtectHome=yes \
        --property="ReadWritePaths=$jobs_source" --property="InaccessiblePaths=$code_hidden" \
        --property=KillMode=control-group --property=TimeoutStopSec=20s --property=RuntimeMaxSec=2700s \
        --property="StandardOutput=append:$WORK/agent-cooperative-code-service.log" \
        --property="StandardError=append:$WORK/agent-cooperative-code-service.err" \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        compute public-serve --socket "$code_socket" --state-parent "$code_state" \
        --runtime-root "$jobs_source/document-runtime" --model-root "$jobs_source/document-model" \
        --model-profile smollm2-135m-v1 --identity "$jobs_source/identity.key" \
        --passphrase-file "$jobs_source/passphrase" --publisher-key "$jobs_publisher" \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" \
        --max-seconds 600 --max-task-seconds 2400 --threads 2 --execute \
        || fail COOPERATIVE_CODE_SERVICE_FAILED
    code_attempt=0
    while [ ! -S "$code_socket" ]; do
        code_attempt=$((code_attempt + 1))
        [ "$code_attempt" -le 100 ] || fail COOPERATIVE_CODE_SOCKET_UNAVAILABLE
        sleep 0.1
    done
    [ "$(stat -Lc '%a:%u' "$code_socket")" = "600:$AGENT_UID" ] || fail COOPERATIVE_CODE_SOCKET_AUTHORITY
    python3 -B "$code_script" account-home-prepare "$WORK" || fail COOPERATIVE_CODE_HOME_FAILED
    code_driver_unit=volparossa-alpha-cooperative-code.service
    [ "$(unit_load_state "$code_driver_unit")" = not-found ] || fail COOPERATIVE_CODE_DRIVER_COLLISION
    jobs_units="$jobs_units $code_driver_unit"
    code_snapshot_hash=$(jq -er '.snapshot_sha256' "$WORK/agent-cooperative-code-input.json") || fail COOPERATIVE_CODE_INPUT_FAILED
    PHASE=agent-cooperative-code-native-task
    content_custody_phase_start fetch
    timeout --signal=INT --kill-after=15s 2520s systemd-run --quiet --wait --collect \
        --unit="$code_driver_unit" --service-type=exec --property=User=volparossa --property=Group=volparossa \
        --property=SetLoginEnvironment=yes --property=NoNewPrivileges=yes --property=UMask=0077 \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= --property=KillMode=control-group \
        --property=TimeoutStopSec=20s --property=RuntimeMaxSec=2520s \
        -- "$code_root/runtime/node" "$code_root/code/scripts/smoke_opencode_cooperation.cjs" \
        --execute --yes --node "$code_root/runtime/node" --build-report "$code_root/runtime/build-report.json" \
        --public-socket "$code_socket" --snapshot "$code_root/input.json" --snapshot-sha256 "$code_snapshot_hash" \
        --project-parent "$code_root/projects" --output "$code_root/report.json" --timeout-seconds 2400 \
        >"$WORK/agent-cooperative-code-driver.log" 2>"$WORK/agent-cooperative-code-driver.err" &
    jobs_batch_pid=$!
    code_observer_status=0
    python3 -B "$code_script" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-cooperative-code-observer.log" 2>"$WORK/agent-cooperative-code-observer.err" \
        || code_observer_status=$?
    if [ "$code_observer_status" -ne 0 ]; then
        systemctl kill --signal=INT --kill-whom=all "$code_driver_unit" 2>/dev/null || true
    fi
    code_driver_status=0
    wait "$jobs_batch_pid" || code_driver_status=$?
    jobs_batch_pid=
    python3 -B "$code_script" capture "$WORK" "$code_driver_status" "$code_observer_status" \
        || fail COOPERATIVE_CODE_CAPTURE_FAILED
    [ "$code_observer_status" -eq 0 ] || fail COOPERATIVE_CODE_PEER_PROOF_FAILED
    [ "$code_driver_status" -eq 0 ] || fail COOPERATIVE_CODE_NATIVE_TASK_FAILED
    content_custody_phase_finish 6
    benchmark_disconnect_route agent-jobs || fail COOPERATIVE_CODE_ROUTE_CLEANUP_FAILED
    agent_jobs_stop || fail COOPERATIVE_CODE_SERVICE_CLEANUP_FAILED
    agent_cooperative_code_account_home_cleanup || fail COOPERATIVE_CODE_HOME_CLEANUP_FAILED
    agent_jobs_cleanup || fail COOPERATIVE_CODE_PRIVATE_CLEANUP_FAILED
    python3 -B "$code_script" evidence "$WORK" "$expected_commit" || fail COOPERATIVE_CODE_EVIDENCE_FAILED
    OBSERVED_BLOCKER=NONE
    PHASE=agent-cooperative-code-complete
}

# The scenario registration also calls this from its failure cleanup,
# after stopping owned units and before declaring the guest unchanged.
agent_cooperative_code_account_home_cleanup() {
    python3 -B "$source_directory/tests/integration/agent-cooperative-code.py" account-home-cleanup "$WORK"
}

agent_cooperative_code_finalize_report() {
    python3 -B "$source_directory/tests/integration/agent-cooperative-code.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    code_exports=$(python3 -B "$source_directory/tests/integration/agent-cooperative-code.py" export-names) || return 1
    for code_name in $code_exports; do
        code_path=$WORK/$code_name
        if [ -f "$code_path" ] && [ ! -L "$code_path" ]; then
            [ "$(wc -c <"$code_path")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$code_path" "$output_directory/$code_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/agent-cooperative-code.py" report \
        "$WORK/agent-cooperative-code-smoke.json" "$expected_commit"
}
