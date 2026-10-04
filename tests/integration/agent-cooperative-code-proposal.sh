#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additive public single-file trial; the old cooperative Code trial is unchanged.
# shellcheck disable=SC2154,SC2034

agent_cooperative_code_proposal_run() {
    proposal_script=$source_directory/tests/integration/agent-cooperative-code-proposal.py
    code_root=$jobs_root/code
    code_state=$jobs_source/public-code
    code_socket=$jobs_source/public.sock
    PHASE=agent-cooperative-code-proposal-provision
    python3 -B "$proposal_script" capacity "$WORK" || fail CODE_PROPOSAL_CAPACITY_OBSERVATION_FAILED
    python3 -B "$proposal_script" provision "$WORK" "$COOPERATIVE_CODE_BUNDLE" "$COOPERATIVE_CODE_MANIFEST_SHA256" \
        || fail CODE_PROPOSAL_INPUTS_FAILED
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$code_state"
    code_unit=volparossa-alpha-public-code.service
    [ "$(unit_load_state "$code_unit")" = not-found ] || fail CODE_PROPOSAL_SERVICE_COLLISION
    jobs_units="$jobs_units $code_unit"
    code_hidden="$WORK/agent-jobs-user"
    for code_node in relay3 relay4 relay5; do code_hidden="$code_hidden $WORK/state-$code_node"; done
    code_control_root=$jobs_source/control-observer
    code_control_socket=$code_control_root/control.sock
    code_control_unit=volparossa-alpha-code-control-observer.service
    [ "$(unit_load_state "$code_control_unit")" = not-found ] || fail CODE_PROPOSAL_OBSERVER_COLLISION
    jobs_units="$jobs_units $code_control_unit"
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$code_control_root"
    install -o root -g root -m 0555 "$source_directory/tests/integration/agent-code-control-observer.py" \
        "$WORK/bin/agent-code-control-observer.py"
    # Fixture-only, same-UID byte-preserving IPC tap. It never selects a provider,
    # generates a response, executes a model or changes core/application deadlines.
    systemd-run --no-block --unit="$code_control_unit" --slice=system.slice --service-type=exec \
        --property=CollectMode=inactive --property=Restart=no --property=UMask=0077 \
        --property=User=volparossa --property=Group=volparossa --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
        --property=PrivateNetwork=yes --property=RestrictAddressFamilies=AF_UNIX \
        --property=PrivateTmp=yes --property=PrivateDevices=yes --property=ProtectHome=yes \
        --property=ProtectSystem=strict --property="ReadWritePaths=$code_control_root" \
        --property="InaccessiblePaths=$code_hidden" --property=KillMode=control-group \
        --property=TimeoutStopSec=5s --property=RuntimeMaxSec=2700s \
        -- /usr/bin/python3 -I -B "$WORK/bin/agent-code-control-observer.py" \
        --socket "$code_control_socket" --upstream "$WORK/runtime-client/control/agent.sock" \
        --directory "$code_control_root" --publisher "$jobs_publisher" || fail CODE_PROPOSAL_OBSERVER_FAILED
    code_attempt=0
    while [ ! -S "$code_control_socket" ]; do
        code_attempt=$((code_attempt + 1))
        [ "$code_attempt" -le 100 ] || fail CODE_PROPOSAL_OBSERVER_UNAVAILABLE
        sleep 0.1
    done
    PHASE=agent-cooperative-code-proposal-service
    # This owner service has neither a model nor a runtime: selection, signing,
    # dispatch and exact receipt reconciliation go through the real core.
    systemd-run --no-block --unit="$code_unit" --slice=system.slice --service-type=exec \
        --property=CollectMode=inactive --property=Restart=no --property=UMask=0077 \
        --property=User=volparossa --property=Group=volparossa --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
        --property="NetworkNamespacePath=/run/netns/$CLIENT" \
        --property=PrivateMounts=yes --property=PrivateTmp=yes --property=PrivateDevices=yes \
        --property=ProtectSystem=strict --property=ProtectHome=yes \
        --property="ReadWritePaths=$jobs_source" --property="InaccessiblePaths=$code_hidden" \
        --property=KillMode=control-group --property=TimeoutStopSec=20s --property=RuntimeMaxSec=2700s \
        --property="StandardOutput=append:$WORK/agent-cooperative-code-proposal-service.log" \
        --property="StandardError=append:$WORK/agent-cooperative-code-proposal-service.err" \
        -- "$binary_directory/volparossa" --control-socket "$code_control_socket" \
        compute public-serve --socket "$code_socket" --state-parent "$code_state" \
        --code-proposal-v6 --model-profile qwen3-0.6b-v1 --discover-peers \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --publisher-key "$jobs_publisher" --max-seconds 600 --max-task-seconds 2400 --threads 2 --execute \
        || fail CODE_PROPOSAL_SERVICE_FAILED
    code_attempt=0
    while [ ! -S "$code_socket" ]; do
        code_attempt=$((code_attempt + 1))
        [ "$code_attempt" -le 100 ] || fail CODE_PROPOSAL_SOCKET_UNAVAILABLE
        sleep 0.1
    done
    [ "$(stat -Lc '%a:%u' "$code_socket")" = "600:$AGENT_UID" ] || fail CODE_PROPOSAL_SOCKET_AUTHORITY
    python3 -B "$source_directory/tests/integration/agent-cooperative-code.py" account-home-prepare "$WORK" \
        || fail CODE_PROPOSAL_HOME_FAILED
    code_driver_unit=volparossa-alpha-cooperative-code.service
    [ "$(unit_load_state "$code_driver_unit")" = not-found ] || fail CODE_PROPOSAL_DRIVER_COLLISION
    jobs_units="$jobs_units $code_driver_unit"
    PHASE=agent-cooperative-code-proposal-executor-discovery
    content_custody_phase_start executor-discovery
    timeout --signal=INT --kill-after=15s 2520s systemd-run --quiet --wait --collect \
        --unit="$code_driver_unit" --service-type=exec --property=User=volparossa --property=Group=volparossa \
        --property=SetLoginEnvironment=yes --property=NoNewPrivileges=yes --property=UMask=0077 \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= --property=KillMode=control-group \
        --property=TimeoutStopSec=20s --property=RuntimeMaxSec=2520s \
        -- "$code_root/runtime/node" "$code_root/code/scripts/smoke_public_code_proposal.cjs" \
        --execute --yes --public-socket "$code_socket" --project-parent "$code_root/projects" --output "$code_root/report.json" \
        >"$WORK/agent-cooperative-code-proposal-driver.log" 2>"$WORK/agent-cooperative-code-proposal-driver.err" &
    jobs_batch_pid=$!
    python3 -B "$proposal_script" await-discovery "$WORK" "$jobs_batch_pid" \
        || fail CODE_PROPOSAL_DISCOVERY_BOUNDARY_FAILED
    content_custody_phase_finish 1
    PHASE=agent-cooperative-code-proposal-native-task
    content_custody_phase_start fetch
    python3 -B "$proposal_script" release-discovery "$WORK" || fail CODE_PROPOSAL_DISCOVERY_RELEASE_FAILED
    code_observer_status=0
    python3 -B "$proposal_script" observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-cooperative-code-proposal-observer.log" 2>"$WORK/agent-cooperative-code-proposal-observer.err" \
        || code_observer_status=$?
    if [ "$code_observer_status" -ne 0 ]; then
        systemctl kill --signal=INT --kill-whom=all "$code_driver_unit" 2>/dev/null || true
    fi
    code_driver_status=0
    wait "$jobs_batch_pid" || code_driver_status=$?
    jobs_batch_pid=
    python3 -B "$proposal_script" capture "$WORK" "$code_driver_status" "$code_observer_status" \
        || fail CODE_PROPOSAL_CAPTURE_FAILED
    [ "$code_observer_status" -eq 0 ] || fail CODE_PROPOSAL_PEER_PROOF_FAILED
    [ "$code_driver_status" -eq 0 ] || fail CODE_PROPOSAL_OWNER_TEST_FAILED
    content_custody_phase_finish 1
    agent_jobs_stop_unit "$code_control_unit" || fail CODE_PROPOSAL_OBSERVER_STOP_FAILED
    python3 -B "$proposal_script" control-observed "$WORK" || fail CODE_PROPOSAL_CONTROL_OBSERVATION_FAILED
    benchmark_disconnect_route agent-jobs || fail CODE_PROPOSAL_ROUTE_CLEANUP_FAILED
    agent_jobs_stop || fail CODE_PROPOSAL_SERVICE_CLEANUP_FAILED
    agent_cooperative_code_account_home_cleanup || fail CODE_PROPOSAL_HOME_CLEANUP_FAILED
    agent_jobs_cleanup || fail CODE_PROPOSAL_PRIVATE_CLEANUP_FAILED
    python3 -B "$proposal_script" evidence "$WORK" "$expected_commit" || fail CODE_PROPOSAL_EVIDENCE_FAILED
    OBSERVED_BLOCKER=NONE
    PHASE=agent-cooperative-code-proposal-complete
}

agent_cooperative_code_proposal_finalize_report() {
    proposal_script=$source_directory/tests/integration/agent-cooperative-code-proposal.py
    python3 -B "$proposal_script" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    proposal_exports=$(python3 -B "$proposal_script" export-names) || return 1
    for proposal_name in $proposal_exports; do
        proposal_path=$WORK/$proposal_name
        if [ -f "$proposal_path" ] && [ ! -L "$proposal_path" ]; then
            [ "$(wc -c <"$proposal_path")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$proposal_path" "$output_directory/$proposal_name"
        fi
    done
    python3 -B "$proposal_script" report "$WORK/agent-cooperative-code-proposal-smoke.json" "$expected_commit"
}
