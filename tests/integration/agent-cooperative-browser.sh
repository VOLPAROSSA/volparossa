#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# The same real peer graph as agent-public-document, driven by a genuine Gecko panel.
# shellcheck disable=SC2154,SC2034

agent_cooperative_browser_python() {
    if [ "${agent_cooperative_browser_discovered:-no}" = yes ]; then
        set -- --trial discovered-360m "$@"
    fi
    python3 -B "$source_directory/tests/integration/agent-cooperative-browser.py" "$@"
}

agent_cooperative_browser_run() {
    PHASE=agent-cooperative-browser-provision
    cooperative_root=$jobs_root/browser
    cooperative_state=$jobs_source/public-browser
    cooperative_socket=$jobs_source/public.sock
    cooperative_script=$source_directory/tests/integration/agent-cooperative-browser.py
    for cooperative_file in agent-cooperative-browser.py agent-cooperative-browser-pins.json \
        agent-private-task-browser-pins.json agent-public-document-smoke.py agent-document-synthesis.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$cooperative_file" "$WORK/bin/$cooperative_file"
    done
    set --
    if [ "${agent_cooperative_browser_discovered:-no}" = yes ]; then
        set -- --trial discovered-360m
    fi
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-cooperative-browser.py" "$@" provision "$WORK" \
        >"$WORK/agent-cooperative-browser-input.json" || fail COOPERATIVE_BROWSER_PROVISION_FAILED
    install -m 0600 "$cooperative_root/provision.json" "$WORK/agent-cooperative-browser-provision.json"
    for cooperative_part in venv model; do
        cooperative_name=document-model
        [ "$cooperative_part" != venv ] || cooperative_name=document-runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$cooperative_part" "$jobs_source/$cooperative_name" \
            || fail COOPERATIVE_BROWSER_OWNER_MODEL_FAILED
    done
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$cooperative_state"
    cooperative_unit=volparossa-alpha-public-browser.service
    [ "$(unit_load_state "$cooperative_unit")" = not-found ] || fail COOPERATIVE_BROWSER_SERVICE_COLLISION
    jobs_units="$jobs_units $cooperative_unit"
    cooperative_hidden="$WORK/agent-jobs-user"
    for cooperative_node in relay3 relay4 relay5; do
        cooperative_hidden="$cooperative_hidden $WORK/state-$cooperative_node"
    done
    set -- --model-profile smollm2-135m-v1 --provider-key "$jobs_key_a" --provider-key "$jobs_key_b"
    if [ "${agent_cooperative_browser_discovered:-no}" = yes ]; then
        set -- --model-profile smollm2-360m-v1 --discover-peers --refine-incomplete --refinement-levels 4
    fi
    PHASE=agent-cooperative-browser-service
    systemd-run --no-block --unit="$cooperative_unit" --slice=system.slice --service-type=exec \
        --property=CollectMode=inactive --property=Restart=no --property=UMask=0077 \
        --property=User=volparossa --property=Group=volparossa --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
        --property="NetworkNamespacePath=/run/netns/$CLIENT" \
        --property=PrivateMounts=yes --property=PrivateTmp=yes --property=PrivateDevices=yes \
        --property=ProtectSystem=strict --property=ProtectHome=yes \
        --property="ReadWritePaths=$jobs_source" --property="InaccessiblePaths=$cooperative_hidden" \
        --property=KillMode=control-group --property=TimeoutStopSec=20s --property=RuntimeMaxSec=2700s \
        --property="StandardOutput=append:$WORK/agent-cooperative-browser-service.log" \
        --property="StandardError=append:$WORK/agent-cooperative-browser-service.err" \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        compute public-serve --socket "$cooperative_socket" --state-parent "$cooperative_state" \
        --runtime-root "$jobs_source/document-runtime" --model-root "$jobs_source/document-model" \
        "$@" --identity "$jobs_source/identity.key" \
        --passphrase-file "$jobs_source/passphrase" --publisher-key "$jobs_publisher" \
        --max-seconds 600 --max-task-seconds 2400 --threads 2 --execute \
        || fail COOPERATIVE_BROWSER_SERVICE_FAILED
    cooperative_attempt=0
    while [ ! -S "$cooperative_socket" ]; do
        cooperative_attempt=$((cooperative_attempt + 1))
        [ "$cooperative_attempt" -le 100 ] || fail COOPERATIVE_BROWSER_SOCKET_UNAVAILABLE
        sleep 0.1
    done
    [ "$(stat -Lc '%a:%u' "$cooperative_socket")" = "600:$AGENT_UID" ] || fail COOPERATIVE_BROWSER_SOCKET_AUTHORITY
    PHASE=agent-cooperative-browser-panel
    content_custody_phase_start fetch
    # sysusers records the account home but does not create it in this non-package
    # guest. Create only the exact missing home; cleanup removes it only if still empty.
    agent_cooperative_browser_python account-home-prepare "$WORK" || fail COOPERATIVE_BROWSER_HOME_FAILED
    # The normal service-user transition chooses the account home without a HOME override.
    cooperative_driver_unit=volparossa-alpha-cooperative-browser.service
    [ "$(unit_load_state "$cooperative_driver_unit")" = not-found ] || fail COOPERATIVE_BROWSER_DRIVER_COLLISION
    jobs_units="$jobs_units $cooperative_driver_unit"
    timeout --signal=INT --kill-after=15s 2520s systemd-run --quiet --wait --collect \
        --unit="$cooperative_driver_unit" --service-type=exec --property=User=volparossa --property=Group=volparossa \
        --property=SetLoginEnvironment=yes --property=NoNewPrivileges=yes --property=UMask=0077 \
        --property=CapabilityBoundingSet= --property=AmbientCapabilities= --property=KillMode=control-group \
        --property=TimeoutStopSec=20s --property=RuntimeMaxSec=2520s \
        -- python3 -B "$cooperative_root/scripts/smoke_cooperative_compute.py" \
        --stage "$cooperative_root/build/firefox-esr" --output "$cooperative_root/build/cooperative-proof" \
        --socket "$cooperative_socket" --input "$cooperative_root/input.json" --core-revision "$expected_commit" \
        >"$WORK/agent-cooperative-browser-driver.log" 2>"$WORK/agent-cooperative-browser-driver.err" &
    jobs_batch_pid=$!
    cooperative_observer_status=0
    agent_cooperative_browser_python observe "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-cooperative-browser-observer.log" 2>"$WORK/agent-cooperative-browser-observer.err" \
        || cooperative_observer_status=$?
    if [ "$cooperative_observer_status" -ne 0 ]; then
        systemctl kill --signal=INT --kill-whom=all "$cooperative_driver_unit" 2>/dev/null || true
    fi
    cooperative_browser_status=0
    wait "$jobs_batch_pid" || cooperative_browser_status=$?
    jobs_batch_pid=
    # Observe existing fixed stage codes before services/private state are retired.
    # Only closed counts leave the guest; this complete bounded ring is not an export.
    cooperative_rpc_query_status=0
    "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        logs --limit 1000 >"$WORK/agent-cooperative-browser-rpc-events.private" \
        || cooperative_rpc_query_status=$?
    agent_cooperative_browser_python diagnostic "$WORK" "$cooperative_browser_status" "$cooperative_observer_status" \
        "$provider_baseline_ms" "$cooperative_rpc_query_status" \
        || fail COOPERATIVE_BROWSER_DIAGNOSTIC_FAILED
    [ "$cooperative_observer_status" -eq 0 ] || fail COOPERATIVE_BROWSER_PEER_PROOF_FAILED
    [ "$cooperative_browser_status" -eq 0 ] || fail COOPERATIVE_BROWSER_PANEL_FAILED
    install -m 0600 "$cooperative_root/build/cooperative-proof/report.json" "$WORK/agent-cooperative-browser-panel.json"
    agent_cooperative_browser_python collect "$WORK" "$expected_commit" || fail COOPERATIVE_BROWSER_RESULT_JOIN_FAILED
    content_custody_phase_finish 6
    benchmark_disconnect_route agent-jobs || fail COOPERATIVE_BROWSER_ROUTE_CLEANUP_FAILED
    agent_jobs_stop || fail COOPERATIVE_BROWSER_SERVICE_CLEANUP_FAILED
    agent_jobs_cleanup || fail COOPERATIVE_BROWSER_PRIVATE_CLEANUP_FAILED
    agent_cooperative_browser_python evidence "$WORK" "$expected_commit" || fail COOPERATIVE_BROWSER_EVIDENCE_FAILED
    OBSERVED_BLOCKER=NONE
    PHASE=agent-cooperative-browser-complete
}

agent_cooperative_browser_finalize_report() {
    agent_cooperative_browser_python finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    cooperative_exports=$(agent_cooperative_browser_python export-names) || return 1
    for cooperative_name in $cooperative_exports; do
        cooperative_path=$WORK/$cooperative_name
        if [ -f "$cooperative_path" ] && [ ! -L "$cooperative_path" ]; then
            [ "$(wc -c <"$cooperative_path")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$cooperative_path" "$output_directory/$cooperative_name"
        fi
    done
    agent_cooperative_browser_python report \
        "$WORK/agent-cooperative-browser-smoke.json" "$expected_commit"
}
