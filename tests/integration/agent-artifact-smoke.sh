#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Distinct producer/consumer nodes; shared custody utilities only provide the protected route.
# shellcheck disable=SC2154,SC2034

agent_artifact_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-artifact-smoke.py" "$@"
}

agent_artifact_cli() {
    artifact_cli_node=$1
    shift
    if [ "$artifact_cli_node" = client ]; then
        artifact_cli_ns=$CLIENT
    else
        content_provider_node "$artifact_cli_node" || return 1
        artifact_cli_ns=$provider_ns
    fi
    timeout --signal=TERM --kill-after=5s 240s ip netns exec "$artifact_cli_ns" setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$artifact_cli_node/control/agent.sock" "$@"
}

agent_artifact_compute() {
    artifact_mode=$1; artifact_input=$2; artifact_output=$3
    shift 3
    if [ "$artifact_mode" = train ]; then
        content_provider_node "$provider_node_a" || return 1
        artifact_compute_ns=$provider_ns
    else
        artifact_compute_ns=$CLIENT
    fi
    exec ip netns exec "$artifact_compute_ns" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" compute run --mode "$artifact_mode" \
        --runtime-root "$artifact_user/provision/venv" --model-root "$artifact_user/provision/model" \
        --dataset "$artifact_input" --output "$artifact_output" --steps 8 --threads 2 \
        --max-seconds 600 --execute "$@"
}

agent_artifact_observe() {
    artifact_pid=$1; artifact_label=$2; artifact_dataset=$3
    # The background shell execs setpriv and then the CLI at this exact PID.
    # Wait for that real privilege drop before asking the read-only observer to bind it.
    artifact_owner_poll=0
    while [ "$artifact_owner_poll" -lt 100 ]; do
        kill -0 "$artifact_pid" 2>/dev/null || return 1
        [ "$(stat -Lc '%u' "/proc/$artifact_pid")" != "$WORKER_UID" ] || break
        sleep 0.01
        artifact_owner_poll=$((artifact_owner_poll + 1))
    done
    [ "$artifact_owner_poll" -lt 100 ] || return 1
    if [ "$artifact_label" = training ]; then
        artifact_compute_node=$provider_node_a
        content_provider_node "$provider_node_a" || return 1
        artifact_compute_ns=$provider_ns
    else
        artifact_compute_node=client
        artifact_compute_ns=$CLIENT
    fi
    artifact_service_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$artifact_compute_node.service")
    python3 -B "$source_directory/tests/integration/agent-artifact-smoke.py" observe \
        "$artifact_pid" "$artifact_user/$artifact_label-isolation.json" \
        "$artifact_user/provision" "$artifact_dataset" "$artifact_user/private-canary" "$artifact_label" \
        "$artifact_compute_node" "/run/netns/$artifact_compute_ns" "$artifact_service_pid" \
        >"$WORK/agent-artifact-$artifact_label-observer.log" 2>"$WORK/agent-artifact-$artifact_label-observer.err"
}

agent_artifact_prepare() {
    PHASE=agent-artifact-provision
    artifact_user=$WORK/client-fixtures/agent-artifact-user
    artifact_job_pid=
    custody_control_gid=$(getent group volparossa-users | cut -d: -f3)
    case $custody_control_gid in ''|*[!0-9]*) fail ARTIFACT_CONTROL_GROUP_INVALID ;; esac
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$artifact_user"
    agent_artifact_private prepare "$artifact_user" "$expected_commit" \
        >"$WORK/agent-artifact-provision.log" 2>"$WORK/agent-artifact-provision.err" || fail ARTIFACT_PROVISION_FAILED
    install -m 0600 "$artifact_user/provision/provision-report.json" "$WORK/agent-artifact-provision.json"
}

agent_artifact_restart() {
    artifact_node=$1
    artifact_unit=volparossa-alpha-agent@$artifact_node.service
    case " $AGENT_UNITS " in *" $artifact_unit "*) ;; *) return 1 ;; esac
    artifact_before_pid=$(systemctl show --property=MainPID --value "$artifact_unit") || return 1
    artifact_before_inode=$(stat -Lc '%d:%i' "$WORK/state-$artifact_node/custody-cache") || return 1
    systemctl restart "$artifact_unit" || return 1
    content_custody_status "$artifact_node" artifact-restored 2 || return 1
    artifact_after_pid=$(systemctl show --property=MainPID --value "$artifact_unit") || return 1
    artifact_after_inode=$(stat -Lc '%d:%i' "$WORK/state-$artifact_node/custody-cache") || return 1
    [ "$artifact_before_pid" -gt 0 ] && [ "$artifact_after_pid" -gt 0 ] \
        && [ "$artifact_before_pid" != "$artifact_after_pid" ] \
        && [ "$artifact_before_inode" = "$artifact_after_inode" ] || return 1
    jq -n --arg node "$artifact_node" --argjson before "$artifact_before_pid" --argjson after "$artifact_after_pid" \
        --arg inode "$artifact_after_inode" '{node:$node,pid_before:$before,pid_after:$after,
        cache_device_inode:$inode,same_cache:true,restored_publications:2}' >"$WORK/agent-artifact-$artifact_node-restart.json"
}

agent_artifact_run() {
    benchmark_select_route agent-artifact-probe mptcp || fail ARTIFACT_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/agent-artifact-probe-selection.json" || fail ARTIFACT_ROUTE_INVALID
    custody_context=$(jq -er '.route_context_id' "$WORK/agent-artifact-probe-selection.json")
    agent_artifact_cli client content status >"$WORK/agent-artifact-client-status.json" || fail ARTIFACT_CONTROL_UNAVAILABLE
    provider_control_peer=$(jq -er '.control_relay_peer_id' "$WORK/agent-artifact-client-status.json")
    provider_nodes=$(jq -cer --arg control "$provider_control_peer" '. as $p | ["relay4","relay5","relay3"]
        | map(select($p[.] != $control)) | .[:2] | select(length == 2)' "$WORK/a01-expected-peers.json") \
        || fail ARTIFACT_PROVIDERS_INVALID
    provider_node_a=$(printf '%s\n' "$provider_nodes" | jq -er '.[0]')
    provider_node_b=$(printf '%s\n' "$provider_nodes" | jq -er '.[1]')
    content_provider_control_underlay
    artifact_client_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $artifact_client_pid in ''|0|*[!0-9]*) fail ARTIFACT_CLIENT_PID_INVALID ;; esac
    nsenter --target "$artifact_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail ARTIFACT_CLIENT_ISOLATION_CONTROL_FAILED
    if nsenter --target "$artifact_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$artifact_user"; then fail ARTIFACT_TRAINER_STATE_EXPOSED; fi
    for artifact_node in "$provider_node_a" "$provider_node_b"; do
        content_custody_status "$artifact_node" artifact-empty 0 || fail ARTIFACT_EMPTY_PROVIDER_FAILED
        if nsenter --target "$artifact_client_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$artifact_node/custody-cache"; then fail ARTIFACT_LOCAL_PROVIDER_SHORTCUT; fi
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- "$binary_directory/volparossa" content recipient-key \
            --identity "$WORK/state-$artifact_node/identity.key" --passphrase-file "$WORK/credential-$artifact_node/identity-passphrase" \
            >"$WORK/agent-artifact-$artifact_node-public.json" || fail ARTIFACT_PROVIDER_KEY_FAILED
    done
    artifact_key_a=$(jq -er '.identity_public_key_hex' "$WORK/agent-artifact-$provider_node_a-public.json")
    artifact_key_b=$(jq -er '.identity_public_key_hex' "$WORK/agent-artifact-$provider_node_b-public.json")
    jq -n --argjson nodes "$provider_nodes" --arg context "$custody_context" --arg control "$provider_control_peer" \
        --arg a "$provider_node_a" --arg b "$provider_node_b" --arg ka "$artifact_key_a" --arg kb "$artifact_key_b" \
        '{provider_nodes:$nodes,producer_node:$a,consumer_node:"client",route_context_id:$context,control_relay_peer_id:$control,provider_keys:{($a):$ka,($b):$kb}}' \
        >"$WORK/agent-artifact-producer-layout.json"
    # No real application flow is opened by this control/selection probe. Do not
    # retain its short-lived grants while the producer trains its public artifact.
    benchmark_disconnect_route agent-artifact-probe || fail ARTIFACT_PROBE_CLEANUP_FAILED
    PHASE=agent-artifact-train
    agent_artifact_compute train "$artifact_user/dataset.json" "$artifact_user/train" \
        >"$WORK/agent-artifact-training.json" 2>"$WORK/agent-artifact-training.err" &
    artifact_job_pid=$!
    agent_artifact_observe "$artifact_job_pid" training "$artifact_user/dataset.json" || fail ARTIFACT_TRAIN_OBSERVER_FAILED
    wait "$artifact_job_pid" || fail ARTIFACT_TRAIN_FAILED
    artifact_job_pid=
    install -m 0600 "$artifact_user/training-isolation.json" "$WORK/agent-artifact-training-isolation.json"
    install -m 0600 "$artifact_user/dataset.json" "$WORK/agent-artifact-original-dataset.json"
    python3 -B "$source_directory/tests/integration/agent-artifact-smoke.py" training "$WORK" "$expected_commit" \
        || fail ARTIFACT_REAL_TRAINING_INVALID
    PHASE=agent-artifact-publish
    agent_artifact_cli "$provider_node_a" init --identity "$artifact_user/identity.key" --passphrase-file "$artifact_user/passphrase" \
        >"$WORK/agent-artifact-identity.log" 2>"$WORK/agent-artifact-identity.err" || fail ARTIFACT_PUBLISHER_IDENTITY_FAILED
    agent_artifact_cli "$provider_node_a" content publish --contribute --input "$artifact_user/dataset.json" \
        --name disposable-agent-dataset --revision 1 --content-type application/vnd.volparossa.agent-dataset.v1+json \
        --identity "$artifact_user/identity.key" --passphrase-file "$artifact_user/passphrase" \
        --cache "$artifact_user/dataset-cache" --manifest "$artifact_user/dataset.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-artifact-dataset-publish.json" 2>"$WORK/agent-artifact-dataset-publish.err" || fail ARTIFACT_DATASET_PUBLISH_FAILED
    artifact_publisher=$(jq -er '.publisher_key_hex' "$WORK/agent-artifact-dataset-publish.json")
    agent_artifact_cli "$provider_node_a" content agent pack --directory "$artifact_user/train/adapter" \
        --training-report "$artifact_user/train/report.json" --dataset-manifest "$artifact_user/dataset.pb" \
        --publisher-key "$artifact_publisher" --output "$artifact_user/bundle.bin" \
        >"$WORK/agent-artifact-pack.json" 2>"$WORK/agent-artifact-pack.err" || fail ARTIFACT_PACK_FAILED
    agent_artifact_cli "$provider_node_a" content publish --contribute --input "$artifact_user/bundle.bin" \
        --name disposable-agent-adapter --revision 1 --content-type application/vnd.volparossa.adapter.v1 \
        --identity "$artifact_user/identity.key" --passphrase-file "$artifact_user/passphrase" \
        --cache "$artifact_user/adapter-cache" --manifest "$artifact_user/adapter.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-artifact-adapter-publish.json" 2>"$WORK/agent-artifact-adapter-publish.err" || fail ARTIFACT_ADAPTER_PUBLISH_FAILED
    agent_artifact_private originals "$artifact_user" >"$WORK/agent-artifact-originals.json" || fail ARTIFACT_ORIGINAL_HASH_FAILED
    agent_artifact_private drop-source "$artifact_user" >"$WORK/agent-artifact-source-removed.json" || fail ARTIFACT_SOURCE_REMOVAL_FAILED
    agent_artifact_restart "$provider_node_a" || fail ARTIFACT_PROVIDER_RESTART_FAILED
    content_custody_status "$provider_node_b" artifact-still-empty 0 || fail ARTIFACT_UNUSED_PROVIDER_CHANGED
    benchmark_select_route agent-artifact mptcp || fail ARTIFACT_FRESH_ROUTE_UNAVAILABLE
    benchmark_bind_slots "$WORK/agent-artifact-selection.json" || fail ARTIFACT_FRESH_ROUTE_INVALID
    custody_context=$(jq -er '.route_context_id' "$WORK/agent-artifact-selection.json")
    agent_artifact_cli client content status >"$WORK/agent-artifact-client-fetch-status.json" || fail ARTIFACT_FRESH_CONTROL_UNAVAILABLE
    jq -e --arg peer "$provider_control_peer" '.control_relay_peer_id == $peer' \
        "$WORK/agent-artifact-client-fetch-status.json" >/dev/null || fail ARTIFACT_CONTROL_OWNER_CHANGED
    jq --arg context "$custody_context" '.route_context_id=$context' \
        "$WORK/agent-artifact-producer-layout.json" >"$WORK/agent-artifact-layout.json"
    PHASE=agent-artifact-fetch
    artifact_cache=$WORK/state-client/agent-artifact-cache
    [ ! -e "$artifact_cache" ] && [ ! -L "$artifact_cache" ] || fail ARTIFACT_CACHE_NOT_NEW
    content_custody_phase_start fetch
    agent_artifact_cli client content agent fetch --publisher-key "$artifact_publisher" \
        --name disposable-agent-adapter --dataset-name disposable-agent-dataset --min-revision 1 \
        --cache "$artifact_cache" --output "$artifact_user/received" \
        >"$WORK/agent-artifact-fetch.json" 2>"$WORK/agent-artifact-fetch.err" || fail ARTIFACT_PROTECTED_FETCH_FAILED
    content_custody_phase_finish 2
    benchmark_disconnect_route agent-artifact || fail ARTIFACT_ROUTE_CLEANUP_FAILED
    [ "$(stat -Lc '%a:%u:%g' "$artifact_cache")" = "700:$AGENT_UID:$AGENT_GID" ] || fail ARTIFACT_AGENT_CACHE_OWNERSHIP
    if setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$artifact_cache"; then fail ARTIFACT_AGENT_CACHE_EXPOSED; fi
    jq -n '{client_identity_positive_control:true,client_cannot_read_trainer:true,
        client_cannot_read_provider_stores:true,user_cannot_read_agent_cache:true,
        fresh_agent_cache:true}' >"$WORK/agent-artifact-content-isolation.json"
    agent_artifact_private received "$artifact_user" >"$WORK/agent-artifact-received.json" || fail ARTIFACT_RECEIVED_HASH_FAILED
    PHASE=agent-artifact-infer
    agent_artifact_compute infer "$artifact_user/received/dataset.json" "$artifact_user/infer" \
        --adapter-root "$artifact_user/received/adapter" \
        >"$WORK/agent-artifact-inference.json" 2>"$WORK/agent-artifact-inference.err" &
    artifact_job_pid=$!
    agent_artifact_observe "$artifact_job_pid" inference "$artifact_user/received/dataset.json" || fail ARTIFACT_INFER_OBSERVER_FAILED
    wait "$artifact_job_pid" || fail ARTIFACT_INFERENCE_FAILED
    artifact_job_pid=
    install -m 0600 "$artifact_user/inference-isolation.json" "$WORK/agent-artifact-inference-isolation.json"
    for artifact_node in "$provider_node_a" "$provider_node_b"; do
        agent_artifact_cli "$artifact_node" content stop >"$WORK/agent-artifact-$artifact_node-stop.json" || fail ARTIFACT_PROVIDER_STOP_FAILED
    done
    agent_artifact_cli client content agent fetch --publisher-key "$artifact_publisher" \
        --name disposable-agent-adapter --dataset-name disposable-agent-dataset --min-revision 1 \
        --cache "$artifact_cache" --reuse-cache --cache-only --output "$artifact_user/reopened" \
        >"$WORK/agent-artifact-cache-only.json" 2>"$WORK/agent-artifact-cache-only.err" || fail ARTIFACT_CACHE_REOPEN_FAILED
    agent_artifact_private received "$artifact_user" reopened >"$WORK/agent-artifact-reopened.json" || fail ARTIFACT_REOPEN_HASH_FAILED
    agent_artifact_cleanup || fail ARTIFACT_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/agent-artifact-smoke.py" evidence "$WORK" "$expected_commit" \
        || fail ARTIFACT_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-artifact-complete
}

agent_artifact_cleanup() {
    if [ -n "${artifact_job_pid:-}" ] && kill -0 "$artifact_job_pid" 2>/dev/null; then
        kill -INT "$artifact_job_pid" || return 1
        wait "$artifact_job_pid" || true
        artifact_job_pid=
    fi
    [ -n "${artifact_user:-}" ] && [ -f "$WORK/bin/agent-artifact-smoke.py" ] || return 0
    if [ ! -f "$WORK/agent-artifact-private-cleanup.json" ]; then
        agent_artifact_private cleanup "$artifact_user" >"$WORK/agent-artifact-private-cleanup.json" || return 1
    fi
}

agent_artifact_finalize_report() {
    artifact_status=$1
    for artifact_log in "$WORK"/agent-artifact-*.json "$WORK"/agent-artifact-*.err "$WORK"/agent-artifact-*.log \
        "$WORK"/content-custody-*.json "$WORK"/content-provider-custody-*.json "$WORK"/content-provider-control-*.json; do
        [ ! -f "$artifact_log" ] || [ -L "$artifact_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$artifact_log" "$output_directory/$(basename -- "$artifact_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-artifact-smoke.py" finalize "$WORK" "$expected_commit" \
        "$artifact_status" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-artifact-smoke.json" "$output_directory/agent-artifact-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-artifact-smoke.py" report "$WORK/agent-artifact-smoke.json" "$expected_commit"
}
