#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Additional real peer adoption gate; the earlier catalog/cycle proof stays unchanged.
# shellcheck disable=SC2154,SC2034

agent_peer_learning_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-peer-learning-smoke.py" "$@"
}

agent_peer_learning_share_validation() {
    PHASE=agent-peer-learning-validation-contribution
    agent_artifact_cli relay4 content export --public-content \
        --manifest "$artifact_user/loop/validation-input/dataset.manifest" --publisher-key "$artifact_publisher" \
        --agent-cache "$loop_cache" --cache "$artifact_user/peer-validation-export" \
        >"$WORK/agent-peer-learning-validation-export.json" || return 1
    agent_artifact_cli relay4 content contribute \
        --manifest "$artifact_user/loop/validation-input/dataset.manifest" --publisher-key "$artifact_publisher" \
        --cache "$artifact_user/peer-validation-export" >"$WORK/agent-peer-learning-validation-contribute.json"
}

agent_peer_learning_execute() {
    exec nsenter --net="/run/netns/$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --groups="$custody_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" \
        compute train-loop --plan "$artifact_user/peer-plan.json" --peer-updates "$artifact_user/peer-channels.json" \
        --validation-source "$artifact_user/peer-validation-source.json" --directory "$artifact_user/peer-learning" \
        --runtime-root "$artifact_user/provision/venv" --model-root "$artifact_user/provision/model" \
        --cache "$peer_learning_cache" --max-cycles 1 --steps 8 --threads 2 --max-seconds 600 --poll-seconds 1 \
        --publish-name disposable-client-peer-successor --publication-key "$peer_learning_publisher" \
        --identity "$artifact_user/peer-identity.key" --passphrase-file "$artifact_user/peer-passphrase" \
        --publish-cache "$artifact_user/peer-publish-cache" --execute
}

agent_peer_learning_run() {
    PHASE=agent-peer-learning-prepare
    [ "$loop_latest" != none ] || fail PEER_LEARNING_NO_APPROVED_PROVIDER_UPDATE
    agent_peer_learning_private setup "$artifact_user" "$loop_publisher" \
        >"$WORK/agent-peer-learning-selected.json" || fail PEER_LEARNING_SELECTION_FAILED
    agent_artifact_cli client init --identity "$artifact_user/peer-identity.key" \
        --passphrase-file "$artifact_user/peer-passphrase" >"$WORK/agent-peer-learning-identity.log" \
        || fail PEER_LEARNING_IDENTITY_FAILED
    agent_artifact_cli client content recipient-key --identity "$artifact_user/peer-identity.key" \
        --passphrase-file "$artifact_user/peer-passphrase" >"$WORK/agent-peer-learning-owner-key.json" \
        || fail PEER_LEARNING_OWNER_KEY_FAILED
    peer_learning_publisher=$(jq -er '.identity_public_key_hex' "$WORK/agent-peer-learning-owner-key.json")
    [ "$peer_learning_publisher" != "$loop_publisher" ] || fail PEER_LEARNING_OWNER_NOT_DISTINCT
    agent_artifact_cli client content publish --input "$artifact_user/peer-plan.json" --name disposable-peer-enrollment \
        --revision 1 --content-type application/json --identity "$artifact_user/peer-identity.key" \
        --passphrase-file "$artifact_user/peer-passphrase" --cache "$artifact_user/peer-publish-cache" \
        --manifest "$artifact_user/peer-enrollment.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-peer-learning-owner-cache.json" || fail PEER_LEARNING_OWNER_CACHE_FAILED
    peer_learning_cache=$WORK/state-client/agent-peer-learning-cache
    [ ! -e "$peer_learning_cache" ] && [ ! -L "$peer_learning_cache" ] || fail PEER_LEARNING_CACHE_NOT_NEW
    content_replication_select client agent-peer-learning-transfer || fail PEER_LEARNING_ROUTE_FAILED
    content_replication_capture reserve-fetch agent-peer-learning-transfer "$WORK/agent-peer-learning-transfer-selection.json" \
        || fail PEER_LEARNING_CAPTURE_FAILED
    # Initialize a real native cache through protected retrieval, never an empty directory.
    agent_artifact_cli client content fetch-name --publisher-key "$artifact_publisher" \
        --name disposable-agent-validation --min-revision 1 --cache "$peer_learning_cache" \
        --local-output "$artifact_user/peer-initial-validation.json" \
        >"$WORK/agent-peer-learning-initial-fetch.json" || fail PEER_LEARNING_INITIAL_FETCH_FAILED
    PHASE=agent-peer-learning-adopt-and-train
    agent_peer_learning_execute >"$WORK/agent-peer-learning-stdout.jsonl" 2>"$WORK/agent-peer-learning-worker.err" &
    artifact_job_pid=$!
    peer_learning_poll=0
    while [ "$peer_learning_poll" -lt 100 ]; do
        kill -0 "$artifact_job_pid" 2>/dev/null || fail PEER_LEARNING_EARLY_EXIT
        [ "$(stat -Lc '%u' "/proc/$artifact_job_pid")" != "$WORKER_UID" ] || break
        sleep 0.01; peer_learning_poll=$((peer_learning_poll + 1))
    done
    peer_learning_service=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" observe "$artifact_job_pid" \
        "$artifact_user" "/run/netns/$CLIENT" "$peer_learning_service" \
        >"$WORK/agent-peer-learning-observer.log" 2>"$WORK/agent-peer-learning-observer.err" \
        || fail PEER_LEARNING_ACTUAL_WORKERS_MISSING
    wait "$artifact_job_pid" || fail PEER_LEARNING_COORDINATOR_FAILED
    artifact_job_pid=
    agent_peer_learning_private collect "$artifact_user" >"$WORK/agent-peer-learning-files.json" \
        || fail PEER_LEARNING_RETAINED_FILES_INVALID
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" last-json \
        "$WORK/agent-peer-learning-stdout.jsonl" compute_train_loop >"$WORK/agent-peer-learning-summary.json" \
        || fail PEER_LEARNING_SUMMARY_INVALID
    content_replication_snapshot client agent-peer-learning-transfer-live || fail PEER_LEARNING_PATHS_FAILED
    stop_privacy_observers || fail PEER_LEARNING_CAPTURE_INCOMPLETE
    content_replication_disconnect client agent-peer-learning-transfer || fail PEER_LEARNING_ROUTE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" evidence "$WORK" "$expected_commit" \
        || fail PEER_LEARNING_PROOF_INVALID
}

agent_peer_learning_cleanup() {
    [ -n "${artifact_user:-}" ] && [ -f "$WORK/bin/agent-peer-learning-smoke.py" ] || return 0
    if [ ! -f "$WORK/agent-peer-learning-cleanup.json" ]; then
        agent_peer_learning_private cleanup "$artifact_user" >"$WORK/agent-peer-learning-cleanup.json" || return 1
    fi
}

agent_peer_learning_finalize() {
    for peer_log in "$WORK"/agent-peer-learning-*.json "$WORK"/agent-peer-learning-*.jsonl \
        "$WORK"/agent-peer-learning-*.err "$WORK"/agent-peer-learning-*.log; do
        [ ! -f "$peer_log" ] || [ -L "$peer_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$peer_log" "$output_directory/$(basename -- "$peer_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-peer-learning-smoke.json" "$output_directory/agent-peer-learning-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-peer-learning-smoke.py" report \
        "$WORK/agent-peer-learning-smoke.json" "$expected_commit"
}
