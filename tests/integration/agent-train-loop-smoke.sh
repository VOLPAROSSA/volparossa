#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Separate owner-enabled scenario; ordinary artifact/train-cycle scenarios remain unchanged.
# shellcheck disable=SC2154,SC2034

agent_train_loop_private() {
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-train-loop-smoke.py" "$@"
}

agent_train_loop_execute() {
    # Only enter the existing node network. `ip netns exec` creates a new
    # mount namespace and remounts /sys, which can hide the cgroup hierarchy
    # needed by the real owner's fail-closed spare-capacity admission probe.
    # The agent mount namespace is also unsuitable: it deliberately hides
    # these owner-controlled model, seed and output directories.
    exec nsenter --net="/run/netns/$R4" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --groups="$custody_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-relay4/control/agent.sock" \
        compute train-loop --plan "$artifact_user/loop-plan.json" --seed "$artifact_user/loop-seed.json" \
        --directory "$artifact_user/loop" --runtime-root "$artifact_user/provision/venv" \
        --model-root "$artifact_user/provision/model" --cache "$loop_cache" \
        --max-cycles 2 --repeat-sources --steps 8 --threads 2 --max-seconds 600 --poll-seconds 1 \
        --publish-name disposable-loop-update --publication-key "$loop_publisher" \
        --identity "$artifact_user/loop-identity.key" --passphrase-file "$artifact_user/loop-passphrase" \
        --publish-cache "$artifact_user/loop-publish-cache" --execute
}

agent_train_loop_isolation() {
    for loop_node in relay4 client; do
        loop_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$loop_node.service")
        case $loop_pid in ''|0|*[!0-9]*) return 1 ;; esac
        nsenter --target "$loop_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
            --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$loop_node/identity.key" || return 1
        for loop_hidden in "$artifact_user" "$WORK/state-relay5"; do
            if nsenter --target "$loop_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
                --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
                -- test -r "$loop_hidden"; then return 1; fi
        done
        if [ "$loop_node" = client ]; then
            if nsenter --target "$loop_pid" --mount setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
                --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
                -- test -r "$WORK/state-relay4"; then return 1; fi
        fi
    done
    jq -n '{own_identity_positive_controls:true,trainer_cannot_read_source_store:true,
        importer_cannot_read_other_stores:true,agents_cannot_read_user_inputs:true}' \
        >"$WORK/agent-train-loop-content-isolation.json"
}

agent_train_loop_run() {
    provider_node_a=relay5
    provider_node_b=relay4
    loop_observer_pid=
    agent_train_loop_isolation || fail TRAIN_LOOP_STORAGE_ISOLATION_FAILED
    content_custody_status relay5 loop-empty 0 || fail TRAIN_LOOP_SOURCE_NOT_EMPTY
    content_custody_status relay4 loop-empty 0 || fail TRAIN_LOOP_TRAINER_NOT_EMPTY
    PHASE=agent-train-loop-original-training
    agent_artifact_compute train "$artifact_user/dataset.json" "$artifact_user/train" \
        >"$WORK/agent-artifact-training.json" 2>"$WORK/agent-artifact-training.err" &
    artifact_job_pid=$!
    agent_artifact_observe "$artifact_job_pid" training "$artifact_user/dataset.json" || fail TRAIN_LOOP_SOURCE_OBSERVER_FAILED
    wait "$artifact_job_pid" || fail TRAIN_LOOP_SOURCE_TRAINING_FAILED
    artifact_job_pid=
    install -m 0600 "$artifact_user/training-isolation.json" "$WORK/agent-artifact-training-isolation.json"
    install -m 0600 "$artifact_user/dataset.json" "$WORK/agent-artifact-original-dataset.json"
    python3 -B "$source_directory/tests/integration/agent-artifact-smoke.py" training "$WORK" "$expected_commit" \
        || fail TRAIN_LOOP_SOURCE_TRAINING_INVALID
    PHASE=agent-train-loop-source-publication
    agent_artifact_cli relay5 init --identity "$artifact_user/identity.key" --passphrase-file "$artifact_user/passphrase" \
        >"$WORK/agent-train-loop-source-identity.log" || fail TRAIN_LOOP_SOURCE_IDENTITY_FAILED
    agent_artifact_cli relay5 content publish --contribute --input "$artifact_user/dataset.json" \
        --name disposable-agent-dataset --revision 1 --content-type application/vnd.volparossa.agent-dataset.v1+json \
        --identity "$artifact_user/identity.key" --passphrase-file "$artifact_user/passphrase" \
        --cache "$artifact_user/dataset-cache" --manifest "$artifact_user/dataset.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-artifact-dataset-publish.json" || fail TRAIN_LOOP_DATASET_PUBLISH_FAILED
    artifact_publisher=$(jq -er '.publisher_key_hex' "$WORK/agent-artifact-dataset-publish.json")
    agent_artifact_cli relay5 content agent pack --directory "$artifact_user/train/adapter" \
        --training-report "$artifact_user/train/report.json" --dataset-manifest "$artifact_user/dataset.pb" \
        --publisher-key "$artifact_publisher" --output "$artifact_user/bundle.bin" \
        >"$WORK/agent-train-loop-source-pack.json" || fail TRAIN_LOOP_SEED_PACK_FAILED
    agent_artifact_cli relay5 content publish --contribute --input "$artifact_user/bundle.bin" \
        --name disposable-agent-adapter --revision 1 --content-type application/vnd.volparossa.adapter.v1 \
        --identity "$artifact_user/identity.key" --passphrase-file "$artifact_user/passphrase" \
        --cache "$artifact_user/adapter-cache" --manifest "$artifact_user/adapter.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-artifact-adapter-publish.json" || fail TRAIN_LOOP_SEED_PUBLISH_FAILED
    agent_artifact_private originals "$artifact_user" >"$WORK/agent-artifact-originals.json" || fail TRAIN_LOOP_ORIGINALS_INVALID
    artifact_dataset_id=$(jq -er '.dataset_manifest_id' "$WORK/agent-artifact-originals.json")
    agent_train_loop_private setup "$artifact_user" "$artifact_publisher" "$artifact_dataset_id" || fail TRAIN_LOOP_ENROLLMENT_INVALID
    agent_artifact_private drop-source "$artifact_user" >"$WORK/agent-artifact-source-removed.json" || fail TRAIN_LOOP_SOURCE_REMOVAL_FAILED
    agent_artifact_restart relay5 || fail TRAIN_LOOP_SOURCE_REOPEN_FAILED

    # Existing encrypted owner identity and a real native store are explicit prerequisites.
    # The tiny enrollment marker only initializes this owner cache; it is never contributed.
    agent_artifact_cli relay4 init --identity "$artifact_user/loop-identity.key" --passphrase-file "$artifact_user/loop-passphrase" \
        >"$WORK/agent-train-loop-owner-identity.log" || fail TRAIN_LOOP_OWNER_IDENTITY_FAILED
    agent_artifact_cli relay4 content recipient-key --identity "$artifact_user/loop-identity.key" \
        --passphrase-file "$artifact_user/loop-passphrase" >"$WORK/agent-train-loop-owner-key.json" || fail TRAIN_LOOP_OWNER_KEY_FAILED
    loop_publisher=$(jq -er '.identity_public_key_hex' "$WORK/agent-train-loop-owner-key.json")
    [ "$loop_publisher" != "$artifact_publisher" ] || fail TRAIN_LOOP_PUBLISHERS_NOT_DISTINCT
    agent_artifact_cli relay4 content publish --input "$artifact_user/loop-plan.json" --name disposable-loop-enrollment \
        --revision 1 --content-type application/json --identity "$artifact_user/loop-identity.key" \
        --passphrase-file "$artifact_user/loop-passphrase" --cache "$artifact_user/loop-publish-cache" \
        --manifest "$artifact_user/loop-enrollment.pb" --lifetime-seconds 7200 \
        >"$WORK/agent-train-loop-owner-cache.json" || fail TRAIN_LOOP_OWNER_CACHE_FAILED
    PHASE=agent-train-loop-protected-seed
    loop_cache=$WORK/state-relay4/agent-loop-cache
    [ ! -e "$loop_cache" ] && [ ! -L "$loop_cache" ] || fail TRAIN_LOOP_CACHE_NOT_NEW
    content_replication_select relay4 agent-train-loop-uptake || fail TRAIN_LOOP_SEED_ROUTE_FAILED
    content_replication_capture uptake agent-train-loop-uptake "$WORK/agent-train-loop-uptake-selection.json" \
        || fail TRAIN_LOOP_SEED_CAPTURE_FAILED
    agent_artifact_cli relay4 content fetch-name --publisher-key "$artifact_publisher" \
        --name disposable-agent-dataset --min-revision 1 --cache "$loop_cache" \
        --local-output "$artifact_user/initial-dataset.json" >"$WORK/agent-train-loop-initial-fetch.json" \
        2>"$WORK/agent-train-loop-initial-fetch.err" || fail TRAIN_LOOP_INITIAL_PROTECTED_FETCH_FAILED
    agent_train_loop_execute >"$WORK/agent-train-loop-stdout.jsonl" 2>"$WORK/agent-train-loop-worker.err" &
    artifact_job_pid=$!
    loop_service_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@relay4.service)
    # Wait only for the genuine CLI privilege drop; observer resolves children across all Tokio threads.
    loop_poll=0
    while [ "$loop_poll" -lt 100 ]; do
        kill -0 "$artifact_job_pid" 2>/dev/null || fail TRAIN_LOOP_EARLY_EXIT
        [ "$(stat -Lc '%u' "/proc/$artifact_job_pid")" != "$WORKER_UID" ] || break
        sleep 0.01; loop_poll=$((loop_poll + 1))
    done
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" observe-loop "$artifact_job_pid" \
        "$artifact_user" "/run/netns/$R4" "$loop_service_pid" \
        >"$WORK/agent-train-loop-observer.log" 2>"$WORK/agent-train-loop-observer.err" &
    loop_observer_pid=$!
    loop_poll=0
    while [ ! -f "$artifact_user/loop-first-worker.ready" ] && [ "$loop_poll" -lt 900 ]; do
        kill -0 "$artifact_job_pid" 2>/dev/null || fail TRAIN_LOOP_FIRST_WORKER_MISSING
        kill -0 "$loop_observer_pid" 2>/dev/null || fail TRAIN_LOOP_OBSERVER_FAILED
        sleep 0.1; loop_poll=$((loop_poll + 1))
    done
    [ -f "$artifact_user/loop-first-worker.ready" ] || fail TRAIN_LOOP_FIRST_WORKER_TIMEOUT
    content_replication_snapshot relay4 agent-train-loop-uptake-live || fail TRAIN_LOOP_SEED_PATHS_FAILED
    stop_privacy_observers || fail TRAIN_LOOP_SEED_CAPTURE_INCOMPLETE
    content_replication_disconnect relay4 agent-train-loop-uptake || fail TRAIN_LOOP_SEED_ROUTE_CLEANUP_FAILED
    PHASE=agent-train-loop-autonomous-cycles
    wait "$artifact_job_pid" || fail TRAIN_LOOP_COORDINATOR_FAILED
    artifact_job_pid=
    wait "$loop_observer_pid" || fail TRAIN_LOOP_OBSERVER_FAILED
    loop_observer_pid=
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" last-json \
        "$WORK/agent-train-loop-stdout.jsonl" compute_train_loop >"$WORK/agent-train-loop-summary.json" || fail TRAIN_LOOP_SUMMARY_INVALID
    agent_train_loop_private collect "$artifact_user" >"$WORK/agent-train-loop-loop.json" || fail TRAIN_LOOP_ACTUAL_FILES_INVALID
    content_custody_status relay4 loop-shared 2 || fail TRAIN_LOOP_UPDATES_NOT_SHARED
    PHASE=agent-train-loop-explicit-original-dataset-contribution
    # Fixture-only explicit sharing of the already fetched original dataset. The loop's two
    # adapter publications above are automatic; this separate handoff is not claimed automatic.
    agent_artifact_cli relay4 content export --public-content \
        --manifest "$artifact_user/loop/cycle-0000000000000002/dataset.manifest" --publisher-key "$artifact_publisher" \
        --agent-cache "$loop_cache" --cache "$artifact_user/loop-dataset-export" \
        >"$WORK/agent-train-loop-dataset-export.json" || fail TRAIN_LOOP_DATASET_EXPORT_FAILED
    agent_artifact_cli relay4 content contribute \
        --manifest "$artifact_user/loop/cycle-0000000000000002/dataset.manifest" --publisher-key "$artifact_publisher" \
        --cache "$artifact_user/loop-dataset-export" >"$WORK/agent-train-loop-dataset-contribute.json" || fail TRAIN_LOOP_DATASET_CONTRIBUTION_FAILED
    content_custody_status relay4 loop-all-shared 3 || fail TRAIN_LOOP_DATASET_NOT_SHARED
    agent_artifact_cli relay5 content stop >"$WORK/agent-train-loop-source-stop.json" || fail TRAIN_LOOP_SOURCE_STOP_FAILED

    PHASE=agent-train-loop-independent-import
    content_replication_select client agent-train-loop-reserve-fetch || fail TRAIN_LOOP_IMPORT_ROUTE_FAILED
    content_replication_capture reserve-fetch agent-train-loop-reserve-fetch "$WORK/agent-train-loop-reserve-fetch-selection.json" \
        || fail TRAIN_LOOP_IMPORT_CAPTURE_FAILED
    artifact_cache=$WORK/state-client/agent-loop-import-cache
    [ ! -e "$artifact_cache" ] && [ ! -L "$artifact_cache" ] || fail TRAIN_LOOP_IMPORT_CACHE_NOT_NEW
    agent_artifact_cli client content agent fetch --publisher-key "$loop_publisher" \
        --dataset-publisher-key "$artifact_publisher" --name disposable-loop-update \
        --dataset-name disposable-agent-dataset --min-revision 2 --cache "$artifact_cache" --output "$artifact_user/received" \
        >"$WORK/agent-train-loop-fetch.json" 2>"$WORK/agent-train-loop-fetch.err" || fail TRAIN_LOOP_IMPORT_FAILED
    content_replication_snapshot client agent-train-loop-reserve-fetch-live || fail TRAIN_LOOP_IMPORT_PATHS_FAILED
    stop_privacy_observers || fail TRAIN_LOOP_IMPORT_CAPTURE_INCOMPLETE
    content_replication_disconnect client agent-train-loop-reserve-fetch || fail TRAIN_LOOP_IMPORT_ROUTE_CLEANUP_FAILED
    agent_artifact_private received "$artifact_user" >"$WORK/agent-artifact-received.json" || fail TRAIN_LOOP_IMPORTED_BYTES_INVALID
    PHASE=agent-train-loop-imported-inference
    agent_artifact_compute infer "$artifact_user/received/dataset.json" "$artifact_user/infer" \
        --adapter-root "$artifact_user/received/adapter" \
        >"$WORK/agent-artifact-inference.json" 2>"$WORK/agent-artifact-inference.err" &
    artifact_job_pid=$!
    agent_artifact_observe "$artifact_job_pid" inference "$artifact_user/received/dataset.json" || fail TRAIN_LOOP_INFERENCE_OBSERVER_FAILED
    wait "$artifact_job_pid" || fail TRAIN_LOOP_INFERENCE_FAILED
    artifact_job_pid=
    install -m 0600 "$artifact_user/inference-isolation.json" "$WORK/agent-artifact-inference-isolation.json"
    agent_train_loop_cleanup || fail TRAIN_LOOP_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" evidence "$WORK" "$expected_commit" || fail TRAIN_LOOP_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-train-loop-complete
}

agent_train_loop_cleanup() {
    if [ -n "${artifact_job_pid:-}" ] && kill -0 "$artifact_job_pid" 2>/dev/null; then
        kill -TERM "$artifact_job_pid" || return 1
        wait "$artifact_job_pid" || true
        artifact_job_pid=
    fi
    if [ -n "${loop_observer_pid:-}" ]; then
        kill -TERM "$loop_observer_pid" 2>/dev/null || true
        wait "$loop_observer_pid" 2>/dev/null || true
        loop_observer_pid=
    fi
    [ -n "${artifact_user:-}" ] && [ -f "$WORK/bin/agent-train-loop-smoke.py" ] || return 0
    for loop_sequence in 1 2; do
        loop_diagnostic=$artifact_user/loop-$loop_sequence-readiness.json
        if [ -f "$loop_diagnostic" ] && [ ! -L "$loop_diagnostic" ]; then
            install -m 0600 "$loop_diagnostic" "$WORK/agent-train-loop-$loop_sequence-readiness.json"
        fi
    done
    if [ ! -f "$WORK/agent-train-loop-cleanup.json" ]; then
        agent_train_loop_private cleanup "$artifact_user" >"$WORK/agent-train-loop-cleanup.json" || return 1
    fi
}

agent_train_loop_finalize_report() {
    loop_status=$1
    for loop_log in "$WORK"/agent-train-loop-*.json "$WORK"/agent-train-loop-*.jsonl "$WORK"/agent-train-loop-*.err \
        "$WORK"/agent-train-loop-*.log "$WORK"/agent-artifact-*.json "$WORK"/agent-artifact-*.err "$WORK"/content-custody-*.json; do
        [ ! -f "$loop_log" ] || [ -L "$loop_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$loop_log" "$output_directory/$(basename -- "$loop_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" finalize "$WORK" "$expected_commit" \
        "$loop_status" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-train-loop-smoke.json" "$output_directory/agent-train-loop-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-train-loop-smoke.py" report "$WORK/agent-train-loop-smoke.json" "$expected_commit"
}
