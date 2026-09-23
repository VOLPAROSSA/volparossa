#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the owned disposable KVM guest; never executes models on host.
# shellcheck disable=SC2154,SC2034

agent_adapter_aggregation_python() {
    python3 -B "$source_directory/tests/integration/agent-adapter-aggregation-smoke.py" "$@"
}

agent_adapter_aggregation_start() {
    aa_node=$1; aa_label=$2; aa_bound=$3
    shift 3
    aa_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$aa_node.service")
    case $aa_pid in ''|0|*[!0-9]*) fail AGGREGATION_NODE_NOT_RUNNING ;; esac
    PHASE=agent-adapter-aggregation-$aa_label
    # Keep node filesystem masks. Fresh proc exists only in this nonpropagating
    # child; the original service mounts and guest/host networking are unchanged.
    timeout --signal=INT --kill-after=15s "$aa_bound" nsenter --target "$aa_pid" --mount --net \
        unshare --mount --propagation private --mount-proc=/proc \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-$aa_node/control/agent.sock" "$@" \
        >"$WORK/agent-adapter-aggregation-$aa_label.json" \
        2>"$WORK/agent-adapter-aggregation-$aa_label.err" &
    jobs_batch_pid=$!
    agent_adapter_aggregation_python observe "$WORK" "$aa_node" "$aa_label" "$jobs_batch_pid" \
        || fail AGGREGATION_ACTUAL_WORKER_MISSING
    wait "$jobs_batch_pid" || fail AGGREGATION_WORKER_FAILED
    jobs_batch_pid=
}

agent_adapter_aggregation_network_start() {
    aa_network_label=$1
    [ -z "${jobs_batch_pid:-}" ] || fail AGGREGATION_WORKER_STILL_ACTIVE
    [ -z "$PRIVACY_CLIENT_PID$PRIVACY_RELAY0_PID$PRIVACY_RELAY1_PID$PRIVACY_RELAY2_PID$PRIVACY_EXIT_PID$PROVIDER_CONTROL_PID" ] \
        || fail AGGREGATION_CAPTURE_OVERLAP
    case $aa_network_label in
        uptake) aa_network_node=relay4; aa_other_node=client; aa_network_phase=uptake ;;
        receiver) aa_network_node=client; aa_other_node=relay4; aa_network_phase=reserve-fetch ;;
        *) fail AGGREGATION_NETWORK_PHASE_INVALID ;;
    esac
    aa_network_prefix=agent-adapter-aggregation-path-$aa_network_label
    content_replication_disconnect "$aa_other_node" "$aa_network_prefix-other" || fail AGGREGATION_OTHER_ROUTE_ACTIVE
    content_replication_select "$aa_network_node" "$aa_network_prefix" || fail AGGREGATION_PROTECTED_ROUTE_UNAVAILABLE
    content_replication_capture "$aa_network_phase" "$aa_network_prefix" "$WORK/$aa_network_prefix-selection.json" "${2:-1800}" \
        || fail AGGREGATION_CAPTURE_UNAVAILABLE
}

agent_adapter_aggregation_network_finish() {
    [ -z "${jobs_batch_pid:-}" ] || fail AGGREGATION_WORKER_STILL_ACTIVE
    content_replication_snapshot "$aa_network_node" "$aa_network_prefix-live" || fail AGGREGATION_LIVE_ROUTE_MISSING
    stop_privacy_observers || fail AGGREGATION_CAPTURE_INCOMPLETE
    content_replication_disconnect "$aa_network_node" "$aa_network_prefix" || fail AGGREGATION_ROUTE_CLEANUP_FAILED
    agent_adapter_aggregation_python network-path "$WORK" "$aa_network_label" || fail AGGREGATION_PATH_EVIDENCE_INVALID
}

agent_adapter_aggregation_stop_supplier() {
    aa_stopped_node=$1
    case $aa_stopped_node in relay3|relay5) ;; *) fail AGGREGATION_STOP_NODE_INVALID ;; esac
    agent_jobs_cli "$aa_stopped_node" content stop \
        >"$WORK/agent-adapter-aggregation-$aa_stopped_node-stop.json" || fail AGGREGATION_SUPPLIER_STOP_FAILED
    jq -e '.serving == false and .publications == 0' "$WORK/agent-adapter-aggregation-$aa_stopped_node-stop.json" >/dev/null \
        || fail AGGREGATION_SUPPLIER_STILL_SERVING
    systemctl stop "volparossa-alpha-agent@$aa_stopped_node.service" || fail AGGREGATION_SUPPLIER_SHUTDOWN_FAILED
    [ "$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$aa_stopped_node.service")" = 0 ] \
        || fail AGGREGATION_SUPPLIER_STILL_RUNNING
}

agent_adapter_aggregation_prepare() {
    [ "$provider_node_a" = relay4 ] || fail AGGREGATION_LAYOUT_CHANGED
    [ "$provider_node_b" = relay5 ] || fail AGGREGATION_LAYOUT_CHANGED
    aa_r3=$WORK/state-relay3/compute
    aa_r4=$WORK/state-relay4/compute
    aa_r5=$WORK/state-relay5/compute
    aa_client=$WORK/state-client/compute-source
    # R3 adds a third independent runtime lock. The broker is idle; the actual
    # training jobs below use the same bounded product launcher as every node.
    agent_jobs_cli relay3 content recipient-key --identity "$WORK/state-relay3/identity.key" \
        --passphrase-file "$WORK/credential-relay3/identity-passphrase" \
        >"$WORK/agent-jobs-relay3-public.json" || fail AGGREGATION_THIRD_IDENTITY_FAILED
    agent_jobs_broker relay3 || fail AGGREGATION_THIRD_RUNTIME_FAILED
    for aa_copy in venv model; do
        aa_target=$aa_copy
        [ "$aa_copy" != venv ] || aa_target=runtime
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- cp --archive --reflink=auto -- "$jobs_root/provision/$aa_copy" "$aa_client/$aa_target" \
            || fail AGGREGATION_RECEIVER_RUNTIME_FAILED
    done
    agent_adapter_aggregation_python setup "$WORK" "$expected_commit" || fail AGGREGATION_PUBLIC_SOURCE_SETUP_FAILED
    for aa_source in dataset validation; do
        aa_name=disposable-aggregate-data
        [ "$aa_source" != validation ] || aa_name=disposable-aggregate-validation
        agent_jobs_cli relay5 content publish --input "$aa_r5/$aa_source.json" --name "$aa_name" --revision 1 \
            --content-type application/vnd.volparossa.agent-dataset.v1+json \
            --identity "$WORK/state-relay5/identity.key" --passphrase-file "$WORK/credential-relay5/identity-passphrase" \
            --cache "$aa_r5/$aa_source-cache" --manifest "$aa_r5/$aa_source.pb" --lifetime-seconds 7200 --contribute \
            >"$WORK/agent-adapter-aggregation-$aa_source-publish.json" \
            2>"$WORK/agent-adapter-aggregation-$aa_source-publish.err" || fail AGGREGATION_SOURCE_PUBLICATION_FAILED
    done
    agent_adapter_aggregation_python enroll "$WORK" || fail AGGREGATION_ENROLLMENT_FAILED
    aa_steps=8
    for aa_training_node in relay3 relay4 relay5; do
        aa_training_root=$WORK/state-$aa_training_node/compute
        agent_adapter_aggregation_start "$aa_training_node" "$aa_training_node-train" 650s compute run --mode train \
            --runtime-root "$aa_training_root/runtime" --model-root "$jobs_root/provision/model" \
            --dataset "$aa_training_root/dataset.json" --output "$aa_training_root/training" \
            --steps "$aa_steps" --threads 2 --max-seconds 600 --spare-capacity --execute
        agent_jobs_cli "$aa_training_node" content agent pack --directory "$aa_training_root/training/adapter" \
            --training-report "$aa_training_root/training/report.json" --dataset-manifest "$aa_training_root/dataset.pb" \
            --publisher-key "$jobs_key_b" --output "$aa_training_root/adapter.bundle" \
            >"$WORK/agent-adapter-aggregation-$aa_training_node-pack.json" \
            2>"$WORK/agent-adapter-aggregation-$aa_training_node-pack.err" || fail AGGREGATION_ORIGINAL_PACK_FAILED
        # Sign on the actual training node. Do not advertise original R3/R4
        # providers: the explicitly provisioned R5 is the sole network supplier.
        agent_jobs_cli "$aa_training_node" content publish --input "$aa_training_root/adapter.bundle" \
            --name "disposable-aggregate-$aa_training_node" --revision 1 \
            --content-type application/vnd.volparossa.adapter.v1 \
            --identity "$WORK/state-$aa_training_node/identity.key" \
            --passphrase-file "$WORK/credential-$aa_training_node/identity-passphrase" \
            --cache "$aa_training_root/original-cache" --manifest "$aa_training_root/publication.pb" --lifetime-seconds 7200 \
            >"$WORK/agent-adapter-aggregation-$aa_training_node-publish.json" \
            2>"$WORK/agent-adapter-aggregation-$aa_training_node-publish.err" || fail AGGREGATION_ORIGINAL_SIGNING_FAILED
        agent_adapter_aggregation_python provision "$WORK" "$aa_training_node" || fail AGGREGATION_PUBLIC_PROVISIONING_FAILED
        aa_signer=$(jq -er '.identity_public_key_hex' "$WORK/agent-jobs-$aa_training_node-public.json")
        agent_jobs_cli relay5 content contribute --manifest "$aa_r5/supplier-$aa_training_node/publication.pb" \
            --publisher-key "$aa_signer" --cache "$aa_r5/supplier-$aa_training_node/cache" \
            >"$WORK/agent-adapter-aggregation-$aa_training_node-contribute.json" \
            2>"$WORK/agent-adapter-aggregation-$aa_training_node-contribute.err" || fail AGGREGATION_SUPPLIER_CUSTODY_FAILED
        aa_steps=$((aa_steps + 1))
    done
    # R3's generic empty provider offer would otherwise also be queried during
    # name lookup. Its original objects are now explicitly in R5 custody.
    # R3 is neither one of the R0/R1/R2 selected relays nor the control broker.
    agent_adapter_aggregation_stop_supplier relay3
    # Empty agent-owned acquisition cache: only this harmless enrollment, never
    # any source/validation/adapter chunks, is initialized by the fixture.
    for aa_cache in source-cache publish-cache; do
        agent_jobs_cli relay4 content publish --input "$aa_r4/enrollment.json" --name disposable-aggregate-enrollment --revision 1 \
            --content-type application/json --identity "$WORK/state-relay4/identity.key" \
            --passphrase-file "$WORK/credential-relay4/identity-passphrase" --cache "$aa_r4/$aa_cache" \
            --manifest "$aa_r4/$aa_cache.pb" --lifetime-seconds 7200 \
            >"$WORK/agent-adapter-aggregation-$aa_cache-init.json" || fail AGGREGATION_EMPTY_CACHE_INIT_FAILED
    done
}

agent_adapter_aggregation_run() {
    agent_adapter_aggregation_prepare
    agent_adapter_aggregation_network_start uptake
    agent_adapter_aggregation_start relay4 aggregate 1900s compute aggregate-adapters --plan "$aa_r4/plan.json" \
        --directory "$aa_r4/aggregate" --runtime-root "$aa_r4/runtime" --model-root "$jobs_root/provision/model" \
        --cache "$aa_r4/source-cache" --validation-source "$aa_r4/validation-source.json" \
        --threads 2 --max-seconds 600 --execute
    agent_adapter_aggregation_network_finish
    jq -e '.approved == true' "$aa_r4/aggregate/result.json" >/dev/null || fail AGGREGATION_ACTUAL_GATE_REJECTED
    PHASE=agent-adapter-aggregation-publish
    agent_jobs_cli relay4 compute publish-aggregate --directory "$aa_r4/aggregate" \
        --publish-name disposable-approved-aggregate --publication-key "$jobs_key_a" --revision 1 \
        --identity "$WORK/state-relay4/identity.key" --passphrase-file "$WORK/credential-relay4/identity-passphrase" \
        --publish-cache "$aa_r4/publish-cache" --execute \
        >"$WORK/agent-adapter-aggregation-publish.json" 2>"$WORK/agent-adapter-aggregation-publish.err" \
        || fail AGGREGATION_APPROVED_PUBLICATION_FAILED
    # Serve the exact original public dataset from R4's genuinely received cache.
    agent_jobs_cli relay4 content export --manifest "$aa_r4/aggregate/peers/0/import/dataset.manifest" \
        --publisher-key "$jobs_key_b" --agent-cache "$aa_r4/source-cache" --cache "$aa_r4/dataset-serving-cache" --public-content \
        >"$WORK/agent-adapter-aggregation-dataset-export.json" || fail AGGREGATION_DATASET_EXPORT_FAILED
    agent_jobs_cli relay4 content contribute --manifest "$aa_r4/aggregate/peers/0/import/dataset.manifest" \
        --publisher-key "$jobs_key_b" --cache "$aa_r4/dataset-serving-cache" \
        >"$WORK/agent-adapter-aggregation-dataset-contribute.json" || fail AGGREGATION_DATASET_CONTRIBUTION_FAILED
    agent_adapter_aggregation_python receiver-sources "$WORK" || fail AGGREGATION_RECEIVER_NOT_COLD
    # Remove the old supplier before the R4-only capture, as in the existing
    # replication reserve-fetch phase. No observer allowlist is widened.
    agent_adapter_aggregation_stop_supplier relay5
    agent_adapter_aggregation_network_start receiver
    agent_jobs_cli client content agent fetch --publisher-key "$jobs_key_a" --dataset-publisher-key "$jobs_key_b" \
        --name disposable-approved-aggregate --dataset-name disposable-aggregate-data --min-revision 1 \
        --cache "$aa_client/aggregate-cache" --output "$aa_client/received" \
        >"$WORK/agent-adapter-aggregation-import.json" 2>"$WORK/agent-adapter-aggregation-import.err" \
        || fail AGGREGATION_RECEIVER_COLD_IMPORT_FAILED
    agent_adapter_aggregation_network_finish
    agent_adapter_aggregation_start client inference 650s compute run --mode infer \
        --runtime-root "$aa_client/runtime" --model-root "$aa_client/model" --adapter-root "$aa_client/received/adapter" \
        --dataset "$aa_client/received/dataset.json" --output "$aa_client/inference" \
        --steps 1 --threads 2 --max-seconds 600 --spare-capacity --execute
    agent_adapter_aggregation_python capture "$WORK" || fail AGGREGATION_ORIGINAL_EVIDENCE_CHANGED
    agent_jobs_cleanup || fail AGGREGATION_PRIVATE_CLEANUP_FAILED
    agent_adapter_aggregation_python evidence "$WORK" "$expected_commit" || fail AGGREGATION_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-adapter-aggregation-complete
}

agent_adapter_aggregation_finalize_report() {
    agent_adapter_aggregation_python finalize "$WORK" "$expected_commit" "$1" "$CLEANUP_COMPLETE" \
        "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    for aa_log in "$WORK"/agent-adapter-aggregation-*.json "$WORK"/agent-adapter-aggregation-*.err; do
        [ ! -f "$aa_log" ] || [ -L "$aa_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$aa_log" "$output_directory/$(basename -- "$aa_log")"
    done
    agent_adapter_aggregation_python report "$WORK/agent-adapter-aggregation-smoke.json" "$expected_commit"
}
