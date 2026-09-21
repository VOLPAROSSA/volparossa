#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit bad-artifact variant; ordinary train-loop and peer-adoption proofs are unchanged.
# shellcheck disable=SC2154,SC2034

agent_artifact_quarantine_run() {
    [ "${agent_artifact_quarantine:-no}" = yes ] || fail ARTIFACT_QUARANTINE_NOT_SELECTED
    agent_peer_learning_run
}

agent_artifact_quarantine_publish() {
    PHASE=agent-artifact-quarantine-publication
    printf '%s\n' 'Disposable guest only: sign and contribute an explicitly generated adapter containing one NaN tensor value under a separate fixture name; the normal valid update is unchanged.'
    agent_artifact_cli relay4 content publish --contribute --input "$artifact_user/quarantine.bundle.bin" \
        --name disposable-quarantine-update --revision 1 --content-type application/vnd.volparossa.adapter.v1 \
        --identity "$artifact_user/loop-identity.key" --passphrase-file "$artifact_user/loop-passphrase" \
        --cache "$artifact_user/quarantine-publish-cache" --manifest "$artifact_user/quarantine.pb" \
        --lifetime-seconds 7200 >"$WORK/agent-artifact-quarantine-publish.json" \
        2>"$WORK/agent-artifact-quarantine-publish.err"
}

agent_artifact_quarantine_finalize() {
    for quarantine_log in "$WORK"/agent-artifact-quarantine-*.json "$WORK"/agent-artifact-quarantine-*.err \
        "$WORK"/agent-peer-learning-*.json "$WORK"/agent-peer-learning-*.jsonl \
        "$WORK"/agent-peer-learning-*.err "$WORK"/agent-peer-learning-*.log; do
        [ ! -f "$quarantine_log" ] || [ -L "$quarantine_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$quarantine_log" "$output_directory/$(basename -- "$quarantine_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-artifact-quarantine-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-artifact-quarantine-smoke.json" \
        "$output_directory/agent-artifact-quarantine-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-artifact-quarantine-smoke.py" report \
        "$WORK/agent-artifact-quarantine-smoke.json" "$expected_commit"
}
