#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the disposable repository-review scenario.
# shellcheck disable=SC2154,SC2034

repository_review_assess() {
    rr_pin=$1
    rr_attempt=$2
    agent_policy_assessment_cli compute peer policy-assess --source-publisher-key "$jobs_publisher" \
        --source-name disposable-repository-subject --source-manifest-id "$rr_subject_id" \
        --repository-proposal-sha256 "$rr_pin" --cache "$rr_owner/cache-$rr_attempt" \
        --publisher-key "$jobs_publisher" --identity "$jobs_source/identity.key" \
        --passphrase-file "$jobs_source/passphrase" --license CC0-1.0 \
        --provider-key "$jobs_key_a" --provider-key "$jobs_key_b" --model-profile smollm2-360m-v1 \
        --output "$rr_owner/$rr_attempt" --portable-receipts --execute
}

repository_review_publish() {
    rr_name=$1
    rr_file=$2
    rr_type=$3
    agent_jobs_cli client content publish --input "$rr_owner/$rr_file" --name "disposable-repository-$rr_name" \
        --revision 1 --content-type "$rr_type" --expected-input-sha256 "$4" --expected-publisher-key "$jobs_publisher" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --cache "$rr_owner/public-$rr_name" --manifest "$rr_owner/$rr_name.manifest" --lifetime-seconds 7200 \
        >"$rr_log-$rr_name-publication.json" 2>"$rr_log-error.err" || return 1
    repository_review_deposit "$rr_name" "$rr_owner/$rr_name.manifest" "$rr_owner/public-$rr_name"
}

repository_review_deposit() {
    agent_jobs_cli client content custody deposit --manifest "$2" --cache "$3" \
        --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --provider-key "$jobs_key_a" >"$rr_log-$1-deposit.json" 2>"$rr_log-error.err"
}

repository_review_receive() {
    rr_object=$1
    agent_jobs_cli "$provider_node_a" content export --manifest "$rr_receiver/$rr_object.manifest" \
        --publisher-key "$jobs_publisher" --agent-cache "$WORK/state-$provider_node_a/custody-cache" \
        --cache "$rr_receiver/cache-$rr_object" --public-content \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 \
        >"$rr_log-$rr_object-export.json" 2>"$rr_log-error.err" || return 1
    agent_jobs_cli "$provider_node_a" content assemble --manifest "$rr_receiver/$rr_object.manifest" \
        --publisher-key "$jobs_publisher" --cache "$rr_receiver/cache-$rr_object" --output "$rr_receiver/$rr_object.bytes" \
        --quota-bytes 16777216 --max-entries 64 --min-free-bytes 268435456 \
        >"$rr_log-$rr_object-assemble.json" 2>"$rr_log-error.err"
}

repository_review_verify() {
    agent_jobs_cli "$provider_node_a" compute peer verify-repository-review --bundle "$rr_receiver/assessment.bytes" \
        --requester-key "$rr_requester" --source-publisher-key "$jobs_publisher" --source-manifest-id "$rr_subject_id" \
        --repository-proposal-sha256 "$1" --provider-key "$jobs_key_a" --provider-key "$jobs_key_b"
}

repository_review_run() {
    PHASE=repository-review-source
    rr_log=$WORK/agent-repository-review
    rr_owner=$jobs_source/repository-proposal
    rr_receiver=$WORK/state-$provider_node_a/repository-review-receiver
    [ ! -e "$rr_owner" ] && [ ! -e "$rr_receiver" ] || fail REPOSITORY_REVIEW_NOT_COLD
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$rr_owner" "$rr_receiver"
    # Prepare the single public Git input in the disposable guest. Transfer only the enrolled public inputs.
    rr_prepared=$(mktemp -d "$WORK/repository-review-source.XXXXXX") || fail REPOSITORY_REVIEW_PREPARE
    python3 -B "$source_directory/tests/integration/repository-review-smoke.py" prepare "$rr_prepared" || fail REPOSITORY_REVIEW_PREPARE
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 "$rr_prepared/git.bundle" "$rr_prepared/subject.txt" "$rr_owner"
    rm -- "$rr_prepared/git.bundle" "$rr_prepared/subject.txt" && rmdir -- "$rr_prepared" || fail REPOSITORY_REVIEW_SOURCE_CLEANUP
    rr_sha=$(sha256sum "$rr_owner/subject.txt" | cut -d' ' -f1)
    rr_git_sha=$(sha256sum "$rr_owner/git.bundle" | cut -d' ' -f1)
    rr_wrong=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    rr_requester=$(agent_jobs_cli client content recipient-key --identity "$WORK/state-client/identity.key" \
        --passphrase-file "$WORK/credential-client/identity-passphrase" | jq -er '.identity_public_key_hex') || fail REPOSITORY_REVIEW_REQUESTER
    repository_review_publish subject subject.txt text/plain "$rr_sha" || fail REPOSITORY_REVIEW_SUBJECT_PUBLICATION
    repository_review_publish git git.bundle application/octet-stream "$rr_git_sha" || fail REPOSITORY_REVIEW_GIT_PUBLICATION
    rr_subject_id=$(sha256sum "$rr_owner/subject.manifest" | cut -d' ' -f1)
    PHASE=repository-review-assessment
    if repository_review_assess "$rr_wrong" wrong >"$rr_log-wrong.json" 2>"$rr_log-wrong.err"; then fail REPOSITORY_REVIEW_WRONG_SUBJECT_ACCEPTED; fi
    grep -Fq compute_repository_proposal_binding "$rr_log-wrong.err" || fail REPOSITORY_REVIEW_WRONG_SUBJECT_BOUNDARY
    repository_review_assess "$rr_sha" assessment >"$rr_log-result.json" 2>"$rr_log-error.err" || fail REPOSITORY_REVIEW_ASSESSMENT
    agent_policy_assessment_cli compute peer policy-pack --assessment "$rr_owner/assessment" --output "$rr_owner/package" \
        --requester-key "$rr_requester" --identity "$jobs_source/identity.key" --passphrase-file "$jobs_source/passphrase" \
        --execute >"$rr_log-pack.json" 2>"$rr_log-error.err" || fail REPOSITORY_REVIEW_PACK
    repository_review_deposit assessment "$rr_owner/package/assessment.manifest" "$rr_owner/package/cache" || fail REPOSITORY_REVIEW_PACKAGE_DEPOSIT

    PHASE=repository-review-cold-recovery
    # Only signed public selection metadata enters the fresh recipient. Both original payloads must come from custody.
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 "$rr_owner/git.manifest" "$rr_owner/package/assessment.manifest" "$rr_receiver"
    cp -- "$rr_receiver/git.manifest" "$rr_log-git-public.manifest"
    cp -- "$rr_receiver/assessment.manifest" "$rr_log-assessment-public.manifest"
    rm -rf -- "$rr_owner"
    rm -- "$jobs_source/identity.key" "$jobs_source/passphrase" || fail REPOSITORY_REVIEW_AUTHOR_CLEANUP
    repository_review_receive git && repository_review_receive assessment || fail REPOSITORY_REVIEW_HOLDER_RECOVERY
    rr_pid=$(systemctl show --property=MainPID --value "volparossa-alpha-agent@$provider_node_a.service")
    nsenter --target "$rr_pid" --mount --net setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -I -B "$WORK/bin/repository-review-subject.py" --public-bundle "$rr_receiver/git.bytes" \
        --bundle-sha256 "$rr_git_sha" --repository-id 851dc721-4b71-4cea-a819-883a7eaf576e \
        --base 655f50114b90ca929db4097da36d577bd4215243 --candidate 1018ac066c68b52fefa029aa7f3bd4c2bc271dfe \
        --path README >"$rr_log-recomputed.txt" 2>"$rr_log-error.err" || fail REPOSITORY_REVIEW_HOLDER_GIT
    rr_recomputed=$(sha256sum "$rr_log-recomputed.txt" | cut -d' ' -f1)
    [ "$rr_recomputed" = "$rr_sha" ] || fail REPOSITORY_REVIEW_HOLDER_DIFFERENT_CHANGE
    if repository_review_verify "$rr_wrong" >"$rr_log-wrong-recipient.json" 2>"$rr_log-wrong-recipient.err"; then fail REPOSITORY_REVIEW_WRONG_RECIPIENT_ACCEPTED; fi
    grep -Fq compute_repository_proposal_binding "$rr_log-wrong-recipient.err" || fail REPOSITORY_REVIEW_WRONG_RECIPIENT_BOUNDARY
    repository_review_verify "$rr_recomputed" >"$rr_log-verified.json" 2>"$rr_log-error.err" || fail REPOSITORY_REVIEW_HOLDER_VERIFY
    cp -- "$rr_receiver/assessment.bytes" "$rr_log-portable.json"
    python3 -B - "$rr_receiver/git.bytes" "$rr_log-git-public.manifest" "$rr_log-assessment-public.manifest" >"$rr_log-source.json" <<'PY'
import json, sys
from pathlib import Path
print(json.dumps(dict(zip(('git_bundle_hex', 'git_manifest_hex', 'assessment_manifest_hex'),
                          (Path(path).read_bytes().hex() for path in sys.argv[1:]), strict=True))))
PY
    jq -n --arg author "$jobs_publisher" --arg requester "$rr_requester" --arg a "$jobs_key_a" --arg b "$jobs_key_b" \
        --arg manifest "$rr_subject_id" --arg subject "$rr_sha" --arg git "$rr_git_sha" \
        --arg package "$(sha256sum "$rr_log-portable.json" | cut -d' ' -f1)" \
        '{author:$author,requester:$requester,providers:[$a,$b],holder:$a,subject_manifest:$manifest,
          proposal_sha256:$subject,git_sha256:$git,received_review_sha256:$package}' >"$rr_log-selection.json"
    jq -n --arg error compute_repository_proposal_binding '{author_selection:$error,recipient_selection:$error}' >"$rr_log-rejections.json"
    python3 -B "$source_directory/tests/integration/repository-review-smoke.py" evidence "$WORK" || fail REPOSITORY_REVIEW_ORIGINAL_CLAIMS
    rm -rf -- "$rr_receiver"
    benchmark_disconnect_route agent-jobs || fail REPOSITORY_REVIEW_ROUTE_CLEANUP
    agent_jobs_cleanup || fail REPOSITORY_REVIEW_CLEANUP
    PHASE=repository-review-complete
}

repository_review_finalize() {
    rr_log=$WORK/agent-repository-review
    jq -n --arg revision "$expected_commit" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$1" --argjson cleanup "$CLEANUP_COMPLETE" --argjson remaining "$REMAINING_OWNED_OBJECTS" \
        --slurpfile host "$WORK/a15-evidence.json" \
        '{revision:$revision,status:$status,cleanup:$cleanup,remaining:$remaining,phase:$phase,blocker:$blocker,host_state:$host[0]}' \
        >"$rr_log-smoke.json" || return 1
    for rr_kind in smoke.json selection.json portable.json source.json verified.json rejections.json pack.json \
        git-deposit.json assessment-deposit.json git-export.json assessment-export.json \
        wrong.err wrong-recipient.err error.err result.json; do
        rr_path=$rr_log-$rr_kind
        [ ! -f "$rr_path" ] || [ -L "$rr_path" ] || install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$rr_path" "$output_directory"
    done
}
