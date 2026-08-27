#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Adversarial unprivileged tests for canonical helper-boundary evidence v1.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
validator=$script_directory/validate-helper-boundary-evidence-v1.sh
fixture=$script_directory/fixtures/helper-boundary-evidence-v1.pass.json
temporary_directory=$(mktemp -d /tmp/volparossa-helper-boundary-evidence-test.XXXXXX)
case $temporary_directory in
    /tmp/volparossa-helper-boundary-evidence-test.??????) ;;
    *)
        printf 'unsafe helper-boundary evidence test directory: %s\n' \
            "$temporary_directory" >&2
        exit 1
        ;;
esac
cleanup() {
    rm -rf --one-file-system -- "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in awk cp grep jq ln mktemp rm sed tr; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required evidence test tool is unavailable: %s\n' "$command_name" >&2
        exit 69
    fi
done

counter=0
last_stdout=
last_stderr=
expect_status() {
    expected=$1
    shift
    counter=$((counter + 1))
    last_stdout=$temporary_directory/stdout.$counter
    last_stderr=$temporary_directory/stderr.$counter
    set +e
    "$@" >"$last_stdout" 2>"$last_stderr"
    observed=$?
    set -e
    if [ "$observed" -ne "$expected" ]; then
        printf 'expected exit %s, got %s: %s\n' "$expected" "$observed" "$*" >&2
        sed -n '1,80p' "$last_stderr" >&2
        exit 1
    fi
}

reject_mutation() {
    mutation_name=$1
    mutation_filter=$2
    mutation=$temporary_directory/$mutation_name.json
    jq -S -c "$mutation_filter" "$fixture" >"$mutation"
    expect_status 1 "$validator" "$mutation"
}

if [ ! -f "$validator" ] || [ ! -x "$validator" ] || [ -L "$validator" ]; then
    printf '%s\n' 'helper-boundary evidence validator is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$fixture" ] || [ -L "$fixture" ]; then
    printf '%s\n' 'canonical helper-boundary PASS fixture is not one regular file' >&2
    exit 1
fi

sh -n "$validator"
jq -e . "$script_directory/helper-boundary-evidence-v1.schema.json" >/dev/null
expect_status 0 "$validator" "$fixture"
if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
    printf '%s\n' 'successful helper-boundary validation was not silent' >&2
    exit 1
fi

sha256_source=$temporary_directory/source-sha256.json
jq -S -c '.observed_source.commit_sha = ("a" * 64)' "$fixture" >"$sha256_source"
expect_status 0 "$validator" "$sha256_source"

equal_timestamps=$temporary_directory/equal-timestamps.json
jq -S -c '
    .finished_at = .started_at
    | .generated_at = .started_at
' "$fixture" >"$equal_timestamps"
expect_status 0 "$validator" "$equal_timestamps"

reject_mutation extra-top-level '.unexpected = true'
reject_mutation missing-top-level 'del(.worker)'
reject_mutation wrong-schema-version '.schema_version = 2'
reject_mutation wrong-report-kind '.report_kind = "acceptance"'
reject_mutation dirty-source '.observed_source.worktree_clean = false'
reject_mutation zero-source-sha '.observed_source.commit_sha = ("0" * 40)'
reject_mutation short-source-sha '.observed_source.commit_sha = ("a" * 39)'
reject_mutation uppercase-source-sha '.observed_source.commit_sha = ("A" * 40)'
reject_mutation missing-artifact-hash \
    'del(.observed_artifact_hashes.volparossa_helper_sha256)'
reject_mutation extra-artifact-hash \
    '.observed_artifact_hashes.unexpected_sha256 = ("a" * 64)'
reject_mutation zero-artifact-hash \
    '.observed_artifact_hashes.production_ipc_probe_sha256 = ("0" * 64)'
reject_mutation uppercase-artifact-hash \
    '.observed_artifact_hashes.production_ipc_probe_sha256 = ("A" * 64)'
reject_mutation wrong-debian '.environment.debian_version = "12"'
reject_mutation wrong-dpkg-architecture '.environment.dpkg_architecture = "arm64"'
reject_mutation wrong-machine '.environment.machine = "aarch64"'
reject_mutation wrong-systemd '.environment.systemd_version = 258'
reject_mutation container-environment '.environment.virtualization = "container"'
reject_mutation unsafe-kernel-string '.environment.kernel_release = "6.12 test"'
reject_mutation oversized-kernel-string '.environment.kernel_release = ("a" * 129)'
reject_mutation malformed-started-at '.started_at = "2026-08-27T12:00:00+00:00"'
reject_mutation impossible-started-at '.started_at = "2026-02-31T12:00:00Z"'
reject_mutation reversed-finish '.finished_at = "2026-08-27T11:59:59Z"'
reject_mutation generated-before-finish '.generated_at = .started_at'
reject_mutation missing-invocation '.invocation_ids = [.invocation_ids[0]]'
reject_mutation zero-invocation-id '.invocation_ids[0] = ("0" * 32)'
reject_mutation duplicate-invocation-ids '.invocation_ids[1] = .invocation_ids[0]'
reject_mutation worker-fdstore-not-two '.worker.fdstore_before_retirement = 1'
reject_mutation worker-unit-still-loaded \
    '.worker.unit_load_state_after_retirement = "loaded"'
reject_mutation production-not-argumentless '.production.argumentless = false'
reject_mutation production-fdstore-not-zero '.production.fdstore_during_run = 1'
reject_mutation production-unit-still-loaded \
    '.production.unit_load_state_after_retirement = "loaded"'
reject_mutation journal-changed '.retirement.journal_unchanged = false'
reject_mutation lock-held '.retirement.lock_released = false'
reject_mutation socket-present '.retirement.socket_absent = false'
reject_mutation host-digest-mismatch \
    '.enumerated_host_state.after_sha256 = ("a" * 64)'
reject_mutation host-state-fences-differ \
    '.enumerated_host_state.equal_at_fences = false'
reject_mutation missing-host-state-record '.enumerated_host_state.records |= .[0:15]'
# The dollar variables below belong to jq, not the shell.
# shellcheck disable=SC2016
reject_mutation reordered-host-state-records \
    '.enumerated_host_state.records[0] as $left
     | .enumerated_host_state.records[1] as $right
     | .enumerated_host_state.records[0] = $right
     | .enumerated_host_state.records[1] = $left'
reject_mutation scope-claims-cleanup-owned '.scope.cleanup_owned = true'
reject_mutation scope-claims-restart-recovery '.scope.restart_recovery = true'
reject_mutation scope-claims-installed-package '.scope.installed_package = true'
reject_mutation scope-claims-datapath '.scope.datapath = true'
reject_mutation scope-claims-acceptance '.scope.acceptance_a01_a15 = true'
reject_mutation scope-not-helper-only '.scope.helper_boundary_only = false'
reject_mutation failed-check '.checks[0].result = "FAIL"'
reject_mutation missing-check '.checks = .checks[0:15]'
reject_mutation extra-check '.checks += [.checks[-1]]'
# The dollar variables below belong to jq, not the shell.
# shellcheck disable=SC2016
reject_mutation reordered-checks \
    '.checks[4] as $left | .checks[5] as $right | .checks[4] = $right | .checks[5] = $left'
reject_mutation renamed-check '.checks[0].id = "SOURCE_CLEAN"'
reject_mutation extra-check-field '.checks[0].detail = "synthetic"'
reject_mutation non-pass-overall '.overall = "FAIL"'

pretty=$temporary_directory/pretty.json
jq -S . "$fixture" >"$pretty"
expect_status 1 "$validator" "$pretty"

unterminated=$temporary_directory/unterminated.json
sed '$s/$//' "$fixture" | tr -d '\n' >"$unterminated"
expect_status 1 "$validator" "$unterminated"

trailing_line=$temporary_directory/trailing-line.json
cp -- "$fixture" "$trailing_line"
printf '\n' >>"$trailing_line"
expect_status 1 "$validator" "$trailing_line"

multiple_values=$temporary_directory/multiple-values.json
awk '{ print; print }' "$fixture" >"$multiple_values"
expect_status 1 "$validator" "$multiple_values"

oversized=$temporary_directory/oversized.json
awk 'BEGIN { for (i = 0; i < 32769; i++) printf "x" }' >"$oversized"
expect_status 1 "$validator" "$oversized"

symlink_report=$temporary_directory/symlink.json
ln -s "$fixture" "$symlink_report"
expect_status 66 "$validator" "$symlink_report"
expect_status 66 "$validator" "$temporary_directory"
expect_status 66 "$validator" "$temporary_directory/missing.json"
expect_status 64 "$validator"
expect_status 64 "$validator" "$fixture" "$fixture"

printf '%s\n' 'PASS: helper-boundary evidence v1 rejected every adversarial mutation.'
