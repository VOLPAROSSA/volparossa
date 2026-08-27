#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Adversarial tests for the PASS-only helper-boundary VM-environment contract.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
validator=$script_directory/validate-helper-boundary-vm-environment-v1.sh
fixture=$script_directory/fixtures/helper-boundary-evidence-v1.pass.json
expected_commit=1111111111111111111111111111111111111111
image_sha512=184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
temporary_directory=$(mktemp -d /tmp/volparossa-vm-environment-test.XXXXXX)
case $temporary_directory in
    /tmp/volparossa-vm-environment-test.??????) ;;
    *) printf '%s\n' 'unsafe VM-environment test directory' >&2; exit 1 ;;
esac
cleanup() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$temporary_directory"
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for required_file in "$validator" "$fixture"; do
    if [ ! -f "$required_file" ] || [ -L "$required_file" ]; then
        printf 'required test input is unsafe: %s\n' "$required_file" >&2
        exit 1
    fi
done

report=$temporary_directory/helper-boundary-evidence-v1.json
cp -- "$fixture" "$report"
report_sha256=$(sha256sum "$report" | sed -n '1{s/[[:space:]].*$//;p;q;}')
valid=$temporary_directory/vm-environment-v1.json
jq -S -c -n \
    --arg commit "$expected_commit" \
    --arg image_sha512 "$image_sha512" \
    --arg report_sha256 "$report_sha256" \
    '{expected_commit: $commit,
      guest: {
        architecture: "amd64",
        cargo_version: "1.85.0",
        debian_version: "13",
        rustc_version: "1.85.0",
        systemd_version: 257,
        virtualization: "kvm"
      },
      image_release_build: "20260826-2582",
      image_sha512: $image_sha512,
      proof_network: {
        external_https: "denied",
        mode: "qemu-user-restrict-on"
      },
      report_kind: "volparossa-helper-boundary-vm-environment",
      report_sha256: $report_sha256,
      schema_version: 1,
      status: "PASS"}' >"$valid"

success_stdout=$temporary_directory/success.stdout
success_stderr=$temporary_directory/success.stderr
"$validator" "$valid" "$report" "$expected_commit" "$image_sha512" \
    >"$success_stdout" 2>"$success_stderr"
if [ -s "$success_stdout" ] || [ -s "$success_stderr" ]; then
    printf '%s\n' 'successful VM-environment validation was not silent' >&2
    exit 1
fi

rejection_count=0
expect_rejected() {
    rejection_name=$1
    rejection_environment=$2
    rejection_report=$3
    rejection_commit=$4
    rejection_image=$5
    rejection_stdout=$temporary_directory/rejection.stdout
    rejection_stderr=$temporary_directory/rejection.stderr
    : >"$rejection_stdout"
    : >"$rejection_stderr"
    if "$validator" "$rejection_environment" "$rejection_report" \
        "$rejection_commit" "$rejection_image" \
        >"$rejection_stdout" 2>"$rejection_stderr"; then
        printf 'validator accepted adversarial mutation: %s\n' "$rejection_name" >&2
        exit 1
    fi
    if [ -s "$rejection_stdout" ]; then
        printf 'validator wrote stdout for rejected mutation: %s\n' "$rejection_name" >&2
        exit 1
    fi
    rejection_count=$((rejection_count + 1))
}

mutate_and_reject() {
    mutation_name=$1
    mutation_filter=$2
    mutation_file=$temporary_directory/mutation.json
    jq -S -c "$mutation_filter" "$valid" >"$mutation_file"
    expect_rejected "$mutation_name" "$mutation_file" "$report" \
        "$expected_commit" "$image_sha512"
}

mutate_and_reject schema-version '.schema_version = 2'
mutate_and_reject report-kind '.report_kind = "other"'
mutate_and_reject status '.status = "STARTED"'
mutate_and_reject expected-commit '.expected_commit = "2222222222222222222222222222222222222222"'
mutate_and_reject release-build '.image_release_build = "20260825-2581"'
mutate_and_reject image-digest '.image_sha512 = ("2" * 128)'
mutate_and_reject report-digest '.report_sha256 = ("2" * 64)'
mutate_and_reject proof-network-external-https '.proof_network.external_https = "allowed"'
mutate_and_reject proof-network-mode '.proof_network.mode = "qemu-user"'
mutate_and_reject guest-architecture '.guest.architecture = "arm64"'
mutate_and_reject guest-cargo '.guest.cargo_version = "1.85.1"'
mutate_and_reject guest-debian '.guest.debian_version = "12"'
mutate_and_reject guest-rustc '.guest.rustc_version = "1.86.0"'
mutate_and_reject guest-systemd '.guest.systemd_version = 258'
mutate_and_reject guest-virtualization '.guest.virtualization = "tcg"'
mutate_and_reject top-level-extra '.unexpected = true'
mutate_and_reject top-level-missing 'del(.status)'
mutate_and_reject guest-extra '.guest.unexpected = true'
mutate_and_reject guest-missing 'del(.guest.cargo_version)'
mutate_and_reject proof-network-extra '.proof_network.unexpected = true'
mutate_and_reject proof-network-missing 'del(.proof_network.mode)'

pretty=$temporary_directory/pretty.json
jq . "$valid" >"$pretty"
expect_rejected pretty-serialization "$pretty" "$report" "$expected_commit" "$image_sha512"

no_lf=$temporary_directory/no-lf.json
canonical_value=$(sed -n '1p' "$valid")
printf '%s' "$canonical_value" >"$no_lf"
expect_rejected missing-final-lf "$no_lf" "$report" "$expected_commit" "$image_sha512"

multiple=$temporary_directory/multiple.json
sed -n '1p' "$valid" >"$multiple"
sed -n '1p' "$valid" >>"$multiple"
expect_rejected multiple-json-values "$multiple" "$report" "$expected_commit" "$image_sha512"

extra_lf=$temporary_directory/extra-lf.json
cp -- "$valid" "$extra_lf"
printf '\n' >>"$extra_lf"
expect_rejected extra-final-lf "$extra_lf" "$report" "$expected_commit" "$image_sha512"

pretty_report=$temporary_directory/pretty-report.json
jq . "$report" >"$pretty_report"
expect_rejected pretty-report-serialization "$valid" "$pretty_report" \
    "$expected_commit" "$image_sha512"

report_no_lf=$temporary_directory/report-no-lf.json
report_value=$(sed -n '1p' "$report")
printf '%s' "$report_value" >"$report_no_lf"
expect_rejected report-missing-final-lf "$valid" "$report_no_lf" \
    "$expected_commit" "$image_sha512"

empty=$temporary_directory/empty.json
: >"$empty"
expect_rejected empty-environment "$empty" "$report" "$expected_commit" "$image_sha512"

oversized=$temporary_directory/oversized.json
jq -S -c --arg padding "$(awk 'BEGIN { for (i = 0; i < 33000; i++) printf "x" }')" \
    '.padding = $padding' "$valid" >"$oversized"
expect_rejected oversized-environment "$oversized" "$report" "$expected_commit" "$image_sha512"

environment_link=$temporary_directory/environment-link.json
ln -s -- "$valid" "$environment_link"
expect_rejected environment-symlink "$environment_link" "$report" \
    "$expected_commit" "$image_sha512"

environment_hardlink=$temporary_directory/environment-hardlink.json
ln -- "$valid" "$environment_hardlink"
expect_rejected environment-hardlink "$valid" "$report" "$expected_commit" "$image_sha512"
rm -- "$environment_hardlink"

report_link=$temporary_directory/report-link.json
ln -s -- "$report" "$report_link"
expect_rejected report-symlink "$valid" "$report_link" "$expected_commit" "$image_sha512"

report_hardlink=$temporary_directory/report-hardlink.json
ln -- "$report" "$report_hardlink"
expect_rejected report-hardlink "$valid" "$report" "$expected_commit" "$image_sha512"
rm -- "$report_hardlink"

expect_rejected invalid-expected-commit "$valid" "$report" not-a-commit "$image_sha512"
expect_rejected wrong-expected-commit "$valid" "$report" \
    2222222222222222222222222222222222222222 "$image_sha512"
expect_rejected wrong-reviewed-image "$valid" "$report" "$expected_commit" \
    22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222

alternate_environment=$temporary_directory/alternate-environment.json
jq -S -c '.expected_commit = "2222222222222222222222222222222222222222"' \
    "$valid" >"$alternate_environment"
expect_rejected report-commit-crosslink "$alternate_environment" "$report" \
    2222222222222222222222222222222222222222 "$image_sha512"

mutated_report=$temporary_directory/mutated-report.json
jq -S -c '.observed_source.commit_sha = "2222222222222222222222222222222222222222"' \
    "$report" >"$mutated_report"
mutated_report_sha=$(sha256sum "$mutated_report" | sed -n '1{s/[[:space:]].*$//;p;q;}')
mutated_environment=$temporary_directory/mutated-environment.json
jq -S -c --arg digest "$mutated_report_sha" '.report_sha256 = $digest' \
    "$valid" >"$mutated_environment"
expect_rejected mutated-report-crosslink "$mutated_environment" "$mutated_report" \
    "$expected_commit" "$image_sha512"

printf 'PASS: helper-boundary VM environment v1 rejected %s adversarial cases.\n' \
    "$rejection_count"
