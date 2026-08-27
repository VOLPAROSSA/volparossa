#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Validate one canonical VM-environment record and its exact helper-boundary report.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
    printf '%s\n' \
        'usage: tests/helper/validate-helper-boundary-vm-environment-v1.sh' \
        '       ENVIRONMENT.json REPORT.json EXPECTED_COMMIT EXPECTED_IMAGE_SHA512' >&2
}

invalid() {
    printf 'invalid helper-boundary VM environment v1: %s\n' "$1" >&2
    exit 1
}

if [ "$#" -ne 4 ]; then
    usage
    exit 64
fi

environment=$1
report=$2
expected_commit=$3
expected_image_sha512=$4
reviewed_image_sha512=184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003

for command_name in cmp dirname jq sed sha256sum stat; do
    command -v "$command_name" >/dev/null 2>&1 \
        || invalid "required validator tool is unavailable: $command_name"
done

case ${#expected_commit} in
    40|64) ;;
    *) invalid 'the expected commit is not a canonical Git object ID' ;;
esac
case $expected_commit in
    *[!0-9a-f]*|0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
        invalid 'the expected commit is not lowercase nonzero hexadecimal'
        ;;
esac
if [ "$expected_image_sha512" != "$reviewed_image_sha512" ]; then
    invalid 'the expected image SHA-512 is not the reviewed Debian image digest'
fi

require_safe_file() {
    checked_file=$1
    checked_name=$2
    checked_maximum=$3
    if [ ! -f "$checked_file" ] || [ -L "$checked_file" ]; then
        invalid "$checked_name must be one regular, non-symlink file"
    fi
    checked_metadata=$(stat -Lc '%F:%h:%s' -- "$checked_file" 2>/dev/null) \
        || invalid "$checked_name metadata is unavailable"
    checked_type=${checked_metadata%%:*}
    checked_rest=${checked_metadata#*:}
    checked_links=${checked_rest%%:*}
    checked_size=${checked_rest##*:}
    if [ "$checked_type" != 'regular file' ] || [ "$checked_links" != 1 ]; then
        invalid "$checked_name must be one single-link regular file"
    fi
    case $checked_size in
        ''|*[!0-9]*) invalid "$checked_name size is invalid" ;;
    esac
    if [ "$checked_size" -lt 1 ] || [ "$checked_size" -gt "$checked_maximum" ]; then
        invalid "$checked_name size is outside its fixed bound"
    fi
}

require_canonical_json() {
    canonical_file=$1
    canonical_name=$2
    jq -e -s 'length == 1' "$canonical_file" >/dev/null 2>&1 \
        || invalid "$canonical_name is not exactly one JSON value"
    jq -S -c . "$canonical_file" | cmp -s - "$canonical_file" \
        || invalid "$canonical_name is not one LF-terminated canonical jq -S -c line"
}

require_safe_file "$environment" 'the environment record' 32768
require_safe_file "$report" 'the helper-boundary report' 32768
environment_metadata_before=$(stat -Lc '%F:%h:%s:%d:%i:%u:%g:%a:%Y:%Z' \
    -- "$environment") || invalid 'the environment record cannot be bookended'
environment_sha256_before=$(sha256sum "$environment" \
    | sed -n '1{s/[[:space:]].*$//;p;q;}') \
    || invalid 'the environment record cannot be bookended'
report_metadata_before=$(stat -Lc '%F:%h:%s:%d:%i:%u:%g:%a:%Y:%Z' -- "$report") \
    || invalid 'the helper-boundary report cannot be bookended'
require_canonical_json "$environment" 'the environment record'

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
report_validator=$script_directory/validate-helper-boundary-evidence-v1.sh
if [ ! -f "$report_validator" ] || [ ! -x "$report_validator" ] \
    || [ -L "$report_validator" ] \
    || [ "$(stat -Lc '%F:%h' "$report_validator" 2>/dev/null || true)" \
        != 'regular file:1' ]; then
    invalid 'the fixed helper-boundary report validator is unavailable'
fi
if ! "$report_validator" "$report" >/dev/null 2>&1; then
    invalid 'the helper-boundary report is not valid evidence v1'
fi

report_sha256=$(sha256sum "$report" | sed -n '1{s/[[:space:]].*$//;p;q;}') \
    || invalid 'the helper-boundary report cannot be hashed'
case $report_sha256 in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) invalid 'the helper-boundary report hash is malformed' ;;
esac
if [ "${#report_sha256}" -ne 64 ]; then
    invalid 'the helper-boundary report hash is malformed'
fi

if ! jq -e \
    --arg expected_commit "$expected_commit" \
    --arg expected_image_sha512 "$expected_image_sha512" \
    --arg report_sha256 "$report_sha256" '
    def exact_keys($expected):
        type == "object" and keys == ($expected | sort);
    exact_keys([
      "expected_commit",
      "guest",
      "image_release_build",
      "image_sha512",
      "proof_network",
      "report_kind",
      "report_sha256",
      "schema_version",
      "status"
    ])
    and .schema_version == 1
    and .report_kind == "volparossa-helper-boundary-vm-environment"
    and .status == "PASS"
    and .expected_commit == $expected_commit
    and .image_release_build == "20260826-2582"
    and .image_sha512 == $expected_image_sha512
    and .report_sha256 == $report_sha256
    and (.proof_network
      | exact_keys(["external_https", "mode"])
      and .external_https == "denied"
      and .mode == "qemu-user-restrict-on")
    and (.guest
      | exact_keys([
          "architecture",
          "cargo_version",
          "debian_version",
          "rustc_version",
          "systemd_version",
          "virtualization"
        ])
      and .architecture == "amd64"
      and .cargo_version == "1.85.0"
      and .debian_version == "13"
      and .rustc_version == "1.85.0"
      and .systemd_version == 257
      and .virtualization == "kvm")
' "$environment" >/dev/null 2>&1; then
    invalid 'the exact PASS-only VM-environment contract is not satisfied'
fi

if ! jq -e --arg expected_commit "$expected_commit" \
    '.observed_source.commit_sha == $expected_commit' "$report" >/dev/null 2>&1; then
    invalid 'the helper-boundary report is not bound to the expected commit'
fi

# Bookend both inputs so a concurrent replacement cannot create a mixed decision.
late_environment_metadata=$(stat -Lc '%F:%h:%s:%d:%i:%u:%g:%a:%Y:%Z' \
    -- "$environment" 2>/dev/null) \
    || invalid 'the environment record disappeared during validation'
late_environment_sha256=$(sha256sum "$environment" \
    | sed -n '1{s/[[:space:]].*$//;p;q;}') \
    || invalid 'the environment record changed during validation'
late_report_metadata=$(stat -Lc '%F:%h:%s:%d:%i:%u:%g:%a:%Y:%Z' \
    -- "$report" 2>/dev/null) \
    || invalid 'the helper-boundary report disappeared during validation'
late_report_sha256=$(sha256sum "$report" | sed -n '1{s/[[:space:]].*$//;p;q;}') \
    || invalid 'the helper-boundary report changed during validation'
if [ "$late_environment_metadata" != "$environment_metadata_before" ] \
    || [ "$late_environment_sha256" != "$environment_sha256_before" ] \
    || [ "$late_report_metadata" != "$report_metadata_before" ] \
    || [ "$late_report_sha256" != "$report_sha256" ]; then
    invalid 'an evidence input changed during validation'
fi
