#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Cross-link one reviewed Debian 13 KVM environment to one restart evidence report.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "$#" -eq 4 ] || { printf '%s\n' 'usage: validate-helper-restart-vm-environment-v1.sh ENV REPORT COMMIT IMAGE_SHA512' >&2; exit 64; }
environment=$1
report=$2
expected_commit=$3
expected_image=$4
invalid() { printf 'invalid helper restart VM environment v1: %s\n' "$1" >&2; exit 1; }
for input in "$environment" "$report"; do
    if [ ! -f "$input" ] || [ -L "$input" ] \
        || [ "$(stat -Lc '%F:%h' "$input" 2>/dev/null || true)" != 'regular file:1' ]; then
        invalid 'inputs must be unique regular non-symlink files'
    fi
    size=$(stat -Lc '%s' "$input")
    if [ "$size" -lt 1 ] || [ "$size" -gt 32768 ]; then
        invalid 'input size is outside its bound'
    fi
    jq -e -s 'length == 1' "$input" >/dev/null 2>&1 || invalid 'input is not one JSON value'
    jq -S -c . "$input" | cmp -s - "$input" || invalid 'input is not canonical jq -S -c JSON'
done
case $expected_commit in
    *[!0-9a-f]*|'') invalid 'expected commit is invalid' ;;
esac
case ${#expected_commit} in 40|64) ;; *) invalid 'expected commit length is invalid' ;; esac
case $expected_image in *[!0-9a-f]*|'') invalid 'expected image digest is invalid' ;; esac
[ "${#expected_image}" -eq 128 ] || invalid 'expected image digest length is invalid'
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
"$here/validate-helper-restart-exact-present-evidence-v1.sh" "$report" \
    || invalid 'linked restart report is invalid'
report_hash=$(sha256sum "$report" | awk '{print $1}') || invalid 'report hash is unavailable'
jq -e '
  keys == ["expected_commit","guest","image_release_build","image_sha512",
    "proof_network","report_kind","report_sha256","schema_version","status"]
  and (.guest | keys == ["architecture","cargo_version","debian_version",
    "rustc_version","systemd_version","virtualization"])
  and (.proof_network | keys == ["external_https","mode"])
' "$environment" >/dev/null 2>&1 || invalid 'environment keys are not exact'
jq -e --arg commit "$expected_commit" --arg image "$expected_image" \
    --arg report_hash "$report_hash" '
  def exact_keys($keys): type == "object" and keys == ($keys | sort);
  . as $environment
  | (($environment | exact_keys(["expected_commit","guest","image_release_build","image_sha512",
    "proof_network","report_kind","report_sha256","schema_version","status"]))
  and $environment.expected_commit == $commit
  and ($environment.guest | exact_keys(["architecture","cargo_version","debian_version",
      "rustc_version","systemd_version","virtualization"])
    and .architecture == "amd64" and .cargo_version == "1.85.0"
    and .debian_version == "13" and .rustc_version == "1.85.0"
    and .systemd_version == 257 and .virtualization == "kvm")
  and $environment.image_release_build == "20260826-2582"
  and $environment.image_sha512 == $image
  and ($environment.proof_network | exact_keys(["external_https","mode"])
    and .external_https == "denied" and .mode == "qemu-user-restrict-on")
  and $environment.report_kind == "volparossa-helper-restart-vm-environment"
  and $environment.report_sha256 == $report_hash
  and $environment.schema_version == 1 and $environment.status == "PASS")
' "$environment" >/dev/null 2>&1 || invalid 'exact environment cross-link is not satisfied'
jq -e --arg commit "$expected_commit" '.observed_source.commit_sha == $commit' \
    "$report" >/dev/null || invalid 'report commit does not match expected commit'
