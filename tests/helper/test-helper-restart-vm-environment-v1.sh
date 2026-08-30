#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
validator=$here/validate-helper-restart-vm-environment-v1.sh
report=$here/fixtures/helper-restart-exact-present-evidence-v1.pass.json
template=$here/fixtures/helper-restart-vm-environment-v1.pass.json
commit=1111111111111111111111111111111111111111
image=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
tmp=$(mktemp -d /tmp/volparossa-restart-environment-test.XXXXXX)
trap 'rm -rf --one-file-system -- "$tmp"' EXIT
hash=$(sha256sum "$report" | awk '{print $1}')
jq -S -c --arg hash "$hash" '.report_sha256=$hash' "$template" >"$tmp/pass.json"
expect() { wanted=$1; shift; set +e; "$@" >"$tmp/out" 2>"$tmp/err"; got=$?; set -e; [ "$got" -eq "$wanted" ] || exit 1; }
reject() { jq -S -c "$2" "$tmp/pass.json" >"$tmp/$1.json"; expect 1 "$validator" "$tmp/$1.json" "$report" "$commit" "$image"; }
sh -n "$validator"
jq -e . "$here/helper-restart-vm-environment-v1.schema.json" >/dev/null
expect 0 "$validator" "$tmp/pass.json" "$report" "$commit" "$image"
reject extra '.extra=true'
reject wrong-kind '.report_kind="volparossa-helper-boundary-vm-environment"'
reject wrong-report-hash '.report_sha256=("b"*64)'
reject wrong-systemd '.guest.systemd_version=258'
reject online '.proof_network.external_https="allowed"'
reject wrong-image '.image_sha512=("b"*128)'
reject wrong-commit '.expected_commit=("2"*40)'
pretty=$tmp/pretty.json; jq -S . "$tmp/pass.json" >"$pretty"; expect 1 "$validator" "$pretty" "$report" "$commit" "$image"
expect 1 "$validator" "$tmp/pass.json" "$report" \
    2222222222222222222222222222222222222222 "$image"
expect 64 "$validator"
printf '%s\n' 'PASS: restart VM environment rejects cross-link and environment substitutions.'
