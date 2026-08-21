#!/bin/sh
# Regression test for locked third-party notice collection and path-source rejection.
set -eu

export LC_ALL=C

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/volparossa-license-test.XXXXXX")
cleanup() {
    if [ -d "$test_tmp" ]; then
        rm -rf -- "$test_tmp"
    fi
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'FAIL  %s\n' "$1" >&2
    exit 1
}

metadata=$test_tmp/metadata.json
cargo metadata --locked --offline --format-version 1 >"$metadata"

focused_metadata=$test_tmp/focused-metadata.json
jq '
    .workspace_members as $workspace_members
    | .packages |= map(select(
        (.id as $id | ($workspace_members | index($id)) != null)
        or (.name == "hickory-proto" and .version == "0.25.2")
        or (.name == "time" and .version == "0.3.41")
    ))
' "$metadata" >"$focused_metadata"

notices=$test_tmp/notices
./packaging/collect-cargo-licenses.sh "$focused_metadata" "$notices" >"$test_tmp/collector.log"

for license_path in \
    "$notices/hickory-proto-0.25.2/LICENSE-APACHE" \
    "$notices/hickory-proto-0.25.2/LICENSE-MIT" \
    "$notices/time-0.3.41/LICENSE-Apache" \
    "$notices/time-0.3.41/LICENSE-MIT"
do
    [ -f "$license_path" ] || fail "vendored license was not collected: $license_path"
done

awk -F '	' '
    $1 == "hickory-proto" &&
    $2 == "0.25.2" &&
    $4 == "vendored-crates.io+hickory-proto-0.25.2-security-backport" {
        found = 1
    }
    END { exit !found }
' "$notices/DEPENDENCIES.tsv" ||
    fail 'hickory-proto security-backport provenance is absent from notice inventory'

awk -F '	' '
    $1 == "time" &&
    $2 == "0.3.41" &&
    $4 == "vendored-crates.io+time-0.3.41-security-backport" {
        found = 1
    }
    END { exit !found }
' "$notices/DEPENDENCIES.tsv" ||
    fail 'time security-backport provenance is absent from notice inventory'

if find "$notices" -mindepth 1 -maxdepth 1 -type d -name 'volparossa-*' -print -quit |
    grep -q .
then
    fail 'a workspace member was incorrectly copied as a third-party dependency'
fi

unreviewed_metadata=$test_tmp/unreviewed.json
jq --arg manifest "$test_tmp/unreviewed/Cargo.toml" '
    (.packages[]
        | select(.name == "hickory-proto" and .version == "0.25.2")
        | .manifest_path) = $manifest
' "$focused_metadata" >"$unreviewed_metadata"

if ./packaging/collect-cargo-licenses.sh \
    "$unreviewed_metadata" "$test_tmp/rejected" >"$test_tmp/rejected.log" 2>&1
then
    fail 'an arbitrary non-workspace path dependency was accepted'
fi
grep -F 'Unapproved non-workspace Cargo path dependency:' "$test_tmp/rejected.log" >/dev/null ||
    fail 'arbitrary path dependency did not fail for the expected reason'

printf '%s\n' 'PASS  vendored notices included; workspace and arbitrary path sources excluded'
