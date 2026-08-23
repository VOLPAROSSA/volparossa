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
        or (.name == "libp2p-yamux" and .version == "0.47.0")
        or (.name == "time" and .version == "0.3.41")
        or (.name == "yamux" and .version == "0.13.10")
    ))
' "$metadata" >"$focused_metadata"

notices=$test_tmp/notices
./packaging/collect-cargo-licenses.sh "$focused_metadata" "$notices" >"$test_tmp/collector.log"

for license_path in \
    "$notices/hickory-proto-0.25.2/LICENSE-APACHE" \
    "$notices/hickory-proto-0.25.2/LICENSE-MIT" \
    "$notices/libp2p-yamux-0.47.0/LICENSE" \
    "$notices/time-0.3.41/LICENSE-Apache" \
    "$notices/time-0.3.41/LICENSE-MIT" \
    "$notices/yamux-0.13.10/LICENSE-APACHE" \
    "$notices/yamux-0.13.10/LICENSE-MIT"
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

awk -F '	' '
    $1 == "libp2p-yamux" &&
    $2 == "0.47.0" &&
    $4 == "vendored-crates.io+libp2p-yamux-0.47.0-single-backend" {
        found = 1
    }
    END { exit !found }
' "$notices/DEPENDENCIES.tsv" ||
    fail 'libp2p-yamux single-backend provenance is absent from notice inventory'

awk -F '\t' '
    $1 == "yamux" &&
    $2 == "0.13.10" &&
    $4 == "crates.io+yamux-0.13.10;licenses=official-tag-70db05dc63e8368bd0559a5ec0dba6e5fc2bdd41" {
        found = 1
    }
    END { exit !found }
' "$notices/DEPENDENCIES.tsv" ||
    fail 'yamux backend license provenance is absent from notice inventory'

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

fake_yamux=$test_tmp/fake-yamux
install -d "$fake_yamux"
printf '%s\n' '[package]' 'name = "yamux"' 'version = "0.13.10"' >"$fake_yamux/Cargo.toml"
printf '%s\n' \
    '{"git":{"sha1":"0000000000000000000000000000000000000000"},"path_in_vcs":"yamux"}' \
    >"$fake_yamux/.cargo_vcs_info.json"
misbound_yamux_metadata=$test_tmp/misbound-yamux.json
jq --arg manifest "$fake_yamux/Cargo.toml" '
    (.packages[]
        | select(.name == "yamux" and .version == "0.13.10")
        | .manifest_path) = $manifest
' "$focused_metadata" >"$misbound_yamux_metadata"

if ./packaging/collect-cargo-licenses.sh \
    "$misbound_yamux_metadata" "$test_tmp/misbound" >"$test_tmp/misbound.log" 2>&1
then
    fail 'yamux license fallback accepted mismatched VCS provenance'
fi
grep -F 'yamux 0.13.10 has unexpected or missing VCS provenance.' \
    "$test_tmp/misbound.log" >/dev/null ||
    fail 'misbound yamux fallback did not fail for the expected reason'

printf '%s\n' 'PASS  reviewed notices included; workspace, arbitrary path, and misbound fallback sources excluded'
