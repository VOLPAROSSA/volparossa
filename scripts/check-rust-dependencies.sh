#!/bin/sh
# Verify locally backported RustSec fixes, then audit the locked dependency graph without network I/O.
set -eu

export LC_ALL=C

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"
mode=full

if [ "$#" -gt 1 ]; then
    printf '%s\n' 'Usage: scripts/check-rust-dependencies.sh [--verify-vendor-only]' >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    case "$1" in
        --verify-vendor-only) mode=vendor_only ;;
        -h|--help)
            printf '%s\n' 'Usage: scripts/check-rust-dependencies.sh [--verify-vendor-only]'
            exit 0
            ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
fi

audit_tmp=
cleanup() {
    if [ -n "$audit_tmp" ] && [ -d "$audit_tmp" ]; then
        rm -rf -- "$audit_tmp"
    fi
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'FAIL  %s\n' "$1" >&2
    exit 1
}

pass() {
    printf 'PASS  %s\n' "$1"
}

check_sha256() {
    expected=$1
    path=$2
    [ -f "$path" ] || fail "required dependency input is missing: $path"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$expected" ] ||
        fail "SHA-256 mismatch for $path: expected $expected, got $actual"
}

tree_sha256() {
    directory=$1
    (
        cd "$directory"
        find . -type f -print0 |
            sort -z |
            xargs -0 sha256sum |
            sha256sum |
            awk '{print $1}'
    )
}

verify_vendor() {
    archive=$1
    archive_sha256=$2
    patch=$3
    patch_sha256=$4
    crate_directory=$5
    vendor_tree_sha256=$6
    embedded_lock_policy=${7:-keep}

    check_sha256 "$archive_sha256" "$archive"
    check_sha256 "$patch_sha256" "$patch"

    tar -xzf "$archive" -C "$audit_tmp"
    extracted="$audit_tmp/$crate_directory"
    [ -d "$extracted" ] || fail "archive did not contain $crate_directory"

    case "$embedded_lock_policy" in
        keep) ;;
        omit)
            rm -f -- "$extracted/Cargo.lock"
            ;;
        *) fail "invalid embedded lock policy for $crate_directory" ;;
    esac

    git -C "$extracted" apply --recount --check "$repository_root/$patch"
    git -C "$extracted" apply --recount "$repository_root/$patch"

    vendor="$repository_root/third_party/rust/vendor/$crate_directory"
    [ -d "$vendor" ] || fail "vendored dependency is missing: $vendor"
    if find "$vendor" -type l -print -quit | grep -q .; then
        fail "$crate_directory contains a symbolic link"
    fi

    diff -qr "$extracted" "$vendor" >/dev/null ||
        fail "$crate_directory differs from its verified crates.io archive plus reviewed patch"

    actual_tree_sha256=$(tree_sha256 "$vendor")
    [ "$actual_tree_sha256" = "$vendor_tree_sha256" ] ||
        fail "tree SHA-256 mismatch for $crate_directory"

    pass "$crate_directory is exactly its reviewed crates.io reconstruction"
}

find_advisory_database() {
    if [ -n "${RUSTSEC_ADVISORY_DB:-}" ]; then
        [ -d "$RUSTSEC_ADVISORY_DB/.git" ] ||
            fail "RUSTSEC_ADVISORY_DB is not a RustSec advisory Git checkout"
        printf '%s\n' "$RUSTSEC_ADVISORY_DB"
        return
    fi

    cargo_home_path=${CARGO_HOME:-${HOME:?HOME is required to locate Cargo data}/.cargo}
    found_database=
    for candidate in "$cargo_home_path/advisory-db" "$cargo_home_path"/advisory-dbs/advisory-db-*; do
        [ -d "$candidate/.git" ] || continue
        if [ -n "$found_database" ]; then
            fail 'multiple local RustSec databases found; select one with RUSTSEC_ADVISORY_DB'
        fi
        found_database=$candidate
    done

    [ -n "$found_database" ] ||
        fail 'no local RustSec database found; set RUSTSEC_ADVISORY_DB to an existing checkout'
    printf '%s\n' "$found_database"
}

check_audit_version() {
    audit_version=$1
    awk -v version="$audit_version" 'BEGIN {
        count = split(version, part, ".");
        if (count < 3) exit 1;
        if (part[1] > 0) exit 0;
        if (part[1] == 0 && part[2] > 22) exit 0;
        if (part[1] == 0 && part[2] == 22 && part[3] >= 1) exit 0;
        exit 1;
    }'
}

check_single_path_package() {
    metadata=$1
    package=$2
    version=$3
    manifest_path=$4

    jq -e \
        --arg package "$package" \
        --arg version "$version" \
        --arg manifest_path "$manifest_path" \
        '[.packages[] | select(.name == $package)] as $matches |
         ($matches | length) == 1 and
         $matches[0].version == $version and
         $matches[0].source == null and
         $matches[0].manifest_path == $manifest_path' \
        "$metadata" >/dev/null ||
        fail "the locked graph does not use only the reviewed $package $version path package"
}

check_single_registry_package() {
    metadata=$1
    package=$2
    version=$3

    jq -e \
        --arg package "$package" \
        --arg version "$version" \
        '[.packages[] | select(.name == $package)] as $matches |
         ($matches | length) == 1 and
         $matches[0].version == $version and
         $matches[0].source == "registry+https://github.com/rust-lang/crates.io-index"' \
        "$metadata" >/dev/null ||
        fail "the locked graph does not use exactly registry $package $version"
}

audit_tmp=$(mktemp -d "${TMPDIR:-/tmp}/volparossa-rustsec.XXXXXX")

verify_vendor \
    third_party/rust/sources/hickory-proto-0.25.2.crate \
    f8a6fe56c0038198998a6f217ca4e7ef3a5e51f46163bd6dd60b5c71ca6c6502 \
    third_party/rust/patches/hickory-proto-0.25.2-rustsec.patch \
    bd1d5df1a13574d5c8b546e1a53dfde04d524353a646c8235786d7724215828a \
    hickory-proto-0.25.2 \
    65d70d1559f2209a76b3ca68357c86bd94c9046e0b5dd22b0b3458ad418b1786

verify_vendor \
    third_party/rust/sources/time-0.3.41.crate \
    8a7619e19bc266e0f9c5e6686659d394bc57973859340060a69221e57dbc0c40 \
    third_party/rust/patches/time-0.3.41-rustsec.patch \
    bc4ad8b199c3284c59b1aa259d5ec907d43f7cb898083a8d5ab99a71cc7a5c8a \
    time-0.3.41 \
    722fc9e265043f6d683a365596063ad3b192a7d4dce542f9aa56bee65ccfdd7b

verify_vendor \
    third_party/rust/sources/libp2p-yamux-0.47.0.crate \
    f15df094914eb4af272acf9adaa9e287baa269943f32ea348ba29cfb9bfc60d8 \
    third_party/rust/patches/libp2p-yamux-0.47.0-single-backend.patch \
    1a845f6cfaa57c993b54f654dc8e9294a450de8c46be323618481a7cc750740d \
    libp2p-yamux-0.47.0 \
    a7a9977042b6d9f602e98d67dc8409c485b5e588f79f8567b9b5b6ec9587e4fb \
    omit

check_sha256 \
    6b9522191b8cb7126b2d214edd7f782d2ccd83c467e9c03b8af9e0bf903b49b4 \
    third_party/rust/vendor/hickory-proto-0.25.2/LICENSE-APACHE
check_sha256 \
    dc470946f0a127507a9e577a20da1eb19eae0abc383b2be1f786f6427944f06c \
    third_party/rust/vendor/hickory-proto-0.25.2/LICENSE-MIT
check_sha256 \
    0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594 \
    third_party/rust/vendor/time-0.3.41/LICENSE-Apache
check_sha256 \
    2537228d9a1b44a5dc595241349cae7090b326c8de165aaf89bfddef4a00d0fc \
    third_party/rust/vendor/time-0.3.41/LICENSE-MIT
check_sha256 \
    e10098b8c52fd18ad0f116aac2c0dba1e99ca125d6848640c00688e160a3ee7d \
    third_party/rust/vendor/libp2p-yamux-0.47.0/LICENSE
check_sha256 \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 \
    third_party/rust/licenses/yamux-0.13.10/LICENSE-APACHE
check_sha256 \
    ec353d4fecf7963b4c054384557e5dbc3c7a717997eb4a3815b315721a6aa75a \
    third_party/rust/licenses/yamux-0.13.10/LICENSE-MIT
pass 'upstream Apache-2.0 and MIT license files are unchanged'

check_sha256 \
    bee77a5a6fa12bdd6fcc4fcee18f831e4f11e7c392583c4cffb13b884d50fd37 \
    third_party/rust/backport-regressions/Cargo.toml
check_sha256 \
    aabd2af12e26033cb8de9b63841b54574718406e4479b47e41bc0d92fc6f14e0 \
    third_party/rust/backport-regressions/.cargo/config.toml
check_sha256 \
    796ae0f160c8d95aa6e395dc56f266273e47928b097c318bdc0dfa499b8dadfd \
    third_party/rust/backport-regressions/src/lib.rs
check_sha256 \
    08e7bcd46d2e3f7411e8f4e855c70027f627be6061f63ab459c43f41a687c5cc \
    third_party/rust/backport-regressions/Cargo.lock
pass 'isolated dependency-security regression harness and rustc-1.85 lock are unchanged'

if [ "$mode" = vendor_only ]; then
    exit 0
fi

CARGO_TARGET_DIR="$audit_tmp/backport-target" \
    cargo test \
        --manifest-path third_party/rust/backport-regressions/Cargo.toml \
        --locked \
        --offline
pass 'all five dependency-security regressions passed, including Yamux fail-closed and wrapper-policy handling'

command -v jq >/dev/null 2>&1 ||
    fail 'jq is required to verify exact locked package provenance'

root_metadata="$audit_tmp/root-metadata.json"
cargo metadata --locked --offline --format-version 1 >"$root_metadata"
fuzz_metadata="$audit_tmp/fuzz-metadata.json"
cargo metadata \
    --manifest-path fuzz/Cargo.toml \
    --locked \
    --offline \
    --format-version 1 >"$fuzz_metadata"

check_single_path_package \
    "$root_metadata" \
    libp2p-yamux \
    0.47.0 \
    "$repository_root/third_party/rust/vendor/libp2p-yamux-0.47.0/Cargo.toml"
check_single_registry_package "$root_metadata" yamux 0.13.10
check_single_path_package \
    "$fuzz_metadata" \
    libp2p-yamux \
    0.47.0 \
    "$repository_root/third_party/rust/vendor/libp2p-yamux-0.47.0/Cargo.toml"
check_single_registry_package "$fuzz_metadata" yamux 0.13.10
pass 'root and fuzz graphs contain one reviewed Yamux wrapper and only fixed yamux 0.13.10'

hickory_features="$audit_tmp/hickory-features.txt"
time_features="$audit_tmp/time-features.txt"
fuzz_hickory_features="$audit_tmp/fuzz-hickory-features.txt"
fuzz_time_features="$audit_tmp/fuzz-time-features.txt"
cargo tree --locked --offline -e features -i hickory-proto >"$hickory_features"
cargo tree --locked --offline -e features -i time >"$time_features"
cargo tree \
    --manifest-path fuzz/Cargo.toml \
    --locked \
    --offline \
    -e features \
    -i hickory-proto >"$fuzz_hickory_features"
cargo tree \
    --manifest-path fuzz/Cargo.toml \
    --locked \
    --offline \
    -e features \
    -i time >"$fuzz_time_features"

grep -F "third_party/rust/vendor/hickory-proto-0.25.2" "$hickory_features" >/dev/null ||
    fail 'the locked graph does not use the reviewed hickory-proto vendor tree'
grep -F "third_party/rust/vendor/time-0.3.41" "$time_features" >/dev/null ||
    fail 'the locked graph does not use the reviewed time vendor tree'
if grep -Eq 'dnssec-ring|dnssec-aws-lc-rs|volparossa-backport-regressions' "$hickory_features"; then
    fail 'the production feature graph unexpectedly enables Hickory DNSSEC'
fi
pass 'locked Cargo graph uses the reviewed Hickory and time patches and keeps Hickory DNSSEC disabled'

check_single_path_package \
    "$fuzz_metadata" \
    hickory-proto \
    0.25.2 \
    "$repository_root/third_party/rust/vendor/hickory-proto-0.25.2/Cargo.toml"
check_single_path_package \
    "$fuzz_metadata" \
    time \
    0.3.41 \
    "$repository_root/third_party/rust/vendor/time-0.3.41/Cargo.toml"
grep -F "third_party/rust/vendor/hickory-proto-0.25.2" "$fuzz_hickory_features" >/dev/null ||
    fail 'the locked fuzz graph does not use the reviewed hickory-proto vendor tree'
grep -F "third_party/rust/vendor/time-0.3.41" "$fuzz_time_features" >/dev/null ||
    fail 'the locked fuzz graph does not use the reviewed time vendor tree'
if grep -Eq \
    'dnssec-ring|dnssec-aws-lc-rs|volparossa-backport-regressions' \
    "$fuzz_hickory_features"; then
    fail 'the fuzz feature graph unexpectedly enables Hickory DNSSEC'
fi
pass 'locked fuzz graph uses the reviewed Hickory and time patches exclusively and keeps Hickory DNSSEC disabled'

cargo deny --version >/dev/null 2>&1 ||
    fail 'cargo-deny is required for license, ban, and source checks'
cargo deny --locked --offline check licenses bans sources
cargo deny \
    --manifest-path fuzz/Cargo.toml \
    --locked \
    --offline \
    check licenses bans sources
pass 'cargo-deny checked root and fuzz licenses, bans, and sources without fetching'

audit_command=${CARGO_AUDIT:-cargo-audit}
case "$audit_command" in
    */*) [ -x "$audit_command" ] || fail "cargo-audit executable is unavailable: $audit_command" ;;
    *) command -v "$audit_command" >/dev/null 2>&1 ||
        fail 'cargo-audit >= 0.22.1 is required; install pinned 0.22.1 with: cargo install --locked cargo-audit --version 0.22.1' ;;
esac

audit_version=$("$audit_command" --version | awk '{print $2}')
check_audit_version "$audit_version" ||
    fail "cargo-audit $audit_version cannot parse the current CVSS 4.0 advisories; require >= 0.22.1"

advisory_database=$(find_advisory_database)
advisory_commit=$(git -C "$advisory_database" rev-parse HEAD)
printf 'INFO  offline RustSec database commit: %s\n' "$advisory_commit"

"$audit_command" audit \
    --db "$advisory_database" \
    --no-fetch \
    --file Cargo.lock \
    --ignore RUSTSEC-2026-0009 \
    --ignore RUSTSEC-2026-0118 \
    --ignore RUSTSEC-2026-0119
"$audit_command" audit \
    --db "$advisory_database" \
    --no-fetch \
    --file fuzz/Cargo.lock \
    --ignore RUSTSEC-2026-0009 \
    --ignore RUSTSEC-2026-0118 \
    --ignore RUSTSEC-2026-0119
pass 'cargo-audit found no unremediated root or fuzz vulnerability; three version matches are locally patched'
