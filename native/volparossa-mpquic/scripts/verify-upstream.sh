#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
source_root="$repo_root/third_party/src/mqvpn"

for command_name in awk cmp git sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "ERROR: required verification command is absent: $command_name" >&2
        exit 1
    }
done

verify_repo() {
    name=$1
    directory=$2
    expected_commit=$3
    expected_tree=$4
    expected_origin=$5

    if [ ! -d "$directory/.git" ] && [ ! -f "$directory/.git" ]; then
        echo "ERROR: $name source is absent: $directory" >&2
        return 1
    fi
    actual_commit=$(git -C "$directory" rev-parse HEAD)
    actual_tree=$(git -C "$directory" rev-parse 'HEAD^{tree}')
    if [ "$actual_commit" != "$expected_commit" ]; then
        echo "ERROR: $name commit mismatch: $actual_commit" >&2
        return 1
    fi
    if [ "$actual_tree" != "$expected_tree" ]; then
        echo "ERROR: $name tree mismatch: $actual_tree" >&2
        return 1
    fi
    actual_origin=$(git -C "$directory" remote get-url origin)
    if [ "$actual_origin" != "$expected_origin" ]; then
        echo "ERROR: $name origin mismatch: $actual_origin" >&2
        return 1
    fi
    worktree_state=$(git -C "$directory" status --porcelain=v1 \
        --untracked-files=no --ignore-submodules=all)
    if [ -n "$worktree_state" ]; then
        echo "ERROR: $name source contains tracked changes" >&2
        return 1
    fi
    echo "$name $actual_commit $actual_tree"
}

verify_tag() {
    name=$1
    directory=$2
    expected_tag=$3
    actual_tag=$(git -C "$directory" tag --points-at HEAD --list "$expected_tag")
    if [ "$actual_tag" != "$expected_tag" ]; then
        echo "ERROR: $name tag is not attached to the locked commit: $expected_tag" >&2
        return 1
    fi
}

verify_license() {
    name=$1
    upstream_file=$2
    recorded_file=$3
    expected_hash=$4
    if [ ! -f "$upstream_file" ] || [ ! -f "$recorded_file" ]; then
        echo "ERROR: $name license/notice file is absent" >&2
        return 1
    fi
    upstream_hash=$(sha256sum "$upstream_file" | awk '{print $1}')
    recorded_hash=$(sha256sum "$recorded_file" | awk '{print $1}')
    if [ "$upstream_hash" != "$expected_hash" ] ||
       [ "$recorded_hash" != "$expected_hash" ] ||
       ! cmp -s "$upstream_file" "$recorded_file"; then
        echo "ERROR: $name license/notice copy does not match the lock" >&2
        return 1
    fi
}

verify_bundled_file() {
    name=$1
    bundled_file=$2
    expected_hash=$3
    if [ ! -f "$bundled_file" ]; then
        echo "ERROR: $name bundled file is absent: $bundled_file" >&2
        return 1
    fi
    actual_hash=$(sha256sum "$bundled_file" | awk '{print $1}')
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "ERROR: $name bundled file hash mismatch: $actual_hash" >&2
        return 1
    fi
}

verify_patch() {
    name=$1
    patch_file=$2
    expected_hash=$3
    if [ ! -f "$patch_file" ]; then
        echo "ERROR: $name patch is absent: $patch_file" >&2
        return 1
    fi
    actual_hash=$(sha256sum "$patch_file" | awk '{print $1}')
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "ERROR: $name patch hash mismatch: $actual_hash" >&2
        return 1
    fi
}

verify_repo mqvpn "$source_root" \
    607c0df921e2c23bae8bea21cb3c6f2acb2db275 \
    d6c5ff654c5b7be4754bcb8ad2720b112a2b1e56 \
    https://github.com/mp0rta/mqvpn.git
verify_repo xquic "$source_root/third_party/xquic" \
    6957ccf9b9fcb9ab62c43672638876abe47162dc \
    1999a0a944a1c93b46f7b41b9ff4dccb9302966b \
    https://github.com/mp0rta/xquic.git
verify_repo lwip "$source_root/third_party/lwip" \
    821af1994c4dbaf1e2cba9a7c2207303b3e5327b \
    995119cb3b9074644ed8af3d8c2553fe4f3781aa \
    https://github.com/mp0rta/heiher-lwip.git
verify_repo boringssl "$source_root/third_party/xquic/third_party/boringssl" \
    fd490c05de684d4cf135388023acf9aabb4e54f1 \
    0420b7c79fdb88ccf2d7cb21bb934da6a0bc4092 \
    https://github.com/google/boringssl.git

verify_tag mqvpn "$source_root" v0.15.1
verify_tag xquic "$source_root/third_party/xquic" mqvpn-v0.15.1
verify_tag boringssl "$source_root/third_party/xquic/third_party/boringssl" \
    0.20260730.0

for ancestor in \
    16992ac0c9077bbd33f31f30b3af7b89ace1118b \
    e4d89de3a7837ffdc8b0d2c281549151107aebed \
    d20b6b8b6d9552261463e21e48e49e3fbb762b12; do
    if ! git -C "$source_root/third_party/xquic" merge-base --is-ancestor \
        "$ancestor" HEAD; then
        echo "ERROR: xquic security-hardening ancestor is absent: $ancestor" >&2
        exit 1
    fi
done

mqvpn_xquic=$(git -C "$source_root" ls-tree HEAD third_party/xquic | awk '{print $3}')
mqvpn_lwip=$(git -C "$source_root" ls-tree HEAD third_party/lwip | awk '{print $3}')
xquic_boringssl=$(git -C "$source_root/third_party/xquic" \
    ls-tree HEAD third_party/boringssl | awk '{print $3}')

[ "$mqvpn_xquic" = 6957ccf9b9fcb9ab62c43672638876abe47162dc ] || {
    echo "ERROR: mqvpn xquic gitlink does not match lock" >&2
    exit 1
}
[ "$mqvpn_lwip" = 821af1994c4dbaf1e2cba9a7c2207303b3e5327b ] || {
    echo "ERROR: mqvpn lwip gitlink does not match lock" >&2
    exit 1
}
[ "$xquic_boringssl" = fd490c05de684d4cf135388023acf9aabb4e54f1 ] || {
    echo "ERROR: xquic BoringSSL gitlink does not match lock" >&2
    exit 1
}

verify_license mqvpn-license "$source_root/LICENSE" \
    "$repo_root/third_party/licenses/mqvpn-Apache-2.0.txt" \
    cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
verify_license mqvpn-notice "$source_root/NOTICE" \
    "$repo_root/third_party/licenses/mqvpn-NOTICE.txt" \
    c86c552bb97af19967707243cd32203d7c43bebc6856abe69ea08e8f20258da5
verify_license xquic-license "$source_root/third_party/xquic/LICENSE" \
    "$repo_root/third_party/licenses/xquic-Apache-2.0.txt" \
    c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4
verify_license lwip-license "$source_root/third_party/lwip/LICENSE" \
    "$repo_root/third_party/licenses/lwip-BSD-3-Clause.txt" \
    ef4aac92e05e87cd1cdc140870ed52206ba03d4a7fe46c1e11d7ffa6c87d252b
verify_license boringssl-license \
    "$source_root/third_party/xquic/third_party/boringssl/LICENSE" \
    "$repo_root/third_party/licenses/boringssl-LICENSE.txt" \
    827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f
verify_license wintun-license \
    "$source_root/third_party/wintun/LICENSE" \
    "$repo_root/third_party/licenses/wintun-MIT.txt" \
    55743868302006ccaa536bcb96903e185999c6a9cb51ff5bf4b41b96bb30fd07
verify_bundled_file wintun-header "$source_root/third_party/wintun/wintun.h" \
    fd87705912c04a94b9736b88f9a2eb8a6dcb2e40f9dd1515bad941bb71af852a
verify_bundled_file wintun-readme "$source_root/third_party/wintun/README.md" \
    124fd31fc8c48a528bdc43e9fb8b1d0bc2439f37833eea141c1670a1b85e9e67

verify_patch mqvpn "$repo_root/patches/volparossa-mqvpn.patch" \
    91885f49781c5fc38f9d1822c2b98ffec135fc939c769b678acccd7de48fa887
verify_patch mqvpn-exit "$repo_root/patches/volparossa-mqvpn-exit-paths.patch" \
    da22508590dd066852344ac685cb1fc53dfdfaebaed16353ae53f8675f7e1427
verify_patch xquic "$repo_root/patches/volparossa-xquic.patch" \
    acdb5af1a3ba452cfd49b46c80e99e49774db43e1130d032808d4e538772353b
verify_patch mqvpn-edt "$repo_root/patches/volparossa-mqvpn-edt.patch" \
    eeea5b5d09e1225633e0a1fdd1f78c64384cc18bc676088b18bd5f1f41a1f00f
verify_patch xquic-edt "$repo_root/patches/volparossa-xquic-edt.patch" \
    a6d6cae3535b11b650902cec79b91a8e849760b1103ef009d91db99d216d3a57

echo "all upstream commits, trees, tags, gitlinks, origins, bundled files, licenses, and patches match the lock"
