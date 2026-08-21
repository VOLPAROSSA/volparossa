#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
source_root="$repo_root/third_party/src/mqvpn"

if [ "${1-}" != "--yes" ]; then
    echo "This explicitly downloads four public Git repositories at locked commits."
    echo "It writes only below: $repo_root/third_party/src"
    echo "It does not install software or change routes, DNS, firewall, or interfaces."
    echo "Re-run with --yes after reviewing third_party/upstream.lock.json." >&2
    exit 2
fi

clone_exact() {
    name=$1
    origin=$2
    commit=$3
    directory=$4

    if [ -d "$directory/.git" ] || [ -f "$directory/.git" ]; then
        actual_commit=$(git -C "$directory" rev-parse HEAD)
        actual_origin=$(git -C "$directory" remote get-url origin)
        worktree_state=$(git -C "$directory" status --porcelain=v1 \
            --untracked-files=all --ignore-submodules=all)
        if [ "$actual_commit" != "$commit" ] ||
           [ "$actual_origin" != "$origin" ] ||
           [ -n "$worktree_state" ]; then
            echo "ERROR: refusing non-matching existing $name checkout: $directory" >&2
            exit 1
        fi
        echo "locked $name checkout already present"
        return 0
    fi

    if [ -L "$directory" ] ||
       { [ -e "$directory" ] &&
         { [ ! -d "$directory" ] || [ -n "$(ls -A -- "$directory")" ]; }; }; then
        echo "ERROR: refusing to replace existing $name path: $directory" >&2
        exit 1
    fi
    mkdir -p "$(dirname -- "$directory")"
    echo "fetching $name at $commit"
    git clone --filter=blob:none --no-checkout "$origin" "$directory"
    git -C "$directory" checkout --detach "$commit"
}

clone_exact mqvpn https://github.com/mp0rta/mqvpn.git \
    607c0df921e2c23bae8bea21cb3c6f2acb2db275 "$source_root"
clone_exact xquic https://github.com/mp0rta/xquic.git \
    6957ccf9b9fcb9ab62c43672638876abe47162dc \
    "$source_root/third_party/xquic"
clone_exact lwip https://github.com/mp0rta/heiher-lwip.git \
    821af1994c4dbaf1e2cba9a7c2207303b3e5327b \
    "$source_root/third_party/lwip"
clone_exact boringssl https://github.com/google/boringssl.git \
    fd490c05de684d4cf135388023acf9aabb4e54f1 \
    "$source_root/third_party/xquic/third_party/boringssl"

"$script_dir/verify-upstream.sh"
echo "fetch complete; the normal build remains network-free"
