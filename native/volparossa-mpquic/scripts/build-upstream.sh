#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
component_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH='' cd -- "$component_root/../.." && pwd)
source_root="$repo_root/third_party/src/mqvpn"
build_root="$component_root/build/upstream"
source_stage="$build_root/source"
native_build="$component_root/build/native-cmake"
jobs=${VMP_BUILD_JOBS:-2}
mqvpn_patch="$repo_root/patches/volparossa-mqvpn.patch"
xquic_patch="$repo_root/patches/volparossa-xquic.patch"
mqvpn_patch_sha256=dfeffe71a9db187a700a078f0f9f427a57f7eb69bfae2ba1b974a556bd22719d
xquic_patch_sha256=acdb5af1a3ba452cfd49b46c80e99e49774db43e1130d032808d4e538772353b

"$script_dir/verify-upstream.sh"

for command in awk chmod cmake ctest make cc c++ git sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "ERROR: required build command is absent: $command" >&2
        exit 1
    }
done

boringssl_locked_source="$source_root/third_party/xquic/third_party/boringssl"
boringssl_source="$source_stage/boringssl"
boringssl_archive="$source_stage/boringssl.tar"
boringssl_build="$build_root/boringssl"
xquic_locked_source="$source_root/third_party/xquic"
xquic_source="$source_stage/xquic"
xquic_archive="$source_stage/xquic.tar"
xquic_build="$build_root/xquic"
lwip_locked_source="$source_root/third_party/lwip"
lwip_source="$source_stage/lwip"
lwip_archive="$source_stage/lwip.tar"
mqvpn_source="$source_stage/mqvpn"
mqvpn_archive="$source_stage/mqvpn.tar"
mqvpn_build="$build_root/mqvpn"

export_locked_tree() {
    locked_repository=$1
    destination=$2
    archive=$3

    cmake -E remove_directory "$destination"
    cmake -E make_directory "$destination"
    git -C "$locked_repository" archive --format=tar --output="$archive" HEAD
    (
        CDPATH='' cd -- "$destination"
        cmake -E tar xf "$archive"
    )
    cmake -E rm -f "$archive"
}

apply_locked_patch() {
    patch_name=$1
    destination=$2
    patch_file=$3
    expected_sha256=$4

    actual_sha256=$(sha256sum "$patch_file" | awk '{print $1}')
    if [ "$actual_sha256" != "$expected_sha256" ]; then
        echo "ERROR: $patch_name patch hash mismatch: $actual_sha256" >&2
        exit 1
    fi
    git init --quiet "$destination"
    (
        CDPATH='' cd -- "$destination"
        git apply --check --verbose "$patch_file"
        git apply --verbose "$patch_file"
    )
    cmake -E remove_directory "$destination/.git"
}

cmake -E make_directory "$source_stage"
export_locked_tree "$xquic_locked_source" "$xquic_source" "$xquic_archive"
export_locked_tree "$lwip_locked_source" "$lwip_source" "$lwip_archive"
export_locked_tree "$source_root" "$mqvpn_source" "$mqvpn_archive"
export_locked_tree "$boringssl_locked_source" "$boringssl_source" \
    "$boringssl_archive"
apply_locked_patch xquic "$xquic_source" "$xquic_patch" "$xquic_patch_sha256"
apply_locked_patch mqvpn "$mqvpn_source" "$mqvpn_patch" "$mqvpn_patch_sha256"
cmake -E make_directory "$mqvpn_source/third_party"
cmake -E remove_directory "$mqvpn_source/third_party/xquic"
cmake -E remove_directory "$mqvpn_source/third_party/lwip"
cmake -E create_symlink "$xquic_source" "$mqvpn_source/third_party/xquic"
cmake -E create_symlink "$lwip_source" "$mqvpn_source/third_party/lwip"

cmake -E remove_directory "$boringssl_build"
cmake -S "$boringssl_source" -B "$boringssl_build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_FLAGS=-fPIC \
    -DCMAKE_CXX_FLAGS=-fPIC
cmake --build "$boringssl_build" --parallel "$jobs" --target ssl crypto

cmake -E remove_directory "$xquic_build"
cmake -S "$xquic_source" -B "$xquic_build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DSSL_TYPE=boringssl \
    -DSSL_INC_PATH="$boringssl_source/include" \
    -DSSL_LIB_PATH="$boringssl_build/libssl.a;$boringssl_build/libcrypto.a" \
    -DXQC_ENABLE_BBR2=ON \
    -DXQC_ENABLE_UNLIMITED=OFF \
    -DXQC_ENABLE_FEC=OFF \
    -DXQC_ENABLE_XOR=OFF
cmake --build "$xquic_build" --parallel "$jobs"

cmake -E remove_directory "$mqvpn_build"
cmake -S "$mqvpn_source" -B "$mqvpn_build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTING=ON \
    -DBORINGSSL_BUILD_DIR="$boringssl_build" \
    -DBORINGSSL_INCLUDE_DIR="$boringssl_source/include" \
    -DXQUIC_BUILD_DIR="$xquic_build"
cmake --build "$mqvpn_build" --parallel "$jobs"
ctest --test-dir "$mqvpn_build" --output-on-failure

cmake -E remove_directory "$native_build"
cmake -S "$component_root" -B "$native_build" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=ON -DVMP_BUILD_DAEMON=ON
cmake --build "$native_build" --parallel "$jobs"
ctest --test-dir "$native_build" --output-on-failure

artifact="$component_root/build/volparossa-mpquic"
if [ ! -f "$artifact" ]; then
    echo "ERROR: expected daemon artifact is absent: $artifact" >&2
    exit 1
fi
chmod 0755 "$artifact"

echo "upstream source, daemon, and bounded native unit tests completed"
echo "artifact: $artifact"
echo "No VOLPAROSSA multipath acceptance claim follows from these unit tests."
