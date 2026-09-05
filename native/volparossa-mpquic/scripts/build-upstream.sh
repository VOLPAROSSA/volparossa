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
run_tests=${VMP_RUN_TESTS:-yes}
mqvpn_patch="$repo_root/patches/volparossa-mqvpn.patch"
mqvpn_exit_patch="$repo_root/patches/volparossa-mqvpn-exit-paths.patch"
xquic_patch="$repo_root/patches/volparossa-xquic.patch"
mqvpn_edt_patch="$repo_root/patches/volparossa-mqvpn-edt.patch"
xquic_edt_patch="$repo_root/patches/volparossa-xquic-edt.patch"
mqvpn_patch_sha256=91885f49781c5fc38f9d1822c2b98ffec135fc939c769b678acccd7de48fa887
mqvpn_exit_patch_sha256=da22508590dd066852344ac685cb1fc53dfdfaebaed16353ae53f8675f7e1427
xquic_patch_sha256=acdb5af1a3ba452cfd49b46c80e99e49774db43e1130d032808d4e538772353b
mqvpn_edt_patch_sha256=eeea5b5d09e1225633e0a1fdd1f78c64384cc18bc676088b18bd5f1f41a1f00f
xquic_edt_patch_sha256=1cf0fc84fe87a6057ad654a412b7b9b2edc47d71875e06d6fc17079a6bef6ebf

case $run_tests in
    yes) build_testing=ON ;;
    no) build_testing=OFF ;;
    *)
        echo "ERROR: VMP_RUN_TESTS must be yes or no" >&2
        exit 2
        ;;
esac

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
apply_locked_patch xquic-edt "$xquic_source" "$xquic_edt_patch" \
    "$xquic_edt_patch_sha256"
apply_locked_patch mqvpn "$mqvpn_source" "$mqvpn_patch" "$mqvpn_patch_sha256"
apply_locked_patch mqvpn-exit "$mqvpn_source" "$mqvpn_exit_patch" \
    "$mqvpn_exit_patch_sha256"
apply_locked_patch mqvpn-edt "$mqvpn_source" "$mqvpn_edt_patch" \
    "$mqvpn_edt_patch_sha256"
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
if [ "$run_tests" = yes ]; then
    ctest --test-dir "$xquic_build" --output-on-failure \
        -R '^volparossa_edt_contract$'
fi

cmake -E remove_directory "$mqvpn_build"
cmake -S "$mqvpn_source" -B "$mqvpn_build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTING="$build_testing" \
    -DBORINGSSL_BUILD_DIR="$boringssl_build" \
    -DBORINGSSL_INCLUDE_DIR="$boringssl_source/include" \
    -DXQUIC_BUILD_DIR="$xquic_build"
cmake --build "$mqvpn_build" --parallel "$jobs"
if [ "$run_tests" = yes ]; then
    ctest --test-dir "$mqvpn_build" --output-on-failure
fi

cmake -E remove_directory "$native_build"
cmake -S "$component_root" -B "$native_build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTING="$build_testing" \
    -DVMP_BUILD_DAEMON=ON
cmake --build "$native_build" --parallel "$jobs"
if [ "$run_tests" = yes ]; then
    ctest --test-dir "$native_build" --output-on-failure
fi

artifact="$component_root/build/volparossa-mpquic"
if [ ! -f "$artifact" ]; then
    echo "ERROR: expected daemon artifact is absent: $artifact" >&2
    exit 1
fi
chmod 0755 "$artifact"

if [ "$run_tests" = yes ]; then
    echo "upstream source, daemon, and bounded native unit tests completed"
    echo "No VOLPAROSSA multipath acceptance claim follows from these unit tests."
else
    echo "upstream source and daemon build completed; tests were explicitly skipped"
    echo "No VOLPAROSSA multipath acceptance claim follows from a build-only check."
fi
echo "artifact: $artifact"
