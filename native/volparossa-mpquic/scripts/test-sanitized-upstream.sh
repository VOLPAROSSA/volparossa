#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

set -eu
umask 077
export LC_ALL=C

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
component_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH='' cd -- "$component_root/../.." && pwd)
lock_file="$repo_root/third_party/upstream.lock.json"
source_root="$repo_root/third_party/src/mqvpn"
build_root="$component_root/build/sanitized-upstream"
source_stage="$build_root/source"
boringssl_source="$source_stage/boringssl"
boringssl_build="$build_root/boringssl"
xquic_source="$source_stage/xquic"
xquic_build="$build_root/xquic"
lwip_source="$source_stage/lwip"
mqvpn_source="$source_stage/mqvpn"
mqvpn_build="$build_root/mqvpn"
wrapper_build="$build_root/wrapper"
jobs=${VMP_SANITIZER_BUILD_JOBS:-2}
sanitizer_flags="-fsanitize=address,undefined -fno-omit-frame-pointer"
asan_options="halt_on_error=1:abort_on_error=1:detect_leaks=1"
ubsan_options="halt_on_error=1:abort_on_error=1:print_stacktrace=1"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

case "$jobs" in
    ""|*[!0-9]*) die "VMP_SANITIZER_BUILD_JOBS must be a positive integer" ;;
esac
[ "$jobs" -ge 1 ] || die "VMP_SANITIZER_BUILD_JOBS must be at least one"

for command in awk bash c++ cc chmod cmake ctest find git grep jq make mktemp \
        nm sed sha256sum sleep stat tr; do
    command -v "$command" >/dev/null 2>&1 ||
        die "required build command is absent: $command"
done

require_file() {
    [ -f "$1" ] || die "required file is absent: $1"
}

locked_patch_field() {
    target=$1
    field=$2
    value=$(jq -r --arg target "$target" --arg field "$field" '
        [.local_patches[] | select(.target == $target)] |
        if length == 1 then .[0][$field] // empty else empty end
    ' "$lock_file")
    [ -n "$value" ] ||
        die "lock has no unique $field for patch target $target"
    printf '%s\n' "$value"
}

export_locked_tree() {
    locked_repository=$1
    destination=$2
    archive=$3

    cmake -E remove_directory "$destination"
    cmake -E make_directory "$destination"
    git -C "$locked_repository" archive --format=tar \
        --output="$archive" HEAD
    (
        CDPATH='' cd -- "$destination"
        cmake -E tar xf "$archive"
    )
    cmake -E rm -f "$archive"
}

apply_locked_patch() {
    patch_target=$1
    destination=$2
    patch_relative=$(locked_patch_field "$patch_target" file)
    expected_sha256=$(locked_patch_field "$patch_target" sha256)
    case "$patch_relative" in
        patches/*.patch) ;;
        *) die "unsafe patch path in lock: $patch_relative" ;;
    esac
    patch_file="$repo_root/$patch_relative"
    require_file "$patch_file"
    actual_sha256=$(sha256sum "$patch_file" | awk '{print $1}')
    [ "$actual_sha256" = "$expected_sha256" ] ||
        die "$patch_target patch hash mismatch: $actual_sha256"

    git init --quiet "$destination"
    (
        CDPATH='' cd -- "$destination"
        git apply --check --verbose "$patch_file"
        git apply --verbose "$patch_file"
    )
    cmake -E remove_directory "$destination/.git"
}

verify_compile_flags() {
    name=$1
    directory=$2
    database="$directory/compile_commands.json"
    require_file "$database"
    if ! jq -e '
        [
            .[] |
            select((.file // "") | test("\\.(c|cc|cpp|cxx|C)$"))
        ] as $entries |
        ($entries | length) > 0 and
        all($entries[];
            (.command // ((.arguments // []) | join(" "))) as $command |
            ($command | contains("-fsanitize=address,undefined")) and
            ($command | contains("-fno-omit-frame-pointer")))
    ' "$database" >/dev/null; then
        die "$name has a C/C++ compile command without required sanitizer flags"
    fi
    entries=$(jq -r '[
        .[] |
        select((.file // "") | test("\\.(c|cc|cpp|cxx|C)$"))
    ] | length' "$database")
    ignored=$(jq -r '
        length - ([
            .[] |
            select((.file // "") | test("\\.(c|cc|cpp|cxx|C)$"))
        ] | length)
    ' "$database")
    echo "$name sanitized C/C++ compile commands: $entries"
    echo "$name ignored non-C/C++ compile database entries: $ignored"
}

verify_link_flags() {
    name=$1
    directory=$2
    checked=0
    link_list=$(mktemp "$directory/.vmp-link-files.XXXXXX")
    find "$directory" -type f \
        -path "*/CMakeFiles/*.dir/link.txt" -print > "$link_list"
    while IFS= read -r link_file; do
        link_command=$(tr '\n' ' ' < "$link_file")
        case "$link_command" in
            *"/ar "*|*" ar "*|*"/gcc-ar "*|*" gcc-ar "*) continue ;;
        esac
        case "$link_command" in
            *"-fsanitize=address,undefined"*) ;;
            *) die "$name link command lacks ASan+UBSan: $link_file" ;;
        esac
        case "$link_command" in
            *"-fno-omit-frame-pointer"*) ;;
            *) die "$name link command lacks frame pointers: $link_file" ;;
        esac
        checked=$((checked + 1))
    done < "$link_list"
    cmake -E rm -f "$link_list"
    [ "$checked" -gt 0 ] ||
        die "$name produced no auditable executable/shared link command"
    echo "$name sanitized link commands: $checked"
}

verify_archive_instrumented() {
    archive=$1
    require_file "$archive"
    if ! nm -u "$archive" 2>/dev/null | grep -q '__asan_'; then
        die "archive has no ASan references: $archive"
    fi
    if ! nm -u "$archive" 2>/dev/null | grep -q '__ubsan_'; then
        die "archive has no UBSan references: $archive"
    fi
}

verify_binary_instrumented() {
    binary=$1
    require_file "$binary"
    if ! nm -u "$binary" 2>/dev/null | grep -q '__asan_'; then
        die "binary has no ASan runtime references: $binary"
    fi
    if ! nm -u "$binary" 2>/dev/null | grep -q '__ubsan_'; then
        die "binary has no UBSan runtime references: $binary"
    fi
}

require_ctest_count() {
    name=$1
    directory=$2
    expected=$3
    actual=$(ctest --test-dir "$directory" -N |
        awk '/Total Tests:/ {print $3}')
    [ "$actual" = "$expected" ] ||
        die "$name test count changed: expected $expected, found ${actual:-none}"
}

require_ctest_name() {
    directory=$1
    test_name=$2
    ctest --test-dir "$directory" -N |
        grep -E "Test +#[0-9]+: $test_name$" >/dev/null ||
        die "required sanitizer test is absent: $test_name"
}

run_ctest_suite() {
    name=$1
    directory=$2
    expected=$3
    require_ctest_count "$name" "$directory" "$expected"
    cmake -E env \
        "ASAN_OPTIONS=$asan_options" \
        "UBSAN_OPTIONS=$ubsan_options" \
        ctest --test-dir "$directory" --output-on-failure \
            --no-tests=error --parallel 1
}

smoke_pid=
smoke_watchdog_pid=
smoke_dir=
cleanup_smoke() {
    if [ -n "$smoke_watchdog_pid" ]; then
        kill -TERM "$smoke_watchdog_pid" 2>/dev/null || true
        wait "$smoke_watchdog_pid" 2>/dev/null || true
        smoke_watchdog_pid=
    fi
    if [ -n "$smoke_pid" ] && kill -0 "$smoke_pid" 2>/dev/null; then
        kill -KILL "$smoke_pid" 2>/dev/null || true
        wait "$smoke_pid" 2>/dev/null || true
    fi
    smoke_pid=
    if [ -n "$smoke_dir" ] && [ -d "$smoke_dir" ]; then
        cmake -E remove_directory "$smoke_dir"
    fi
}

run_daemon_smoke() {
    daemon=$1
    shutdown_signal=$2
    case "$shutdown_signal" in
        INT) signal_label=int ;;
        TERM) signal_label=term ;;
        *) die "unsupported daemon smoke shutdown signal: $shutdown_signal" ;;
    esac
    verify_binary_instrumented "$daemon"
    smoke_dir=$(mktemp -d /tmp/vmp-san-smoke-XXXXXX)
    chmod 0700 "$smoke_dir"
    smoke_socket="$smoke_dir/control.sock"
    smoke_log="$build_root/daemon-smoke-$signal_label.log"
    shutdown_timeout_marker="$smoke_dir/shutdown-timeout"

    trap cleanup_smoke 0 1 2 15
    ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS="$ubsan_options" \
        "$daemon" --mode exit --socket "$smoke_socket" \
        >"$smoke_log" 2>&1 &
    smoke_pid=$!

    attempt=0
    while [ ! -S "$smoke_socket" ]; do
        if ! kill -0 "$smoke_pid" 2>/dev/null; then
            wait "$smoke_pid" 2>/dev/null || true
            smoke_pid=
            die "sanitized daemon exited before creating its control socket; see $smoke_log"
        fi
        attempt=$((attempt + 1))
        [ "$attempt" -lt 100 ] ||
            die "sanitized daemon did not create its control socket; see $smoke_log"
        sleep 0.05
    done

    socket_mode=$(stat -c '%a' "$smoke_socket")
    [ "$socket_mode" = "600" ] ||
        die "sanitized daemon socket mode is $socket_mode, expected 600"
    (
        sleep 5
        if kill -0 "$smoke_pid" 2>/dev/null; then
            : > "$shutdown_timeout_marker"
            kill -KILL "$smoke_pid" 2>/dev/null || true
        fi
    ) &
    smoke_watchdog_pid=$!
    kill "-$shutdown_signal" "$smoke_pid"
    if wait "$smoke_pid"; then
        smoke_status=0
    else
        smoke_status=$?
    fi
    smoke_pid=
    kill -TERM "$smoke_watchdog_pid" 2>/dev/null || true
    wait "$smoke_watchdog_pid" 2>/dev/null || true
    smoke_watchdog_pid=
    [ ! -e "$shutdown_timeout_marker" ] ||
        die "sanitized daemon did not stop within 5 seconds after SIG$shutdown_signal; see $smoke_log"
    [ "$smoke_status" -eq 0 ] ||
        die "sanitized daemon exited with status $smoke_status after SIG$shutdown_signal; see $smoke_log"
    [ ! -e "$smoke_socket" ] ||
        die "sanitized daemon left its control socket behind"

    cleanup_smoke
    smoke_dir=
    trap - 0 1 2 15
    echo "sanitized daemon SIG$shutdown_signal lifecycle smoke passed"
}

"$script_dir/verify-upstream.sh"

echo "Replacing isolated sanitizer build root: $build_root"
cmake -E remove_directory "$build_root"
cmake -E make_directory "$source_stage"

export_locked_tree \
    "$source_root/third_party/xquic/third_party/boringssl" \
    "$boringssl_source" "$source_stage/boringssl.tar"
export_locked_tree "$source_root/third_party/xquic" \
    "$xquic_source" "$source_stage/xquic.tar"
export_locked_tree "$source_root/third_party/lwip" \
    "$lwip_source" "$source_stage/lwip.tar"
export_locked_tree "$source_root" \
    "$mqvpn_source" "$source_stage/mqvpn.tar"
apply_locked_patch xquic "$xquic_source"
apply_locked_patch mqvpn "$mqvpn_source"
cmake -E make_directory "$mqvpn_source/third_party"
cmake -E remove_directory "$mqvpn_source/third_party/xquic"
cmake -E remove_directory "$mqvpn_source/third_party/lwip"
cmake -E create_symlink "$xquic_source" \
    "$mqvpn_source/third_party/xquic"
cmake -E create_symlink "$lwip_source" \
    "$mqvpn_source/third_party/lwip"

cmake -G "Unix Makefiles" -S "$boringssl_source" -B "$boringssl_build" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTING=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DCMAKE_C_FLAGS="$sanitizer_flags" \
    -DCMAKE_CXX_FLAGS="$sanitizer_flags" \
    -DCMAKE_EXE_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_SHARED_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_MODULE_LINKER_FLAGS="$sanitizer_flags"
cmake --build "$boringssl_build" --parallel "$jobs" \
    --target ssl crypto bssl
verify_compile_flags BoringSSL "$boringssl_build"
verify_link_flags BoringSSL "$boringssl_build"
verify_archive_instrumented "$boringssl_build/libssl.a"
verify_archive_instrumented "$boringssl_build/libcrypto.a"

cmake -G "Unix Makefiles" -S "$xquic_source" -B "$xquic_build" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DCMAKE_C_FLAGS="$sanitizer_flags" \
    -DCMAKE_CXX_FLAGS="$sanitizer_flags" \
    -DCMAKE_EXE_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_SHARED_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_MODULE_LINKER_FLAGS="$sanitizer_flags" \
    -DSSL_TYPE=boringssl \
    -DSSL_INC_PATH="$boringssl_source/include" \
    -DSSL_LIB_PATH="$boringssl_build/libssl.a;$boringssl_build/libcrypto.a" \
    -DXQC_ENABLE_TESTING=OFF \
    -DXQC_ENABLE_BBR2=ON \
    -DXQC_ENABLE_UNLIMITED=OFF \
    -DXQC_ENABLE_FEC=OFF \
    -DXQC_ENABLE_XOR=OFF
cmake --build "$xquic_build" --parallel "$jobs"
verify_compile_flags xquic "$xquic_build"
verify_link_flags xquic "$xquic_build"
verify_archive_instrumented "$xquic_build/libxquic-static.a"

cmake -G "Unix Makefiles" -S "$mqvpn_source" -B "$mqvpn_build" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTING=ON \
    -DENABLE_SANITIZERS=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DCMAKE_C_FLAGS="$sanitizer_flags" \
    -DCMAKE_CXX_FLAGS="$sanitizer_flags" \
    -DCMAKE_EXE_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_SHARED_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_MODULE_LINKER_FLAGS="$sanitizer_flags" \
    -DBORINGSSL_BUILD_DIR="$boringssl_build" \
    -DBORINGSSL_INCLUDE_DIR="$boringssl_source/include" \
    -DXQUIC_BUILD_DIR="$xquic_build"
cmake --build "$mqvpn_build" --parallel "$jobs"
verify_compile_flags mqvpn-lwIP "$mqvpn_build"
verify_link_flags mqvpn-lwIP "$mqvpn_build"
verify_archive_instrumented "$mqvpn_build/libmqvpn.a"
verify_archive_instrumented "$mqvpn_build/liblwip_core.a"
require_ctest_name "$mqvpn_build" test_spki_pin
require_ctest_name "$mqvpn_build" test_xquic_abi_pin
require_ctest_name "$mqvpn_build" test_tcp_lane
run_ctest_suite mqvpn-lwIP "$mqvpn_build" 33

cmake -G "Unix Makefiles" -S "$component_root" -B "$wrapper_build" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTING=ON \
    -DVMP_BUILD_DAEMON=ON \
    -DVMP_ENABLE_ASAN=ON \
    -DVMP_ENABLE_UBSAN=ON \
    -DVMP_DAEMON_OUTPUT_DIRECTORY="$wrapper_build/bin" \
    -DVMP_MQVPN_SOURCE_DIR="$mqvpn_source" \
    -DVMP_MQVPN_LIBRARY="$mqvpn_build/libmqvpn.a" \
    -DVMP_LWIP_LIBRARY="$mqvpn_build/liblwip_core.a" \
    -DVMP_XQUIC_LIBRARY="$xquic_build/libxquic-static.a" \
    -DVMP_BORINGSSL_SSL_LIBRARY="$boringssl_build/libssl.a" \
    -DVMP_BORINGSSL_CRYPTO_LIBRARY="$boringssl_build/libcrypto.a" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DCMAKE_C_FLAGS="$sanitizer_flags" \
    -DCMAKE_CXX_FLAGS="$sanitizer_flags" \
    -DCMAKE_EXE_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_SHARED_LINKER_FLAGS="$sanitizer_flags" \
    -DCMAKE_MODULE_LINKER_FLAGS="$sanitizer_flags"
cmake --build "$wrapper_build" --parallel "$jobs"
verify_compile_flags VOLPAROSSA-wrapper "$wrapper_build"
verify_link_flags VOLPAROSSA-wrapper "$wrapper_build"
run_ctest_suite VOLPAROSSA-wrapper "$wrapper_build" 7
api_version=$(ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS="$ubsan_options" \
    "$wrapper_build/bin/volparossa-mpquic" --api-version)
[ "$api_version" = "6" ] ||
    die "native daemon reported API version ${api_version:-none}, expected 6"
echo "sanitized daemon side-effect-free API version probe passed"
run_daemon_smoke "$wrapper_build/bin/volparossa-mpquic" INT
run_daemon_smoke "$wrapper_build/bin/volparossa-mpquic" TERM

echo "full pinned ASan+UBSan graph passed"
echo "build root: $build_root"
echo "mqvpn/lwIP tests: 33"
echo "VOLPAROSSA wrapper tests: 7"
echo "ASAN_OPTIONS=$asan_options"
echo "UBSAN_OPTIONS=$ubsan_options"
echo "BoringSSL and xquic are covered here through sanitized archives, mqvpn"
echo "integration tests, and the sanitized daemon link/lifecycle; this recipe"
echo "does not claim their separate Go/CUnit upstream suites or dataplane acceptance."
