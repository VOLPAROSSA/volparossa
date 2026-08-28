#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Unprivileged argument, preview, and static safety contract for the live helper gate.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
gate=$repository_directory/tests/helper/require-live-worker-identity-proof.sh
capture_library=$repository_directory/tests/helper/lib/live-worker-proof-capture.sh
ipc_hook=$repository_directory/tests/helper/lib/production-ipc-unit-hook.sh
evidence_validator=$repository_directory/tests/helper/validate-helper-boundary-evidence-v1.sh
evidence_schema=$repository_directory/tests/helper/helper-boundary-evidence-v1.schema.json
temporary_directory=$(mktemp -d /tmp/volparossa-helper-proof-contract.XXXXXX)
resolver_authority_outside=
resolver_runtime_directory=
case $temporary_directory in
    /tmp/volparossa-helper-proof-contract.??????) ;;
    *)
        printf 'unsafe helper proof contract directory: %s\n' "$temporary_directory" >&2
        exit 1
        ;;
esac
cleanup() {
    if [ -n "$resolver_authority_outside" ]; then
        case $resolver_authority_outside in
            /tmp/volparossa-resolver-authority-outside.??????)
                rm -f -- "$resolver_authority_outside"
                ;;
            *)
                printf 'unsafe resolver authority cleanup path: %s\n' \
                    "$resolver_authority_outside" >&2
                ;;
        esac
    fi
    if [ -n "$resolver_runtime_directory" ]; then
        case $resolver_runtime_directory in
            /tmp/volparossa-resolver-runtime.??????)
                rm -rf --one-file-system -- "$resolver_runtime_directory"
                ;;
            *)
                printf 'unsafe resolver runtime cleanup path: %s\n' \
                    "$resolver_runtime_directory" >&2
                ;;
        esac
    fi
    rm -rf --one-file-system -- "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'BLOCKED: helper proof contract test must remain unprivileged' >&2
    exit 77
fi
if [ ! -f "$gate" ] || [ ! -x "$gate" ] || [ -L "$gate" ]; then
    printf '%s\n' 'live helper proof gate is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$capture_library" ] || [ -L "$capture_library" ]; then
    printf '%s\n' 'live helper proof capture library is not one regular file' >&2
    exit 1
fi
if [ ! -f "$ipc_hook" ] || [ ! -x "$ipc_hook" ] || [ -L "$ipc_hook" ]; then
    printf '%s\n' 'production IPC unit hook is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$evidence_validator" ] || [ ! -x "$evidence_validator" ] \
    || [ -L "$evidence_validator" ]; then
    printf '%s\n' 'helper-boundary evidence validator is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$evidence_schema" ] || [ ! -r "$evidence_schema" ] \
    || [ -L "$evidence_schema" ]; then
    printf '%s\n' 'helper-boundary evidence schema is not one readable regular file' >&2
    exit 1
fi
sh -n "$gate"
sh -n "$capture_library"
sh -n "$ipc_hook"
sh -n "$evidence_validator"
jq -e . "$evidence_schema" >/dev/null

VP_CAPTURE_OWNER_UID=$(id -u)
VP_CAPTURE_OWNER_GID=$(id -g)
export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
# shellcheck source=tests/helper/lib/live-worker-proof-capture.sh
. "$capture_library"

counter=0
last_stdout=
last_stderr=
expect_status() {
    expected=$1
    shift
    counter=$((counter + 1))
    last_stdout=$temporary_directory/stdout.$counter
    last_stderr=$temporary_directory/stderr.$counter
    set +e
    "$@" >"$last_stdout" 2>"$last_stderr"
    observed=$?
    set -e
    if [ "$observed" -ne "$expected" ]; then
        printf 'expected exit %s, got %s: %s\n' "$expected" "$observed" "$*" >&2
        sed -n '1,80p' "$last_stderr" >&2
        exit 1
    fi
}

injected_successful_producer() {
    printf '%s\n' 'identical partial capture'
}

injected_failing_producer() {
    printf '%s\n' 'identical partial capture'
    return 19
}

injected_failing_parser() {
    cat
    return 23
}

producer_failure_gate() {
    producer_raw=$temporary_directory/producer-failure.raw
    producer_digest=$temporary_directory/producer-failure.digest
    vp_capture_run "$producer_raw" injected_failing_producer || return 77
    vp_capture_publish_digest "$producer_raw" "$producer_digest" || return 77
}

parser_failure_gate() {
    parser_raw=$temporary_directory/parser-failure.raw
    parser_normalized=$temporary_directory/parser-failure.normalized
    parser_digest=$temporary_directory/parser-failure.digest
    vp_capture_run "$parser_raw" injected_successful_producer || return 77
    vp_capture_normalize "$parser_raw" "$parser_normalized" injected_failing_parser || return 77
    vp_capture_publish_digest "$parser_normalized" "$parser_digest" || return 77
}

stream_producer_failure_gate() {
    stream_fifo=$temporary_directory/stream-producer-failure.fifo
    stream_digest=$temporary_directory/stream-producer-failure.digest
    vp_capture_stream_sha256 "$stream_fifo" "$stream_digest" injected_failing_producer \
        || return 77
}

stream_hasher_failure_gate() {
    (
        sha256sum() {
            cat >/dev/null
            return 29
        }
        stream_fifo=$temporary_directory/stream-hasher-failure.fifo
        stream_digest=$temporary_directory/stream-hasher-failure.digest
        vp_capture_stream_sha256 "$stream_fifo" "$stream_digest" \
            injected_successful_producer || exit 77
    )
}

# Exercise the gate's real snapshot parser rather than a test-side copy. These
# fixtures cover both accepted size boundaries and every metadata field that
# grants authority to stage a workspace-owned executable as root.
source_snapshot_function=$temporary_directory/source-snapshot-function.sh
sed -n '/^source_snapshot_is_exact() {$/,/^}$/p' "$gate" \
    >"$source_snapshot_function"
if [ "$(grep -c '^source_snapshot_is_exact() {$' "$source_snapshot_function")" -ne 1 ]; then
    printf '%s\n' 'the bounded source-snapshot predicate cannot be isolated' >&2
    exit 1
fi
sh -n "$source_snapshot_function"
repository_owner_uid=$(id -u)
repository_owner_gid=$(id -g)
staged_executable_max_bytes=134217728
# The function path is generated from the reviewed gate above.
# shellcheck disable=SC1090
. "$source_snapshot_function"

require_snapshot_acceptance() {
    snapshot_description=$1
    snapshot_value=$2
    if ! source_snapshot_is_exact \
        "$snapshot_value" 755 "$staged_executable_max_bytes"; then
        printf 'valid source snapshot was rejected: %s\n' "$snapshot_description" >&2
        exit 1
    fi
}

require_snapshot_rejection() {
    snapshot_description=$1
    snapshot_value=$2
    if source_snapshot_is_exact \
        "$snapshot_value" 755 "$staged_executable_max_bytes"; then
        printf 'adversarial source snapshot was accepted: %s\n' \
            "$snapshot_description" >&2
        exit 1
    fi
}

snapshot_prefix="regular file:11:12:$repository_owner_uid:$repository_owner_gid:755:1"
snapshot_suffix='13:14'
require_snapshot_acceptance size-one \
    "$snapshot_prefix:1:$snapshot_suffix"
require_snapshot_acceptance size-exactly-128-mib \
    "$snapshot_prefix:134217728:$snapshot_suffix"
require_snapshot_rejection size-zero \
    "$snapshot_prefix:0:$snapshot_suffix"
require_snapshot_rejection size-over-128-mib \
    "$snapshot_prefix:134217729:$snapshot_suffix"
require_snapshot_rejection wrong-type \
    "directory:11:12:$repository_owner_uid:$repository_owner_gid:755:1:1:$snapshot_suffix"
require_snapshot_rejection wrong-uid \
    "regular file:11:12:$((repository_owner_uid + 1)):$repository_owner_gid:755:1:1:$snapshot_suffix"
require_snapshot_rejection wrong-gid \
    "regular file:11:12:$repository_owner_uid:$((repository_owner_gid + 1)):755:1:1:$snapshot_suffix"
require_snapshot_rejection wrong-mode \
    "regular file:11:12:$repository_owner_uid:$repository_owner_gid:700:1:1:$snapshot_suffix"
require_snapshot_rejection extra-hardlink \
    "regular file:11:12:$repository_owner_uid:$repository_owner_gid:755:2:1:$snapshot_suffix"
require_snapshot_rejection malformed-missing-field \
    "$snapshot_prefix:1:13"
require_snapshot_rejection malformed-extra-field \
    "$snapshot_prefix:1:$snapshot_suffix:15"
require_snapshot_rejection malformed-size \
    "$snapshot_prefix:not-a-size:$snapshot_suffix"
require_snapshot_rejection noncanonical-size \
    "$snapshot_prefix:01:$snapshot_suffix"

# `dash` preserves the parent's `$$` inside `( ... )`. Build a new /bin/sh
# process around the gate's real limiter so this hard-limit test cannot lower
# the contract runner's own RLIMIT_FSIZE.
proof_limit_runner=$temporary_directory/proof-limit-runner.sh
{
    # Variables in these literal lines expand only in the generated child.
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'export LC_ALL=C' \
        'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
        'export PATH' \
        'umask 077' \
        'proof_file_max_bytes=1048576'
    sed -n '/^install_proof_file_limit() {$/,/^}$/p' "$gate"
    # Variables in these literal lines expand only in the generated child.
    # shellcheck disable=SC2016
    printf '%s\n' \
        '[ "$#" -eq 1 ] || exit 64' \
        'boundary_file=$1' \
        '[ ! -e "$boundary_file" ] && [ ! -L "$boundary_file" ] || exit 1' \
        'if install_proof_file_limit; then exit 1; fi' \
        'if install_proof_file_limit 1048575; then exit 1; fi' \
        'if install_proof_file_limit "$proof_file_max_bytes" extra; then exit 1; fi' \
        'install_proof_file_limit "$proof_file_max_bytes"' \
        'observed_limit=$(prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD | awk '\''NF == 2 { print $1 ":" $2 }'\'')' \
        '[ "$observed_limit" = "$proof_file_max_bytes:$proof_file_max_bytes" ]' \
        'dd if=/dev/zero of="$boundary_file" bs="$proof_file_max_bytes" count=1 status=none' \
        '[ "$(stat -Lc '\''%s'\'' "$boundary_file")" -eq "$proof_file_max_bytes" ]' \
        'set +e' \
        'dd if=/dev/zero of="$boundary_file" bs=1 count=1 oflag=append conv=notrunc status=none 2>/dev/null' \
        'extra_status=$?' \
        'set -e' \
        '[ "$extra_status" -ne 0 ]' \
        '[ "$(stat -Lc '\''%s'\'' "$boundary_file")" -eq "$proof_file_max_bytes" ]'
} >"$proof_limit_runner"
if [ "$(grep -c '^install_proof_file_limit() {$' "$proof_limit_runner")" -ne 1 ]; then
    printf '%s\n' 'the proof file-size limiter cannot be isolated' >&2
    exit 1
fi
chmod 0700 "$proof_limit_runner"
sh -n "$proof_limit_runner"
parent_fsize_before=$(
    prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD \
        | awk 'NF == 2 { print $1 ":" $2 }'
)
case $parent_fsize_before in
    ''|*:|:*|*:*:*)
        printf '%s\n' 'the parent file-size limit is not observable' >&2
        exit 1
        ;;
esac
proof_limit_boundary=$temporary_directory/proof-limit-boundary
expect_status 0 /bin/sh "$proof_limit_runner" "$proof_limit_boundary"
parent_fsize_after=$(
    prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD \
        | awk 'NF == 2 { print $1 ":" $2 }'
)
if [ "$parent_fsize_before" != "$parent_fsize_after" ]; then
    printf '%s\n' 'the child limiter changed the contract runner file-size limit' >&2
    exit 1
fi
if [ "$(stat -Lc '%F:%u:%a:%h:%s' "$proof_limit_boundary")" \
    != "regular file:$(id -u):600:1:1048576" ]; then
    printf '%s\n' 'the proof-limit boundary write did not fail closed at exactly 1 MiB' >&2
    exit 1
fi

resolver_fixture=$temporary_directory/resolver-fixture
mkdir -m 0700 "$resolver_fixture"
resolver_runtime_directory=$(mktemp -d /tmp/volparossa-resolver-runtime.XXXXXX)
case $resolver_runtime_directory in
    /tmp/volparossa-resolver-runtime.??????) ;;
    *)
        printf 'unsafe resolver runtime fixture path: %s\n' \
            "$resolver_runtime_directory" >&2
        exit 1
        ;;
esac
chmod 0755 "$resolver_runtime_directory"
resolver_allowed_roots="$temporary_directory $resolver_runtime_directory"
resolver_runtime_uid=$(id -u)
resolver_runtime_gid=$(id -g)
resolver_other_capture_uid=0
if [ "$resolver_runtime_gid" -eq 0 ]; then
    resolver_other_capture_gid=1
else
    resolver_other_capture_gid=0
fi
if [ "$resolver_runtime_uid" -eq 1 ]; then
    resolver_wrong_runtime_uid=2
else
    resolver_wrong_runtime_uid=1
fi
if [ "$resolver_runtime_gid" -eq 1 ]; then
    resolver_wrong_runtime_gid=2
else
    resolver_wrong_runtime_gid=1
fi

resolver_regular=$resolver_fixture/regular.conf
printf '%s\n' 'nameserver 192.0.2.53' >"$resolver_regular"
chmod 0600 "$resolver_regular"
resolver_regular_snapshot=$temporary_directory/resolver-regular.snapshot
vp_capture_resolver_snapshot "$resolver_regular" "$resolver_regular_snapshot" \
    "$resolver_fixture" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_regular_snapshot"
grep -Fx REGULAR "$resolver_regular_snapshot" >/dev/null
grep -Fx "$resolver_regular" "$resolver_regular_snapshot" >/dev/null

resolver_symlink_target=$resolver_fixture/symlink-target.conf
printf '%s\n' 'nameserver 2001:db8::53' >"$resolver_symlink_target"
chmod 0600 "$resolver_symlink_target"
resolver_symlink=$resolver_fixture/resolv.conf
ln -s symlink-target.conf "$resolver_symlink"
resolver_symlink_snapshot=$temporary_directory/resolver-symlink.snapshot
vp_capture_resolver_snapshot "$resolver_symlink" "$resolver_symlink_snapshot" \
    "$resolver_fixture" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_symlink_snapshot"
grep -Fx symlink-target.conf "$resolver_symlink_snapshot" >/dev/null
grep -Fx "$resolver_symlink_target" "$resolver_symlink_snapshot" >/dev/null

# Model Debian's managed /etc/resolv.conf -> .../stub-resolv.conf authority split.
resolver_managed_stub=$resolver_runtime_directory/stub-resolv.conf
printf '%s\n' 'nameserver 127.0.0.53' >"$resolver_managed_stub"
chmod 0644 "$resolver_managed_stub"
resolver_managed_link=$resolver_fixture/managed-resolv.conf
ln -s "$resolver_managed_stub" "$resolver_managed_link"
resolver_managed_snapshot=$temporary_directory/resolver-managed.snapshot
vp_capture_resolver_snapshot "$resolver_managed_link" "$resolver_managed_snapshot" \
    "$resolver_allowed_roots" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_managed_snapshot"
grep -Fx "$resolver_managed_stub" "$resolver_managed_snapshot" >/dev/null
resolver_managed_runtime_link=$resolver_runtime_directory/managed-resolv.conf
ln -s stub-resolv.conf "$resolver_managed_runtime_link"

resolver_managed_observation_gate() {
    (
        VP_CAPTURE_OWNER_UID=$resolver_other_capture_uid
        VP_CAPTURE_OWNER_GID=$resolver_other_capture_gid
        export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
        vp_capture_resolver_observation "$resolver_managed_runtime_link" \
            "$resolver_allowed_roots" "$resolver_runtime_directory" \
            "$resolver_runtime_uid" "$resolver_runtime_gid" >/dev/null || exit 77
    )
}
expect_status 0 resolver_managed_observation_gate

resolver_managed_uplink=$resolver_runtime_directory/resolv.conf
printf '%s\n' 'nameserver 192.0.2.60' >"$resolver_managed_uplink"
chmod 0644 "$resolver_managed_uplink"
resolver_managed_uplink_snapshot=$temporary_directory/resolver-managed-uplink.snapshot
vp_capture_resolver_snapshot "$resolver_managed_uplink" \
    "$resolver_managed_uplink_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_managed_uplink_snapshot"
grep -Fx "$resolver_managed_uplink" "$resolver_managed_uplink_snapshot" >/dev/null

resolver_unsafe_object_parent=$resolver_fixture/unsafe-object-parent
mkdir -m 0777 "$resolver_unsafe_object_parent"
resolver_unsafe_object=$resolver_unsafe_object_parent/resolv.conf
ln -s "$resolver_managed_stub" "$resolver_unsafe_object"
resolver_unsafe_object_snapshot=$temporary_directory/resolver-unsafe-object.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_object" \
    "$resolver_unsafe_object_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver symlink below a writable object parent was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_object_snapshot" ]; then
    printf '%s\n' 'unsafe resolver object parent left a partial snapshot' >&2
    exit 1
fi

# The service UID/GID grants authority only below the one explicit runtime directory.
resolver_authority_outside=$(mktemp /tmp/volparossa-resolver-authority-outside.XXXXXX)
case $resolver_authority_outside in
    /tmp/volparossa-resolver-authority-outside.??????) ;;
    *)
        printf 'unsafe resolver authority fixture path: %s\n' \
            "$resolver_authority_outside" >&2
        exit 1
        ;;
esac
printf '%s\n' 'nameserver 192.0.2.56' >"$resolver_authority_outside"
chmod 0600 "$resolver_authority_outside"
resolver_outside_authority_gate() {
    (
        VP_CAPTURE_OWNER_UID=$resolver_other_capture_uid
        VP_CAPTURE_OWNER_GID=$resolver_other_capture_gid
        export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
        vp_capture_resolver_observation "$resolver_authority_outside" /tmp \
            "$resolver_runtime_directory" "$resolver_runtime_uid" \
            "$resolver_runtime_gid" >/dev/null || exit 77
    )
}
expect_status 77 resolver_outside_authority_gate
rm -f -- "$resolver_authority_outside"
resolver_authority_outside=

resolver_wrong_uid_snapshot=$temporary_directory/resolver-wrong-uid.snapshot
if vp_capture_resolver_snapshot "$resolver_managed_link" \
    "$resolver_wrong_uid_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_wrong_runtime_uid" \
    "$resolver_runtime_gid"; then
    printf '%s\n' 'managed resolver target with the wrong authority UID was accepted' >&2
    exit 1
fi
if [ -e "$resolver_wrong_uid_snapshot" ]; then
    printf '%s\n' 'wrong resolver authority UID left a partial snapshot' >&2
    exit 1
fi

resolver_wrong_gid_snapshot=$temporary_directory/resolver-wrong-gid.snapshot
if vp_capture_resolver_snapshot "$resolver_managed_link" \
    "$resolver_wrong_gid_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" \
    "$resolver_wrong_runtime_gid"; then
    printf '%s\n' 'managed resolver target with the wrong authority GID was accepted' >&2
    exit 1
fi
if [ -e "$resolver_wrong_gid_snapshot" ]; then
    printf '%s\n' 'wrong resolver authority GID left a partial snapshot' >&2
    exit 1
fi

resolver_writable_target_runtime=$resolver_fixture/writable-target-runtime
mkdir -m 0755 "$resolver_writable_target_runtime"
resolver_unsafe_target=$resolver_writable_target_runtime/stub-resolv.conf
printf '%s\n' 'nameserver 198.51.100.53' >"$resolver_unsafe_target"
chmod 0666 "$resolver_unsafe_target"
resolver_unsafe_snapshot=$temporary_directory/resolver-unsafe.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_target" "$resolver_unsafe_snapshot" \
    "$temporary_directory" "$resolver_writable_target_runtime" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'writable resolver target was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_snapshot" ]; then
    printf '%s\n' 'rejected resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_writable_runtime=$resolver_fixture/writable-runtime
mkdir -m 0777 "$resolver_writable_runtime"
resolver_writable_runtime_target=$resolver_writable_runtime/stub-resolv.conf
printf '%s\n' 'nameserver 192.0.2.57' >"$resolver_writable_runtime_target"
chmod 0644 "$resolver_writable_runtime_target"
resolver_writable_runtime_snapshot=$temporary_directory/resolver-writable-runtime.snapshot
if vp_capture_resolver_snapshot "$resolver_writable_runtime_target" \
    "$resolver_writable_runtime_snapshot" "$temporary_directory" \
    "$resolver_writable_runtime" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'writable resolver runtime directory was accepted' >&2
    exit 1
fi
if [ -e "$resolver_writable_runtime_snapshot" ]; then
    printf '%s\n' 'writable resolver runtime directory left a partial snapshot' >&2
    exit 1
fi

resolver_hardlinked_runtime=$resolver_fixture/hardlinked-runtime
mkdir -m 0755 "$resolver_hardlinked_runtime"
resolver_hardlinked_target=$resolver_hardlinked_runtime/stub-resolv.conf
printf '%s\n' 'nameserver 192.0.2.58' >"$resolver_hardlinked_target"
chmod 0644 "$resolver_hardlinked_target"
ln "$resolver_hardlinked_target" "$resolver_fixture/hardlinked-resolv.peer"
resolver_hardlinked_snapshot=$temporary_directory/resolver-hardlinked.snapshot
if vp_capture_resolver_snapshot "$resolver_hardlinked_target" \
    "$resolver_hardlinked_snapshot" "$temporary_directory" \
    "$resolver_hardlinked_runtime" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'hard-linked resolver target was accepted' >&2
    exit 1
fi
if [ -e "$resolver_hardlinked_snapshot" ]; then
    printf '%s\n' 'hard-linked resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_oversize_runtime=$resolver_fixture/oversize-runtime
mkdir -m 0755 "$resolver_oversize_runtime"
resolver_oversize_target=$resolver_oversize_runtime/stub-resolv.conf
dd if=/dev/zero of="$resolver_oversize_target" bs=65537 count=1 2>/dev/null
chmod 0644 "$resolver_oversize_target"
resolver_oversize_snapshot=$temporary_directory/resolver-oversize.snapshot
if vp_capture_resolver_snapshot "$resolver_oversize_target" \
    "$resolver_oversize_snapshot" "$temporary_directory" \
    "$resolver_oversize_runtime" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver target larger than 64 KiB was accepted' >&2
    exit 1
fi
if [ -e "$resolver_oversize_snapshot" ]; then
    printf '%s\n' 'oversized resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_runtime_symlink_target=$resolver_fixture/runtime-symlink-target
mkdir -m 0755 "$resolver_runtime_symlink_target"
printf '%s\n' 'nameserver 192.0.2.59' \
    >"$resolver_runtime_symlink_target/stub-resolv.conf"
chmod 0644 "$resolver_runtime_symlink_target/stub-resolv.conf"
resolver_runtime_symlink=$resolver_fixture/runtime-symlink
ln -s runtime-symlink-target "$resolver_runtime_symlink"
resolver_runtime_symlink_snapshot=$temporary_directory/resolver-runtime-symlink.snapshot
if vp_capture_resolver_snapshot "$resolver_runtime_symlink/stub-resolv.conf" \
    "$resolver_runtime_symlink_snapshot" "$temporary_directory" \
    "$resolver_runtime_symlink" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'symlinked resolver runtime directory was accepted' >&2
    exit 1
fi
if [ -e "$resolver_runtime_symlink_snapshot" ]; then
    printf '%s\n' 'symlinked resolver runtime directory left a partial snapshot' >&2
    exit 1
fi

resolver_outside=$temporary_directory/resolver-outside.conf
printf '%s\n' 'nameserver 203.0.113.53' >"$resolver_outside"
chmod 0600 "$resolver_outside"
resolver_outside_link=$resolver_fixture/outside.conf
ln -s "$resolver_outside" "$resolver_outside_link"
resolver_outside_snapshot=$temporary_directory/resolver-outside.snapshot
if vp_capture_resolver_snapshot "$resolver_outside_link" "$resolver_outside_snapshot" \
    "$resolver_fixture" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver target outside the allowed root was accepted' >&2
    exit 1
fi
if [ -e "$resolver_outside_snapshot" ]; then
    printf '%s\n' 'rejected outside resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_unsafe_parent=$resolver_fixture/unsafe-parent
mkdir -m 0777 "$resolver_unsafe_parent"
resolver_unsafe_parent_target=$resolver_unsafe_parent/resolv.conf
printf '%s\n' 'nameserver 192.0.2.54' >"$resolver_unsafe_parent_target"
chmod 0600 "$resolver_unsafe_parent_target"
resolver_unsafe_parent_snapshot=$temporary_directory/resolver-unsafe-parent.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_parent_target" \
    "$resolver_unsafe_parent_snapshot" "$resolver_fixture" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver target below an unsafe parent was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_parent_snapshot" ]; then
    printf '%s\n' 'unsafe-parent rejection left a partial resolver snapshot' >&2
    exit 1
fi

resolver_drift_target=$resolver_fixture/drift.conf
printf '%s\n' 'nameserver 192.0.2.55' >"$resolver_drift_target"
chmod 0600 "$resolver_drift_target"
resolver_drift_snapshot=$temporary_directory/resolver-drift.snapshot
resolver_drift_gate() {
    (
        # ShellCheck cannot see the indirect call through the sourced capture helper.
        # shellcheck disable=SC2317
        vp_capture_sha256_file() {
            drift_checksum_line=$(command sha256sum "$1") || return 1
            drift_checksum=$(vp_capture_checksum_from_line "$drift_checksum_line") || return 1
            printf '%s\n' '# injected drift' >>"$1" || return 1
            printf '%s\n' "$drift_checksum"
        }
        vp_capture_resolver_snapshot "$resolver_drift_target" "$resolver_drift_snapshot" \
            "$resolver_fixture" "$resolver_runtime_directory" \
            "$resolver_runtime_uid" "$resolver_runtime_gid" || exit 77
    )
}

expect_status 77 producer_failure_gate
if [ -e "$temporary_directory/producer-failure.raw" ] \
    || [ -e "$temporary_directory/producer-failure.digest" ]; then
    printf '%s\n' 'failed producer left hashable or published capture state' >&2
    exit 1
fi
expect_status 77 parser_failure_gate
if [ -e "$temporary_directory/parser-failure.normalized" ] \
    || [ -e "$temporary_directory/parser-failure.digest" ]; then
    printf '%s\n' 'failed parser left hashable or published normalized state' >&2
    exit 1
fi
expect_status 77 stream_producer_failure_gate
if [ -e "$temporary_directory/stream-producer-failure.fifo" ] \
    || [ -e "$temporary_directory/stream-producer-failure.digest" ] \
    || [ -e "$temporary_directory/stream-producer-failure.digest.consumer" ]; then
    printf '%s\n' 'failed secret producer left a FIFO, digest, or consumer record' >&2
    exit 1
fi
expect_status 77 stream_hasher_failure_gate
if [ -e "$temporary_directory/stream-hasher-failure.fifo" ] \
    || [ -e "$temporary_directory/stream-hasher-failure.digest" ] \
    || [ -e "$temporary_directory/stream-hasher-failure.digest.consumer" ]; then
    printf '%s\n' 'failed secret hasher left a FIFO, digest, or consumer record' >&2
    exit 1
fi
expect_status 77 resolver_drift_gate
if [ -e "$resolver_drift_snapshot" ]; then
    printf '%s\n' 'resolver drift left a partial snapshot' >&2
    exit 1
fi

expect_status 0 "$gate"
default_preview=$last_stdout
if [ -s "$last_stderr" ]; then
    printf '%s\n' 'default preview wrote standard error' >&2
    exit 1
fi
expected_preview=$temporary_directory/expected-preview
printf '%s\n' \
    'VOLPAROSSA live worker-identity proof plan:' \
    '  require a disposable Debian 13 amd64 VM, root, and the exact systemd v257 manager;' \
    '  bookend one unchanged clean Git revision and three exact staged artifact hashes;' \
    '  copy the already-built real helper into one validated root-only temporary stage;' \
    '  create synthetic, collision-free agent/worker/group records only inside that stage;' \
    '  bind account files and the system bus socket read-only in two sequential invocations;' \
    '  pin its D-Bus system address to that verified socket inside the private /run;' \
    '  run with PrivateNetwork=yes, a private temporary /run, and no host account changes;' \
    '  require the host /run/volparossa path absent before and after both private unit runs;' \
    '  set NotifyAccess=main, FileDescriptorStoreMax=128, and' \
    '    FileDescriptorStorePreserve=yes on that transient service;' \
    '  grant exactly CAP_KILL, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SETGID, CAP_SETPCAP,' \
    '    CAP_SETUID, and CAP_SYS_ADMIN to the helper parent;' \
    '  bound both large build-artifact staging copies at 128 MiB, then cap' \
    '    the proof process and every transient-unit file write at 1 MiB;' \
    '  cap the production runtime at three minutes;' \
    '  discard production runtime stdout and stderr through exact systemd null streams;' \
    '  require its kernel supplementary-group vector to contain only the staged agent GID;' \
    '  invoke only --internal-worker-v3-live-proof and require its exact two success records;' \
    '  after main exit require exactly two descriptors in the systemd descriptor store;' \
    '  bind normal retirement to the exact JSON InvocationID returned for that run;' \
    '  recover tentative ownership only from its exact marker and current nonzero manager ID;' \
    '  stop, clean only its fdstore, and collect that exact first invocation;' \
    '  only after the unit is not-found, reuse its random name with a new exact marker and ID;' \
    '  run the argumentless production helper and fixed IPC probe inside the confined unit;' \
    '  require stable Bind identity, bounded malformed-frame and wire-shape rejection,' \
    '    exact peer PID/UID/GID rejection, stable socket inode/token metadata, and zero fdstore;' \
    '  preserve one MainPID and InvocationID throughout those checks, then require clean' \
    '    SIGTERM, an unchanged journal, one held-then-unlocked lock inode, and removed socket;' \
    '  collect that exact second invocation and remove the validated temporary stage;' \
    '  compare privacy-safe before/after host account, resolver, mount, firewall, WireGuard,' \
    '    and network digests;' \
    '  validate one bounded canonical evidence-v1 report before publishing only that JSON.' \
    'This stages the helper identity and production IPC boundary. It creates no host account, link,' \
    'route, firewall rule, WireGuard device, DNS change, sysctl change, or VPN datapath.' \
    'It is not package-install, restart-recovery, CleanupOwned, datapath, or A01-A15 evidence.' \
    'PREVIEW ONLY: no file, account, service, or network state was changed.' \
    >"$expected_preview"
if ! cmp -s "$expected_preview" "$default_preview"; then
    printf '%s\n' 'default preview does not match the exact reviewed plan' >&2
    exit 1
fi

expect_status 0 "$gate" --preview
if ! cmp -s "$default_preview" "$last_stdout" || [ -s "$last_stderr" ]; then
    printf '%s\n' 'explicit and default previews are not byte-identical' >&2
    exit 1
fi

expect_status 0 "$gate" --help
grep -F 'usage: tests/helper/require-live-worker-identity-proof.sh' "$last_stdout" >/dev/null
expect_status 64 "$gate" --execute
grep -Fx 'Execution requires --yes after reviewing the exact plan.' "$last_stderr" >/dev/null
if [ -s "$last_stdout" ]; then
    printf '%s\n' 'unapproved execute request wrote non-JSON standard output' >&2
    exit 1
fi
expect_status 64 "$gate" --preview --yes
expect_status 64 "$gate" --preview --execute
expect_status 64 "$gate" --execute --execute
expect_status 64 "$gate" --execute --yes --yes
expect_status 64 "$gate" --unknown

find /var/tmp -maxdepth 1 -name 'volparossa-helper-live-proof.*' -printf '%f\n' \
    | sort >"$temporary_directory/stages.before"
expect_status 77 "$gate" --execute --yes
if [ -s "$last_stdout" ]; then
    printf '%s\n' 'blocked execute request wrote non-JSON standard output' >&2
    exit 1
fi
grep -Fx 'VOLPAROSSA live worker-identity proof plan:' "$last_stderr" >/dev/null
if grep -F 'PREVIEW ONLY:' "$last_stderr" >/dev/null; then
    printf '%s\n' 'approved execution printed a preview-only claim' >&2
    exit 1
fi
grep -Fx 'BLOCKED: execution requires root inside the disposable VM' "$last_stderr" >/dev/null
find /var/tmp -maxdepth 1 -name 'volparossa-helper-live-proof.*' -printf '%f\n' \
    | sort >"$temporary_directory/stages.after"
if ! cmp -s "$temporary_directory/stages.before" "$temporary_directory/stages.after"; then
    printf '%s\n' 'unprivileged refusal created a temporary proof stage' >&2
    exit 1
fi

if ! awk '
    /^if \[ "\$approval" != yes \]; then$/ { approval_guard = NR }
    /^print_plan >&2$/ { execute_plan = NR }
    /^if \[ "\$\(id -u\)" -ne 0 \]; then$/ { root_preflight = NR }
    END {
        if (!(approval_guard < execute_plan && execute_plan < root_preflight)) exit 1
    }
' "$gate"; then
    printf '%s\n' 'execute plan is not ordered between approval and preflight' >&2
    exit 1
fi

if ! awk '
    /^[[:space:]]*systemd-run \\$/ {
        run_count++
        if (run_count == 1) first_run = NR
        if (run_count == 2) second_run = NR
    }
    /^worker_unit_name=\$unit_name$/ { first_identity_saved = NR }
    /^        unit_name=\$worker_unit_name$/ { name_reused = NR }
    /if \[ "\$reuse_load_state" != not-found \]/ { not_found_required = NR }
    /VOLPAROSSA helper production IPC transient ownership marker v1/ {
        production_marker = NR
    }
    END {
        valid = run_count == 2 && first_run < first_identity_saved
        valid = valid && first_identity_saved < name_reused
        valid = valid && name_reused < not_found_required
        valid = valid && not_found_required < production_marker
        valid = valid && production_marker < second_run
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'production IPC phase does not follow collected not-found worker proof' >&2
    exit 1
fi

if ! awk '
    /^adopt_tentative_unit\(\) \{$/ { in_adopt = 1; next }
    in_adopt && /^\}$/ { in_adopt = 0 }
    in_adopt && /adopted_invocation_id=\$\(unit_current_invocation_id/ { id_read = NR }
    in_adopt && id_read > 0 && /unit_description_matches_marker \|\| return 1/ {
        marker_after_id = NR
    }
    in_adopt && /unit_owned=yes/ { ownership_commit = NR }
    END {
        if (!(id_read > 0 && id_read < marker_after_id && marker_after_id < ownership_commit)) {
            exit 1
        }
    }
' "$gate"; then
    printf '%s\n' 'tentative unit adoption does not recheck its marker after the ID read' >&2
    exit 1
fi

# These are literal source contracts; expansion here would defeat the check.
# shellcheck disable=SC2016
for required_contract in \
    'paste prlimit readlink rm sed setpriv' \
    'staged_executable_max_bytes=134217728' \
    'proof_file_max_bytes=1048576' \
    'source_snapshot_is_exact() {' \
    'install_proof_file_limit() {' \
    'source_snapshot_is_exact "$source_before" 755 "$staged_executable_max_bytes"' \
    'source_snapshot_is_exact "$ipc_probe_before" 755 "$staged_executable_max_bytes"' \
    'source_snapshot_is_exact "$ipc_hook_before" 700 "$proof_file_max_bytes"' \
    'source_snapshot_is_exact "$ipc_hook_before" 750 "$proof_file_max_bytes"' \
    'source_snapshot_is_exact "$ipc_hook_before" 755 "$proof_file_max_bytes"' \
    '[ "$source_before" != "$helper_initial_snapshot" ]' \
    '[ "$ipc_probe_before" != "$ipc_probe_initial_snapshot" ]' \
    '[ "$ipc_hook_before" = "$ipc_hook_initial_snapshot" ]' \
    'prlimit --fsize="$staged_executable_max_bytes:$staged_executable_max_bytes" --' \
    'install_proof_file_limit "$proof_file_max_bytes"' \
    'prlimit --pid "$$" --fsize="$1:$1"' \
    'prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD' \
    '--property=PrivateNetwork=yes' \
    '--property=PrivateMounts=yes' \
    '--property=NoNewPrivileges=yes' \
    '--property=LimitCORE=0' \
    '--property=LimitFSIZE=1048576' \
    '--property=NotifyAccess=main' \
    '--property=FileDescriptorStoreMax=128' \
    '--property=FileDescriptorStorePreserve=yes' \
    '--property=TimeoutStartSec=45s' \
    '--property=TimeoutStartSec=90s' \
    '--property=TimeoutStopSec=45s' \
    '--service-type=exec' \
    '--property=Restart=no' \
    '--property=RuntimeMaxSec=180s' \
    '--property=StandardOutput=null' \
    '--property=StandardError=null' \
    '--property=KillSignal=SIGTERM' \
    '--json=short' \
    '--ignore-failure' \
    '--description="$unit_ownership_marker"' \
    '--property="CapabilityBoundingSet=$capabilities"' \
    '--property="AmbientCapabilities=$capabilities"' \
    '--property="BindReadOnlyPaths=$helper_bind $account_binds $system_bus_bind"' \
    '--property="BindReadOnlyPaths=$production_helper_bind $production_probe_bind $production_hook_bind $account_binds $system_bus_bind"' \
    '--property="BindPaths=$production_runtime_bind $production_output_bind"' \
    '--property="ExecStartPost=/run/volparossa-helper-production-ipc-hook start $unit_name $agent_uid $agent_gid $operator_gid $worker_uid $worker_gid"' \
    '--property="ExecStopPost=/run/volparossa-helper-production-ipc-hook stop $unit_name $agent_gid"' \
    'install -d -o root -g root -m 2700 "$temporary_stage/production-output"' \
    '--property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket' \
    'system_bus_socket=/run/dbus/system_bus_socket' \
    'host_runtime_directory=/run/volparossa' \
    "blocked 'the disposable host /run/volparossa path must initially be absent'" \
    'state_records='"'"'production_runtime_path accounts namespaces mounts resolver sysctls links addresses routes rules nexthops qdiscs nftables wireguard legacy_ipv4_firewall legacy_ipv6_firewall'"'"'' \
    "failed 'the host /run/volparossa path is not absent at a state fence'" \
    'systemctl show --property=Version --value' \
    "blocked 'execution requires exact systemd v257'" \
    'capture_unit_property Environment "$temporary_stage/unit-environment"' \
    '!= DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket ]' \
    'parsed_invocation_id=$(jq -ers --arg expected_unit "$unit_name"' \
    'and (.[0] | keys) == ["invocation_id", "unit"]' \
    'unit_invocation_id=$parsed_invocation_id' \
    'unit_owned=yes' \
    'unit_may_own=yes' \
    'unit_may_own=no' \
    'VOLPAROSSA helper live proof transient ownership marker v1' \
    'VOLPAROSSA helper production IPC transient ownership marker v1' \
    'unit_description_matches_marker' \
    'adopt_tentative_unit' \
    '[ "$adopt_attempt" -lt 1000 ]' \
    'unit_invocation_is_current || return 1' \
    'if ! unit_invocation_is_current; then' \
    'forget_unit_ownership' \
    'capture_unit_property Description "$temporary_stage/unit-description"' \
    '[ "$observed_description" != "$unit_ownership_marker" ]' \
    'capture_unit_property NFileDescriptorStore "$temporary_stage/unit-fdstore-count"' \
    'capture_unit_property ControlGroup "$temporary_stage/unit-control-group"' \
    'capture_unit_property ControlGroup "$temporary_stage/production-control-group"' \
    'capture_unit_property RuntimeMaxUSec' \
    'capture_unit_property LimitFSIZE "$temporary_stage/production-limit-fsize"' \
    'capture_unit_property LimitFSIZESoft' \
    'capture_unit_property StandardOutput' \
    'capture_unit_property StandardError' \
    '[ "$observed_fdstore_count" != 2 ]' \
    '[ "$production_fdstore_count" != 0 ]' \
    '[ "$production_runtime_max" != 3min ]' \
    '[ "$production_limit_fsize" != 1048576 ]' \
    '[ "$production_limit_fsize_soft" != 1048576 ]' \
    '[ "$production_standard_output" != null ]' \
    '[ "$production_standard_error" != null ]' \
    'production_socket_identity_file=$temporary_stage/production-output/socket.identity' \
    'production_lock_identity_file=$temporary_stage/production-output/lock.identity' \
    'production_lock_fd_identity=$(stat -Lc' \
    '/usr/bin/flock -n 9' \
    'systemctl stop --no-block "$unit_name"' \
    'systemctl show --property=Job --value "$unit_name"' \
    'systemctl clean --what=fdstore "$unit_name"' \
    '[ "$retire_fdstore_count" -eq 0 ]' \
    '[ "$retire_load_state" = not-found ]' \
    '[ "$retire_attempt" -lt 1200 ]' \
    '[ "$poll_attempt" -ge 2000 ]' \
    'retired_runtime_is_absent' \
    'retired_cgroup_path=/sys/fs/cgroup$retired_control_group' \
    '[ "$retired_attempt" -lt 1200 ]' \
    '"/proc/$retired_main_pid/exe"' \
    '[ "$poll_attempt" -ge 1000 ]' \
    'systemctl reset-failed "$unit_name"' \
    '--internal-worker-v3-live-proof' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass' \
    'VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass' \
    'evidence_validator=$script_directory/validate-helper-boundary-evidence-v1.sh' \
    'status --porcelain=v1 --untracked-files=normal' \
    "blocked 'the source worktree must be clean before live evidence execution'" \
    "failed 'the exact clean source revision changed during live execution'" \
    'jq -n -S -c' \
    '"$evidence_validator" "$report_path" >"$validator_stdout" 2>"$validator_stderr"' \
    '[ "$validator_status" -ne 0 ]' \
    '[ -s "$validator_stdout" ]' \
    '[ -s "$validator_stderr" ]' \
    'validated_report=$(cat "$report_path")' \
    "failed 'the exact clean source revision changed before report publication'" \
    'if ! remove_temporary_stage; then' \
    'printf '\''%s\n'\'' "$validated_report"'
do
    grep -F -- "$required_contract" "$gate" >/dev/null || {
        printf 'missing live helper proof contract: %s\n' "$required_contract" >&2
        exit 1
    }
done
if ! awk '
    /^[[:space:]]*resolver_runtime_uid=\$\(/ { runtime_uid_derived = NR }
    /^[[:space:]]*resolver_runtime_gid=\$\(/ { runtime_gid_derived = NR }
    {
        logical_line = $0
        logical_continues = logical_line ~ /\\[[:space:]]*$/
        sub(/[[:space:]]*\\[[:space:]]*$/, " ", logical_line)
        logical_statement = logical_statement " " logical_line
        if (logical_continues) next
        if (logical_statement ~ /vp_capture_resolver_snapshot \/etc\/resolv[.]conf/) {
            resolver_calls++
            if (index(logical_statement, "\"$resolver_object_capture\"") > 0 \
                && index(logical_statement, "/etc /run") > 0 \
                && index(logical_statement, \
                    "/run/systemd/resolve \"$resolver_runtime_uid\" \"$resolver_runtime_gid\"") \
                    > 0) {
                explicit_authority_call = NR
            }
        }
        logical_statement = ""
    }
    END {
        valid = resolver_calls == 1 && runtime_uid_derived > 0 && runtime_gid_derived > 0
        valid = valid && explicit_authority_call > runtime_uid_derived
        valid = valid && explicit_authority_call > runtime_gid_derived
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' \
        'live resolver capture lacks one literal runtime authority and derived UID/GID pair' >&2
    exit 1
fi
if ! awk '
    /if \[ "\$proof_ok" != yes \]; then/ { proof_gate = NR }
    /final_source_commit=\$\(git / { source_revalidation = NR }
    /^jq -n -S -c \\/ { report_generation = NR }
    /^"\$evidence_validator" "\$report_path" >/ { report_validation = NR }
    /^validator_status=\$\?$/ { validator_status = NR }
    /if ! vp_capture_file_is_safe "\$validator_stdout"/ { validator_gate = NR }
    /validated_report=\$\(cat "\$report_path"\)/ { retained_report = NR }
    /publication_source_commit=\$\(git / { publication_fence = NR }
    /if ! remove_temporary_stage; then/ { stage_removal = NR }
    /^printf '\''%s\\n'\'' "\$validated_report"$/ { publication = NR }
    END {
        valid = proof_gate > 0 && source_revalidation > 0 && report_generation > 0
        valid = valid && report_validation > 0 && validator_status > 0
        valid = valid && validator_gate > 0 && retained_report > 0
        valid = valid && publication_fence > 0 && stage_removal > 0 && publication > 0
        valid = valid && proof_gate < source_revalidation
        valid = valid && source_revalidation < report_generation
        valid = valid && report_generation < report_validation
        valid = valid && report_validation < validator_status
        valid = valid && validator_status < validator_gate
        valid = valid && validator_gate < retained_report
        valid = valid && retained_report < publication_fence
        valid = valid && publication_fence < stage_removal
        valid = valid && stage_removal < publication
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'validated report publication is not ordered after proof and stage removal' >&2
    exit 1
fi
if [ "$(grep -Fc -- '--property=LimitFSIZE=1048576' "$gate")" -ne 2 ]; then
    printf '%s\n' 'both transient helper invocations do not have the exact file-size limit' >&2
    exit 1
fi
# This is a literal gate-source contract, not a test-shell expansion.
# shellcheck disable=SC2016
if [ "$(grep -Fc -- \
    'prlimit --fsize="$staged_executable_max_bytes:$staged_executable_max_bytes" --' \
    "$gate")" -ne 2 ]; then
    printf '%s\n' 'both large staging copies do not have the exact 128 MiB limit' >&2
    exit 1
fi
# This is a literal gate-source regular expression.
# shellcheck disable=SC1003,SC2016
if [ "$(grep -Ec '^install_proof_file_limit "\$proof_file_max_bytes" \\' \
    "$gate")" -ne 1 ]; then
    printf '%s\n' 'the proof process does not install its exact 1 MiB limit once' >&2
    exit 1
fi
if [ "$(grep -Ec '^[[:space:]]*prlimit --pid "\$\$" --fsize=' "$gate")" -ne 1 ]; then
    printf '%s\n' 'the proof source changes its own file-size limit more than once' >&2
    exit 1
fi
if ! awk '
    /failed '\''the bounded helper staging copy failed'\''/ { helper_copy = NR }
    /failed '\''the real helper changed while copied or the staged image is unsafe'\''/ {
        helper_fence = NR
    }
    /failed '\''the bounded production IPC probe staging copy failed'\''/ {
        probe_copy = NR
    }
    /failed '\''the production IPC probe changed while copied or its staged image is unsafe'\''/ {
        probe_fence = NR
    }
    /^install_proof_file_limit "\$proof_file_max_bytes" \\/ { proof_limit = NR }
    /^ipc_hook_before=/ { hook_copy = NR }
    /'\''root:x:0:0:root:\/root:\/bin\/sh'\''/ { account_write = NR }
    /^capture_host_state "\$temporary_stage\/before"$/ { host_capture = NR }
    /^[[:space:]]*systemd-run \\/ && first_unit == 0 { first_unit = NR }
    END {
        valid = helper_copy > 0 && helper_fence > 0 && probe_copy > 0
        valid = valid && probe_fence > 0 && proof_limit > 0 && hook_copy > 0
        valid = valid && account_write > 0 && host_capture > 0 && first_unit > 0
        valid = valid && helper_copy < helper_fence && helper_fence < probe_copy
        valid = valid && probe_copy < probe_fence && probe_fence < proof_limit
        valid = valid && proof_limit < hook_copy && hook_copy < account_write
        valid = valid && account_write < host_capture && host_capture < first_unit
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'the two-tier staging and proof-file limits are ordered incorrectly' >&2
    exit 1
fi
for exact_cgroup_property in \
    '--property=ProtectControlGroups=strict' \
    '--property=Delegate=no' \
    '--property=PrivatePIDs=no' \
    "--property='SystemCallFilter=@system-service @network-io seccomp'" \
    "--property='SystemCallFilter=~@mount'"
do
    if [ "$(grep -Fc -- "$exact_cgroup_property" "$gate")" -ne 2 ]; then
        printf 'both transient helper invocations lack exact cgroup isolation: %s\n' \
            "$exact_cgroup_property" >&2
        exit 1
    fi
done
for cgroup_assignment_contract in \
    'ProtectControlGroups=:2' \
    'Delegate=:2' \
    'PrivatePIDs=:2' \
    'SystemCallFilter=:4'
do
    assignment_key=${cgroup_assignment_contract%:*}
    expected_count=${cgroup_assignment_contract##*:}
    observed_count=$(grep -Fc -- "$assignment_key" "$gate")
    if [ "$observed_count" -ne "$expected_count" ]; then
        printf 'transient helper profiles contain extra cgroup assignments: %s expected %s, got %s\n' \
            "$assignment_key" "$expected_count" "$observed_count" >&2
        exit 1
    fi
done
if [ "$(grep -Fc -- '--property=RuntimeMaxSec=180s' "$gate")" -ne 1 ]; then
    printf '%s\n' 'production IPC invocation does not have one exact runtime limit' >&2
    exit 1
fi
if [ "$(grep -Fc -- '--property=StandardOutput=null' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc -- '--property=StandardError=null' "$gate")" -ne 1 ]; then
    printf '%s\n' 'production IPC invocation does not have exact null output streams' >&2
    exit 1
fi
# These are literal source paths; expansion here would defeat the check.
# shellcheck disable=SC2016
if grep -F -- '"$temporary_stage/production.stdout"' "$gate" >/dev/null \
    || grep -F -- '"$temporary_stage/production.stderr"' "$gate" >/dev/null; then
    printf '%s\n' 'production IPC proof still stages runtime output files' >&2
    exit 1
fi

# These are literal hook contracts; expansion here would defeat the check.
# shellcheck disable=SC2016
for required_hook_contract in \
    'runtime_directory=/run/volparossa' \
    'helper_socket=$runtime_directory/helper.sock' \
    'cleanup_token=$runtime_directory/helper.cleanup-token' \
    'probe=/run/volparossa-helper-production-ipc-probe' \
    'production_helper=/run/volparossa-helper-production' \
    "'directory:0:0:2700'" \
    'command_line_is_argumentless "$hook_identity_pid"' \
    'running_identity_is_unchanged "$hook_probe_unit" "$hook_probe_identity"' \
    'capture_socket_identity' \
    'socket_identity_is_unchanged' \
    'capture_lock_identity' \
    'write_private_file "$proof_directory/socket.identity" "$hook_socket_identity"' \
    'write_private_file "$proof_directory/lock.identity" "$hook_lock_identity"' \
    'exec 8<>"$journal_lock"' \
    'hook_active_lock_fd_identity=$(stat -Lc' \
    '/usr/bin/flock -n -x -E 42 8' \
    '[ "$hook_active_flock_status" -eq 42 ]' \
    'running_identity_is_unchanged "$hook_unit" "$proof_directory/unit.identity"' \
    'exec 8>&-' \
    '/usr/bin/setpriv' \
    '--clear-groups' \
    '--groups="$hook_probe_groups"' \
    '--inh-caps=-all' \
    '--ambient-caps=-all' \
    '--bounding-set=-all' \
    '--no-new-privs' \
    '"$hook_expected_main_pid" "$hook_expected_agent_gid"' \
    '[ "$hook_probe_status" -eq 0 ] || return 1' \
    'run_probe bind-before bind-runtime "$agent_uid" "$agent_gid" "$operator_gid"' \
    'run_probe frame-bounds reject-frame-bounds "$agent_uid" "$agent_gid" "$operator_gid"' \
    'run_probe wire-shapes reject-wire-shapes "$agent_uid" "$agent_gid" "$operator_gid"' \
    'run_probe wrong-uid expect-unauthorised-peer "$worker_uid" "$agent_gid" clear' \
    'run_probe wrong-gid expect-unauthorised-peer "$agent_uid" "$operator_gid" "$agent_gid"' \
    'run_probe root-peer expect-unauthorised-peer 0 "$agent_gid" clear' \
    'run_probe bind-after bind-runtime "$agent_uid" "$agent_gid" "$operator_gid"' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_UNAUTHORISED_PEER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
    '[ "${SERVICE_RESULT:-}" = success ]' \
    '[ "${EXIT_CODE:-}" = exited ]' \
    '[ "${EXIT_STATUS:-}" = 0 ]' \
    '[ "$#" -eq 2 ] || fail '"'"'stop hook argument count is invalid'"'"'' \
    'hook_expected_agent_gid=$2' \
    'capture_journal_state' \
    "stat -c '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z'" \
    'hook_expected_lock_identity=$(cat "$proof_directory/lock.identity")' \
    'exec 9<>"$journal_lock"' \
    'hook_lock_fd_identity=$(stat -Lc' \
    '/usr/bin/flock -n 9' \
    'systemctl show --property=NFileDescriptorStore --value' \
    '[ "$hook_fdstore_count" = 0 ]' \
    'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass'
do
    grep -F -- "$required_hook_contract" "$ipc_hook" >/dev/null || {
        printf 'missing production IPC hook contract: %s\n' "$required_hook_contract" >&2
        exit 1
    }
done
if ! awk '
    /^start_hook\(\) \{$/ { in_start = 1; next }
    /^stop_hook\(\) \{$/ { in_start = 0 }
    in_start && /hook_lock_identity=\$\(capture_lock_identity/ { captured = NR }
    in_start && /exec 8<>"\$journal_lock"/ { opened = NR }
    in_start && /hook_active_lock_fd_identity=\$\(stat -Lc/ { fd_identity = NR }
    in_start && /"\$hook_active_lock_fd_identity" = "\$hook_lock_identity"/ {
        fd_compared = NR
    }
    in_start && /hook_active_lock_path_before=\$\(capture_lock_identity/ {
        path_before = NR
    }
    in_start && /"\$hook_active_lock_path_before" = "\$hook_lock_identity"/ {
        path_before_compared = NR
    }
    in_start && /\/usr\/bin\/flock -n -x -E 42 8/ { flocked = NR }
    in_start && /"\$hook_active_flock_status" -eq 42/ { contended = NR }
    in_start && /running_identity_is_unchanged "\$hook_unit"/ {
        identity_count++
        if (identity_count == 1) identity_after_contention = NR
        if (identity_count == 2) identity_after_close = NR
    }
    in_start && /hook_active_lock_path_after=\$\(capture_lock_identity/ {
        path_after = NR
    }
    in_start && /"\$hook_active_lock_path_after" = "\$hook_lock_identity"/ {
        path_after_compared = NR
    }
    in_start && /exec 8>&-/ { closed = NR }
    in_start && /hook_active_lock_path_after_close=\$\(capture_lock_identity/ {
        path_after_close = NR
    }
    in_start && /"\$hook_active_lock_path_after_close" = "\$hook_lock_identity"/ {
        path_after_close_compared = NR
    }
    in_start && /write_private_file "\$proof_directory\/lock.identity"/ { published = NR }
    END {
        valid = captured < opened && opened < fd_identity && fd_identity < fd_compared
        valid = valid && fd_compared < path_before && path_before < path_before_compared
        valid = valid && path_before_compared < flocked && flocked < contended
        valid = valid && identity_count == 2
        valid = valid && contended < identity_after_contention
        valid = valid && identity_after_contention < path_after
        valid = valid && path_after < path_after_compared && path_after_compared < closed
        valid = valid && closed < path_after_close
        valid = valid && path_after_close < path_after_close_compared
        valid = valid && path_after_close_compared < identity_after_close
        valid = valid && identity_after_close < published
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'start hook does not prove exact active lock contention in fail-closed order' >&2
    exit 1
fi
if ! awk '
    /^run_probe\(\) \{$/ { in_probe = 1; next }
    in_probe && /socket_identity_is_unchanged/ {
        socket_count++
        if (socket_count == 1) socket_before = NR
        if (socket_count == 2) socket_after = NR
    }
    in_probe && /running_identity_is_unchanged/ {
        identity_count++
        if (identity_count == 1) identity_before = NR
        if (identity_count == 2) identity_after = NR
    }
    in_probe && /"\$probe" "\$hook_probe_mode"/ {
        probe_count++
        if (probe_count == 1) first_probe = NR
        if (probe_count == 2) second_probe = NR
    }
    in_probe && /"\$hook_probe_status" -eq 0/ { status_gate = NR }
    /^start_hook\(\) \{$/ { in_probe = 0 }
    END {
        valid = socket_count == 2 && identity_count == 2 && probe_count == 2
        valid = valid && identity_before < socket_before && socket_before < first_probe
        valid = valid && second_probe < identity_after && identity_after < socket_after
        valid = valid && socket_after < status_gate
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'unit and socket identity are not fenced around every probe branch' >&2
    exit 1
fi
if ! awk '
    /hook_expected_lock_identity=\$\(cat/ { expected = NR }
    /exec 9<>"\$journal_lock"/ { opened = NR }
    /hook_lock_fd_identity=\$\(stat -Lc/ { fd_identity = NR }
    /"\$hook_lock_fd_identity" = "\$hook_expected_lock_identity"/ { compared = NR }
    /\/usr\/bin\/flock -n 9/ { flocked = NR }
    /exec 9>&-/ { closed = NR }
    END {
        valid = expected < opened && opened < fd_identity
        valid = valid && fd_identity < compared
        valid = valid && compared < flocked && flocked < closed
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'stop hook does not flock the exact start lock FD in fail-closed order' >&2
    exit 1
fi
if ! awk '
    /run_probe bind-before bind-runtime/ { bind_before = NR }
    /run_probe frame-bounds reject-frame-bounds/ { frame = NR }
    /run_probe wire-shapes reject-wire-shapes/ { wire = NR }
    /run_probe wrong-uid expect-unauthorised-peer/ { wrong_uid = NR }
    /run_probe wrong-gid expect-unauthorised-peer/ { wrong_gid = NR }
    /run_probe root-peer expect-unauthorised-peer/ { root_peer = NR }
    /run_probe bind-after bind-runtime/ { bind_after = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass'"'"'/ { marker_bind_before = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass'"'"'/ { marker_frame = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass'"'"'/ { marker_wire = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass'"'"'/ { marker_wrong_uid = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass'"'"'/ { marker_wrong_gid = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass'"'"'/ { marker_root_peer = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass'"'"'/ { marker_bind_after = NR }
    END {
        probes = bind_before < frame && frame < wire && wire < wrong_uid
        probes = probes && wrong_uid < wrong_gid && wrong_gid < root_peer
        probes = probes && root_peer < bind_after
        markers = bind_after < marker_bind_before && marker_bind_before < marker_frame
        markers = markers && marker_frame < marker_wire && marker_wire < marker_wrong_uid
        markers = markers && marker_wrong_uid < marker_wrong_gid
        markers = markers && marker_wrong_gid < marker_root_peer
        markers = markers && marker_root_peer < marker_bind_after
        if (!(probes && markers)) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'production IPC probes or hook-owned records are not in exact order' >&2
    exit 1
fi
if ! awk '
    /VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass/ && worker_record == 0 {
        worker_record = NR
    }
    /VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass/ && fdstore_record == 0 {
        fdstore_record = NR
    }
    END {
        if (!(worker_record > 0 && worker_record < fdstore_record)) exit 1
    }
' "$gate"; then
    printf '%s\n' 'live helper proof records are absent or not in exact order' >&2
    exit 1
fi
# The descriptor-store target is a literal source contract, not this test's variable.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'systemctl clean --what=fdstore "$unit_name"' "$gate")" -ne 1 ]; then
    printf '%s\n' 'live helper proof gate does not clean exactly one fdstore target' >&2
    exit 1
fi
if grep -E 'systemctl[[:space:]]+(kill|clean[[:space:]]+--what=(all|cache|configuration|logs|runtime|state))' \
    "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'live helper proof gate has an over-broad or forced unit retirement path' >&2
    exit 1
fi
grep -F \
    "capabilities='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'" \
    "$gate" >/dev/null

if grep -E '(^|[^[:alnum:]_-])(useradd|groupadd|adduser|addgroup|systemd-sysusers)([^[:alnum:]_-]|$)' \
    "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'live helper proof gate contains a host account mutator' >&2
    exit 1
fi
if grep -E '(^|[;&|[:space:]])sysctl[[:space:]]+-w([;&|[:space:]]|$)' \
    "$gate" "$ipc_hook" >/dev/null \
    || grep -E '(^|[;&|[:space:]])wg[[:space:]]+([^#]*[[:space:]])?set([[:space:]]|$)' \
        "$gate" "$ipc_hook" >/dev/null \
    || grep -E '(^|[;&|[:space:]])ip[[:space:]]+([^#]*[[:space:]])?(add|delete|replace|set)([[:space:]]|$)' \
        "$gate" "$ipc_hook" >/dev/null \
    || grep -E '(^|[;&|[:space:]])nft[[:space:]]+([^#]*[[:space:]])?(add|delete|flush)([[:space:]]|$)' \
        "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'live helper proof gate contains a host network mutator' >&2
    exit 1
fi

printf '%s\n' \
    'PASS: live helper identity/fdstore and production IPC preview, retirement, root refusal, confinement, and no-mutation contracts are exact.'
