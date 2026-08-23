#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Unprivileged regressions for run-scoped naming and inode-bound ownership.
set -eu
umask 077

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# This library performs observations only.
# shellcheck source=tests/netns/lib/lifecycle-contract.sh
. "$SCRIPT_DIRECTORY/lib/lifecycle-contract.sh"

TEMPORARY_DIRECTORY=$(mktemp -d /tmp/volparossa-lifecycle-contract.XXXXXX)
case $TEMPORARY_DIRECTORY in
    /tmp/volparossa-lifecycle-contract.??????) ;;
    *)
        printf 'unsafe lifecycle-contract test directory: %s\n' "$TEMPORARY_DIRECTORY" >&2
        exit 1
        ;;
esac
cleanup() {
    /bin/rm -r -- "$TEMPORARY_DIRECTORY"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

expect_success() {
    "$@" || {
        printf 'expected success: %s\n' "$*" >&2
        exit 1
    }
}

expect_failure() {
    set +e
    "$@" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        printf 'expected refusal: %s\n' "$*" >&2
        exit 1
    fi
}

expect_output() {
    expected=$1
    shift
    actual=$("$@") || {
        printf 'expected output-producing success: %s\n' "$*" >&2
        exit 1
    }
    if [ "$actual" != "$expected" ]; then
        printf 'expected output %s, got %s: %s\n' "$expected" "$actual" "$*" >&2
        exit 1
    fi
}

write_manifest() {
    destination=$1
    run_id=$2
    shift 2
    {
        printf '%s\n' "$VP_LIFECYCLE_MANIFEST_MAGIC"
        printf 'run_id=%s\n' "$run_id"
        while [ "$#" -gt 0 ]; do
            printf 'namespace\t%s\t%s\n' "$1" "$2"
            shift 2
        done
        printf '%s\n' END
    } >"$destination"
    chmod 0600 "$destination"
}

RUN_ID=0123456789abcdef0123456789abcdef
OTHER_RUN_ID=fedcba9876543210fedcba9876543210
NAME_A=$(vp_lifecycle_namespace_name "$RUN_ID" a)
NAME_B=$(vp_lifecycle_namespace_name "$RUN_ID" b)

expect_success vp_lifecycle_validate_run_id "$RUN_ID"
for invalid_run_id in \
    '' \
    0123456789abcdef0123456789abcde \
    0123456789abcdef0123456789abcdef0 \
    0123456789ABCDEF0123456789ABCDEF \
    0123456789abcdef0123456789abcdeg \
    '0123456789abcdef/123456789abcdef'
do
    expect_failure vp_lifecycle_validate_run_id "$invalid_run_id"
done
expect_failure vp_lifecycle_validate_run_id "$RUN_ID" extra
expect_output "vpl-$RUN_ID-a" vp_lifecycle_namespace_name "$RUN_ID" a
expect_output "vpl-$RUN_ID-b" vp_lifecycle_namespace_name "$RUN_ID" b
expect_output vpa01234567 vp_lifecycle_interface_name "$RUN_ID" a
expect_output vpb01234567 vp_lifecycle_interface_name "$RUN_ID" b
expect_output "vpl_$RUN_ID" vp_lifecycle_table_name "$RUN_ID"
[ "${#NAME_A}" -le 63 ]
[ "$(vp_lifecycle_interface_name "$RUN_ID" a | LC_ALL=C wc -c)" -le 16 ]
expect_failure vp_lifecycle_namespace_name "$RUN_ID" c
expect_failure vp_lifecycle_validate_namespace_name "$RUN_ID" "vpl-$RUN_ID--bad"
expect_failure vp_lifecycle_validate_namespace_name "$RUN_ID" "vpl-$RUN_ID-c"

uid=$(id -u)
manifest=$TEMPORARY_DIRECTORY/ownership.v1
write_manifest "$manifest" "$RUN_ID" "$NAME_A" 11:101 "$NAME_B" 11:102
expect_success vp_lifecycle_validate_manifest "$manifest" "$RUN_ID" "$uid"
expect_failure vp_lifecycle_validate_manifest "$manifest" "$OTHER_RUN_ID" "$uid"
expect_failure vp_lifecycle_validate_manifest "$manifest" "$RUN_ID" "$((uid + 1))"

invalid=$TEMPORARY_DIRECTORY/invalid.v1
write_manifest "$invalid" "$RUN_ID" "$NAME_A" 11:101 "$NAME_A" 11:102
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
write_manifest "$invalid" "$RUN_ID" "$NAME_A" 11:101 "$NAME_B" 11:101
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
write_manifest "$invalid" "$RUN_ID" "$NAME_B" 11:102 "$NAME_A" 11:101
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
write_manifest "$invalid" "$RUN_ID" "vpl-$RUN_ID-c" 11:103
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
write_manifest "$invalid" "$RUN_ID" "$NAME_A" 011:101
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
write_manifest "$invalid" "$RUN_ID" "$NAME_A" 11:0
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
printf '%s\r\nrun_id=%s\r\nEND\r\n' \
    "$VP_LIFECYCLE_MANIFEST_MAGIC" "$RUN_ID" >"$invalid"
chmod 0600 "$invalid"
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
printf '%s\nrun_id=%s\nnamespace\t%s\t11:101\nEND' \
    "$VP_LIFECYCLE_MANIFEST_MAGIC" "$RUN_ID" "$NAME_A" >"$invalid"
chmod 0600 "$invalid"
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
write_manifest "$invalid" "$RUN_ID" "$NAME_A" 11:101
printf '%s\n' EXTRA >>"$invalid"
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
chmod 0644 "$invalid"
expect_failure vp_lifecycle_validate_manifest "$invalid" "$RUN_ID" "$uid"
/bin/ln -s ownership.v1 "$TEMPORARY_DIRECTORY/manifest-link"
expect_failure vp_lifecycle_validate_manifest \
    "$TEMPORARY_DIRECTORY/manifest-link" "$RUN_ID" "$uid"
mkfifo "$TEMPORARY_DIRECTORY/manifest-fifo"
expect_failure vp_lifecycle_validate_manifest \
    "$TEMPORARY_DIRECTORY/manifest-fifo" "$RUN_ID" "$uid"

mount_root=$TEMPORARY_DIRECTORY/netns
mkdir "$mount_root"
: >"$mount_root/$NAME_A"
: >"$mount_root/$NAME_B"
identity_a=$(stat -c '%d:%i' -- "$mount_root/$NAME_A")
identity_b=$(stat -c '%d:%i' -- "$mount_root/$NAME_B")
write_manifest "$manifest" "$RUN_ID" "$NAME_A" "$identity_a" "$NAME_B" "$identity_b"
expect_output OWNED vp_lifecycle_ownership_decision "$manifest" "$mount_root" "$NAME_A"
expect_output OWNED vp_lifecycle_ownership_decision "$manifest" "$mount_root" "$NAME_B"

# Allocate the replacement while the owned inode is still live, so even filesystems that
# immediately recycle freed inode numbers cannot turn this identity-substitution test flaky.
: >"$mount_root/replacement-a"
/bin/rm -- "$mount_root/$NAME_A"
expect_output ABSENT vp_lifecycle_ownership_decision "$manifest" "$mount_root" "$NAME_A"
/bin/mv -- "$mount_root/replacement-a" "$mount_root/$NAME_A"
expect_output FOREIGN vp_lifecycle_ownership_decision "$manifest" "$mount_root" "$NAME_A"
/bin/rm -- "$mount_root/$NAME_A"
/bin/ln -s "$NAME_B" "$mount_root/$NAME_A"
expect_output FOREIGN vp_lifecycle_ownership_decision "$manifest" "$mount_root" "$NAME_A"
expect_output INVALID vp_lifecycle_ownership_decision \
    "$manifest" "$mount_root" "vpl-$RUN_ID-c"
expect_output INVALID vp_lifecycle_ownership_decision \
    "$TEMPORARY_DIRECTORY/manifest-link" "$mount_root" "$NAME_B"
/bin/ln -s netns "$TEMPORARY_DIRECTORY/netns-link"
expect_output INVALID vp_lifecycle_ownership_decision \
    "$manifest" "$TEMPORARY_DIRECTORY/netns-link" "$NAME_B"

printf '%s\n' \
    'PASS: lifecycle names, manifests, and inode-bound ownership decisions fail closed.'
