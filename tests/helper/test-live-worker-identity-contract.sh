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
temporary_directory=$(mktemp -d /tmp/volparossa-helper-proof-contract.XXXXXX)
case $temporary_directory in
    /tmp/volparossa-helper-proof-contract.??????) ;;
    *)
        printf 'unsafe helper proof contract directory: %s\n' "$temporary_directory" >&2
        exit 1
        ;;
esac
cleanup() {
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
sh -n "$gate"
sh -n "$capture_library"

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

resolver_fixture=$temporary_directory/resolver-fixture
mkdir -m 0700 "$resolver_fixture"
resolver_regular=$resolver_fixture/regular.conf
printf '%s\n' 'nameserver 192.0.2.53' >"$resolver_regular"
chmod 0600 "$resolver_regular"
resolver_regular_snapshot=$temporary_directory/resolver-regular.snapshot
vp_capture_resolver_snapshot "$resolver_regular" "$resolver_regular_snapshot" \
    "$resolver_fixture"
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
    "$resolver_fixture"
vp_capture_file_is_safe "$resolver_symlink_snapshot"
grep -Fx symlink-target.conf "$resolver_symlink_snapshot" >/dev/null
grep -Fx "$resolver_symlink_target" "$resolver_symlink_snapshot" >/dev/null

resolver_unsafe_target=$resolver_fixture/unsafe-target.conf
printf '%s\n' 'nameserver 198.51.100.53' >"$resolver_unsafe_target"
chmod 0666 "$resolver_unsafe_target"
resolver_unsafe_snapshot=$temporary_directory/resolver-unsafe.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_target" "$resolver_unsafe_snapshot" \
    "$resolver_fixture"; then
    printf '%s\n' 'writable resolver target was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_snapshot" ]; then
    printf '%s\n' 'rejected resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_outside=$temporary_directory/resolver-outside.conf
printf '%s\n' 'nameserver 203.0.113.53' >"$resolver_outside"
chmod 0600 "$resolver_outside"
resolver_outside_link=$resolver_fixture/outside.conf
ln -s "$resolver_outside" "$resolver_outside_link"
resolver_outside_snapshot=$temporary_directory/resolver-outside.snapshot
if vp_capture_resolver_snapshot "$resolver_outside_link" "$resolver_outside_snapshot" \
    "$resolver_fixture"; then
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
    "$resolver_unsafe_parent_snapshot" "$resolver_fixture"; then
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
            "$resolver_fixture" || exit 77
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
    '  copy the already-built real helper into one validated root-only temporary stage;' \
    '  create synthetic, collision-free agent/worker/group records only inside that stage;' \
    '  bind account files and the system bus socket read-only inside one transient service;' \
    '  pin its D-Bus system address to that verified socket inside the private /run;' \
    '  run with PrivateNetwork=yes, a private temporary /run, and no host account changes;' \
    '  set NotifyAccess=main, FileDescriptorStoreMax=128, and' \
    '    FileDescriptorStorePreserve=yes on that transient service;' \
    '  grant exactly CAP_KILL, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SETGID, CAP_SETPCAP,' \
    '    CAP_SETUID, and CAP_SYS_ADMIN to the helper parent;' \
    '  require its kernel supplementary-group vector to contain only the staged agent GID;' \
    '  invoke only --internal-worker-v3-live-proof and require its exact two success records;' \
    '  after main exit require exactly two descriptors in the systemd descriptor store;' \
    '  bind normal retirement to the exact JSON InvocationID returned for that run;' \
    '  recover tentative ownership only from its exact marker and current nonzero manager ID;' \
    '  stop the exact random unit, clean only its fdstore, reset/collect it, and remove the stage;' \
    '  compare privacy-safe before/after host account, resolver, mount, firewall, WireGuard,' \
    '    and network digests.' \
    'This stages only the helper identity component. It creates no host account, link,' \
    'route, firewall rule, WireGuard device, DNS change, sysctl change, or VPN datapath.' \
    'It is not production-service, restart-recovery, datapath, or A01-A15 evidence.' \
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
expect_status 64 "$gate" --preview --yes
expect_status 64 "$gate" --preview --execute
expect_status 64 "$gate" --execute --execute
expect_status 64 "$gate" --execute --yes --yes
expect_status 64 "$gate" --unknown

find /var/tmp -maxdepth 1 -name 'volparossa-helper-live-proof.*' -printf '%f\n' \
    | sort >"$temporary_directory/stages.before"
expect_status 77 "$gate" --execute --yes
if ! grep -Fx 'VOLPAROSSA live worker-identity proof plan:' "$last_stdout" >/dev/null \
    || grep -F 'PREVIEW ONLY:' "$last_stdout" >/dev/null; then
    printf '%s\n' 'approved execution did not print the exact plan before refusing root' >&2
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
    /^print_plan$/ { execute_plan = NR }
    /^if \[ "\$\(id -u\)" -ne 0 \]; then$/ { root_preflight = NR }
    END {
        if (!(approval_guard < execute_plan && execute_plan < root_preflight)) exit 1
    }
' "$gate"; then
    printf '%s\n' 'execute plan is not ordered between approval and preflight' >&2
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
    '--property=PrivateNetwork=yes' \
    '--property=PrivateMounts=yes' \
    '--property=NoNewPrivileges=yes' \
    '--property=LimitCORE=0' \
    '--property=NotifyAccess=main' \
    '--property=FileDescriptorStoreMax=128' \
    '--property=FileDescriptorStorePreserve=yes' \
    '--property=TimeoutStartSec=45s' \
    '--json=short' \
    '--ignore-failure' \
    '--description="$unit_ownership_marker"' \
    '--property="CapabilityBoundingSet=$capabilities"' \
    '--property="AmbientCapabilities=$capabilities"' \
    '--property="BindReadOnlyPaths=$helper_bind $account_binds $system_bus_bind"' \
    '--property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket' \
    'system_bus_socket=/run/dbus/system_bus_socket' \
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
    'unit_description_matches_marker' \
    'adopt_tentative_unit' \
    '[ "$adopt_attempt" -lt 1000 ]' \
    'unit_invocation_is_current || return 1' \
    'if ! unit_invocation_is_current; then' \
    'forget_unit_ownership' \
    'capture_unit_property Description "$temporary_stage/unit-description"' \
    '[ "$observed_description" != "$unit_ownership_marker" ]' \
    'capture_unit_property NFileDescriptorStore "$temporary_stage/unit-fdstore-count"' \
    '[ "$observed_fdstore_count" != 2 ]' \
    'systemctl stop --no-block "$unit_name"' \
    'systemctl show --property=Job --value "$unit_name"' \
    'systemctl clean --what=fdstore "$unit_name"' \
    '[ "$retire_fdstore_count" -eq 0 ]' \
    '[ "$retire_load_state" = not-found ]' \
    '[ "$retire_attempt" -lt 400 ]' \
    '[ "$poll_attempt" -ge 1000 ]' \
    'systemctl reset-failed "$unit_name"' \
    '--internal-worker-v3-live-proof' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass' \
    'VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass'
do
    grep -F -- "$required_contract" "$gate" >/dev/null || {
        printf 'missing live helper proof contract: %s\n' "$required_contract" >&2
        exit 1
    }
done
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
    "$gate" >/dev/null; then
    printf '%s\n' 'live helper proof gate has an over-broad or forced unit retirement path' >&2
    exit 1
fi
grep -F \
    "capabilities='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'" \
    "$gate" >/dev/null

if grep -E '(^|[^[:alnum:]_-])(useradd|groupadd|adduser|addgroup|systemd-sysusers)([^[:alnum:]_-]|$)' \
    "$gate" >/dev/null; then
    printf '%s\n' 'live helper proof gate contains a host account mutator' >&2
    exit 1
fi
if grep -E '(^|[;&|[:space:]])sysctl[[:space:]]+-w([;&|[:space:]]|$)' "$gate" >/dev/null \
    || grep -E '(^|[;&|[:space:]])wg[[:space:]]+([^#]*[[:space:]])?set([[:space:]]|$)' \
        "$gate" >/dev/null \
    || grep -E '(^|[;&|[:space:]])ip[[:space:]]+([^#]*[[:space:]])?(add|delete|replace|set)([[:space:]]|$)' \
        "$gate" >/dev/null \
    || grep -E '(^|[;&|[:space:]])nft[[:space:]]+([^#]*[[:space:]])?(add|delete|flush)([[:space:]]|$)' \
        "$gate" >/dev/null; then
    printf '%s\n' 'live helper proof gate contains a host network mutator' >&2
    exit 1
fi

printf '%s\n' \
    'PASS: live helper identity/fdstore preview, retirement, root refusal, confinement, and no-mutation contracts are exact.'
