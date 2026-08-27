#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Unprivileged argument, provenance, workflow and static safety contract for the proof VM.
# Literal variable expressions below are patterns matched inside reviewed files.
# Extracted runner functions consume fixture globals, and the cross-file count
# intentionally spans two files.
# shellcheck disable=SC2016,SC2034,SC2126
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
runner=$script_directory/run-helper-boundary-evidence-vm.sh
manifest=$script_directory/debian13-amd64-image-v1.json
workflow=$repository_directory/.github/workflows/helper-boundary-evidence.yml
supervisor=$script_directory/qemu-pidfd-supervisor.py
environment_validator=$script_directory/validate-helper-boundary-vm-environment-v1.sh
environment_test=$script_directory/test-helper-boundary-vm-environment-v1.sh
temporary_directory=$(mktemp -d /tmp/volparossa-helper-vm-contract.XXXXXX)
case $temporary_directory in
    /tmp/volparossa-helper-vm-contract.??????) ;;
    *)
        printf 'unsafe VM contract directory: %s\n' "$temporary_directory" >&2
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
    printf '%s\n' 'BLOCKED: VM contract test must remain unprivileged' >&2
    exit 77
fi
for required_file in \
    "$runner" "$manifest" "$workflow" "$supervisor" \
    "$environment_validator" "$environment_test"
do
    if [ ! -f "$required_file" ] || [ -L "$required_file" ]; then
        printf 'required VM contract input is unsafe: %s\n' "$required_file" >&2
        exit 1
    fi
done
for required_executable in \
    "$runner" "$supervisor" "$environment_validator" "$environment_test"
do
    if [ ! -x "$required_executable" ]; then
        printf 'required VM contract executable is not executable: %s\n' \
            "$required_executable" >&2
        exit 1
    fi
done
sh -n "$runner"
jq -e . "$manifest" >/dev/null

expected_manifest_sha256=c535c54e44f724aa05278fe2bfa7bf607ecd285b83f35e136f16b99d1b99392a
actual_manifest_sha256=$(sha256sum "$manifest" | awk '{print $1}')
if [ "$actual_manifest_sha256" != "$expected_manifest_sha256" ]; then
    printf '%s\n' 'the reviewed Debian image manifest bytes changed' >&2
    exit 1
fi
jq -e '
    . == {
      architecture: "amd64",
      checksum_provenance: "manually-reviewed-upstream-sha512-no-detached-signature",
      checksum_url: "https://cloud.debian.org/images/cloud/trixie/20260826-2582/SHA512SUMS",
      debian_version: "13",
      filename: "debian-13-genericcloud-amd64-20260826-2582.qcow2",
      format: "qcow2",
      image_kind: "reviewed-debian-genericcloud",
      release_build: "20260826-2582",
      release_codename: "trixie",
      release_date: "2026-08-26",
      schema_version: 1,
      sha512: "184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003",
      systemd_version: 257,
      url: "https://cloud.debian.org/images/cloud/trixie/20260826-2582/debian-13-genericcloud-amd64-20260826-2582.qcow2"
    }
' "$manifest" >/dev/null
jq -S -c . "$manifest" | cmp -s - "$manifest"

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
    actual=$?
    set -e
    if [ "$actual" -ne "$expected" ]; then
        printf 'expected exit %s, got %s: %s\n' "$expected" "$actual" "$*" >&2
        sed -n '1,80p' "$last_stderr" >&2
        exit 1
    fi
}

expect_status 0 "$runner"
default_preview=$last_stdout
if [ -s "$last_stderr" ]; then
    printf '%s\n' 'default VM preview wrote standard error' >&2
    exit 1
fi
grep -Fx '  require an unprivileged host user and usable KVM; never fall back to TCG;' \
    "$default_preview" >/dev/null
grep -Fx 'No bridge, TAP device, host route, firewall, DNS, sysctl or VPN state is changed.' \
    "$default_preview" >/dev/null
grep -Fx 'PREVIEW ONLY: no image, VM, key, file, service, or network state was changed.' \
    "$default_preview" >/dev/null

expect_status 0 "$runner" --preview
cmp -s "$default_preview" "$last_stdout"
if [ -s "$last_stderr" ]; then
    printf '%s\n' 'explicit VM preview wrote standard error' >&2
    exit 1
fi
expect_status 64 "$runner" --preview --yes
expect_status 64 "$runner" --preview --image /tmp/image
expect_status 64 "$runner" --execute
expect_status 64 "$runner" --execute --yes --yes
expect_status 64 "$runner" --execute --yes --image
expect_status 64 "$runner" --execute --yes --image /tmp/image --output /tmp/output
expect_status 64 "$runner" --unknown
expect_status 77 "$runner" --execute --yes \
    --image /tmp/image --output /tmp/output --expected-commit invalid

guest_setup_fixture=$temporary_directory/guest-setup.sh
guest_proof_fixture=$temporary_directory/guest-proof.sh
sed -n "/^cat >.*<<'GUEST_SETUP'$/,/^GUEST_SETUP$/p" "$runner" \
    | sed '1d;$d' >"$guest_setup_fixture"
sed -n "/^cat >.*<<'GUEST_PROOF'$/,/^GUEST_PROOF$/p" "$runner" \
    | sed '1d;$d' >"$guest_proof_fixture"
test -s "$guest_setup_fixture"
test -s "$guest_proof_fixture"
sh -n "$guest_setup_fixture"
sh -n "$guest_proof_fixture"
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck "$guest_setup_fixture" "$guest_proof_fixture"
fi

for exact_runner_text in \
    '-machine q35,accel=kvm' \
    '-no-user-config -nodefaults' \
    '-device VGA,id=video0,bus=pcie.0,addr=0x1' \
    '-display none' \
    '-S -qmp stdio' \
    '--qmp-stdio --qmp-timeout-seconds 10' \
    "qemu_netdev='user,id=net0,hostfwd=tcp:127.0.0.1:22222-:22'" \
    "qemu_netdev='user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:22222-:22'" \
    '-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny' \
    '--no-hardlinks --depth 1 --no-tags --single-branch --branch main' \
    'qemu-pidfd-supervisor.py' \
    'validate-helper-boundary-vm-environment-v1.sh' \
    'StrictHostKeyChecking=yes' \
    'GlobalKnownHostsFile=/dev/null' \
    'IdentityAgent=none' \
    '-F /dev/null' \
    'ControlMaster=no' \
    'ControlPath=none' \
    'ControlPersist=no' \
    'ProxyCommand=none' \
    'ProxyJump=none' \
    'ssh_deletekeys: true' \
    'ed25519_private: |' \
    'exec 9<>"$console_fifo"' \
    'dd bs=65536 count=256 iflag=fullblock' \
    'prlimit --fsize=1048576:1048576' \
    'cargo fetch --locked' \
    'cargo build --locked --offline' \
    'proof_network: {external_https: "denied", mode: "qemu-user-restrict-on"}' \
    'post_image_sha512=$(sha512sum "$image_path"'
do
    grep -F -- "$exact_runner_text" "$runner" >/dev/null
done

if grep -F 'ssh_genkeytypes:' "$runner" >/dev/null; then
    printf '%s\n' 'pre-supplied host keys must not emit a redundant generation list' >&2
    exit 1
fi

vga_device='-device VGA,id=video0,bus=pcie.0,addr=0x1'
test "$(grep -c -F -- "$vga_device" "$runner")" -eq 1
vga_line=$(grep -n -m 1 -F -- "$vga_device" "$runner" | cut -d: -f1)
first_virtio_drive_line=$(
    grep -n -m 1 -F -- '-drive "if=virtio,format=qcow2,file=$overlay"' "$runner" \
        | cut -d: -f1
)
if [ -z "$vga_line" ] || [ -z "$first_virtio_drive_line" ] \
    || [ "$vga_line" -ge "$first_virtio_drive_line" ]; then
    printf '%s\n' 'the fixed VGA device must claim PCIe slot 1 before automatic virtio placement' >&2
    exit 1
fi

# These searches intentionally match literal variables in the reviewed scripts.
# shellcheck disable=SC2016
grep -F 'git -C "$source_clone" remote remove origin' "$runner" >/dev/null
# shellcheck disable=SC2016
grep -F 'rm -rf --one-file-system -- "$source_clone/.git/logs"' "$runner" >/dev/null
# shellcheck disable=SC2016
grep -F 'rm -rf --one-file-system -- "$run_directory"' "$runner" >/dev/null
grep -F 'sha256sum --check --strict' "$runner" >/dev/null
grep -F 'https://cloud.debian.org/images/cloud/trixie/' "$guest_proof_fixture" >/dev/null
grep -F 'start_vm provisioning provisioning' "$runner" >/dev/null
grep -F 'start_vm proof restricted' "$runner" >/dev/null
grep -F '9>&- </dev/null >/dev/null 2>&1 &' "$runner" >/dev/null
grep -F 'wait_for_supervisor_ready 15' "$runner" >/dev/null
grep -F 'QEMU exited after supervisor readiness for $vm_phase' "$runner" >/dev/null
grep -F "printf 'qemu_supervisor_status='" "$runner" >/dev/null
grep -F "printf 'qemu_event_record='" "$runner" >/dev/null
grep -F 'qemu_failure_qmp=$qemu_control/qmp' "$runner" >/dev/null
grep -F 'qemu_failure_stderr=$qemu_control/stderr' "$runner" >/dev/null
grep -F '.events[-1] == {' "$runner" >/dev/null
grep -F 'event: "SHUTDOWN", guest: true, reason: "guest-shutdown"' \
    "$runner" >/dev/null
grep -F 'qemu_clean_lifecycle=yes' "$runner" >/dev/null
grep -F 'publish_reap_failure_diagnostics "$qemu_control"' "$runner" >/dev/null
grep -F 'qemu_failed_before_ssh=no' "$runner" >/dev/null
grep -F 'the stalled QEMU stop request failed for $vm_phase' "$runner" >/dev/null
grep -F "grep -Eq '^\\.qmp\\.[0-9]+\\.tmp$'" "$runner" >/dev/null
grep -F "grep -Eq '^\\.stderr\\.[0-9]+\\.tmp$'" "$runner" >/dev/null
grep -F 'MAX_QMP_RECORD_BYTES = 65_536' "$supervisor" >/dev/null
grep -F 'MAX_QMP_STREAM_BYTES = 8_388_608' "$supervisor" >/dev/null
grep -F 'MAX_STDERR_BYTES = 917_504' "$supervisor" >/dev/null
grep -F 'MAX_STDERR_DRAIN_BYTES_PER_POLL = 262_144' "$supervisor" >/dev/null
grep -F 'control.write_bytes("stderr", stderr_tail)' "$supervisor" >/dev/null
grep -F 'error: "supervisor-failure"' "$runner" >/dev/null
grep -F "trap '' HUP INT TERM" "$runner" >/dev/null
grep -F 'console_log=$run_directory/vm-console.log' "$runner" >/dev/null
grep -F 'published_console_log=$output_directory/vm-console.log' "$runner" >/dev/null
grep -F 'discard_console_publish_temporary || cleanup_status=1' "$runner" >/dev/null
grep -F 'if scrub_sensitive_run_state; then' "$runner" >/dev/null
grep -F 'WARNING: sensitive state may remain in the private run directory:' "$runner" >/dev/null
grep -F 'bounded_run proof-cloud-init 32' "$runner" >/dev/null
grep -F 'bounded_run proof-systemd-ready 2' "$runner" >/dev/null

# A canonical ready record wins over absence of status, while a same-poll
# ready+status pair is retained as the distinct fast-exit state.
readiness_function=$temporary_directory/wait-for-supervisor-ready.sh
sed -n '/^wait_for_supervisor_ready() {$/,/^}$/p' "$runner" >"$readiness_function"
test "$(grep -c '^wait_for_supervisor_ready() {$' "$readiness_function")" -eq 1
sh -n "$readiness_function"
# shellcheck disable=SC1090
. "$readiness_function"

qemu_control=$temporary_directory/readiness-ready
mkdir -m 700 "$qemu_control"
printf '%s\n' ready >"$qemu_control/ready"
wait_for_supervisor_ready 1

qemu_control=$temporary_directory/readiness-status
mkdir -m 700 "$qemu_control"
printf '%s\n' status >"$qemu_control/status"
set +e
wait_for_supervisor_ready 1
status_only_result=$?
set -e
test "$status_only_result" -eq 2

qemu_control=$temporary_directory/readiness-fast-exit
mkdir -m 700 "$qemu_control"
printf '%s\n' ready >"$qemu_control/ready"
printf '%s\n' status >"$qemu_control/status"
set +e
wait_for_supervisor_ready 1
fast_exit_result=$?
set -e
test "$fast_exit_result" -eq 3

trap_line=$(grep -n -m 1 -F 'trap cleanup EXIT' "$runner" | cut -d: -f1)
chmod_line=$(grep -n -m 1 -F 'chmod 0700 "$run_directory"' "$runner" | cut -d: -f1)
if [ -z "$trap_line" ] || [ -z "$chmod_line" ] || [ "$trap_line" -ge "$chmod_line" ]; then
    printf '%s\n' 'the VM cleanup trap is not armed immediately after mktemp fencing' >&2
    exit 1
fi

if grep -Eq -- 'accel=(tcg|kvm:tcg)|-netdev[[:space:]]+(tap|bridge)|-nic[[:space:]]+(tap|bridge)' \
    "$runner"; then
    printf '%s\n' 'the VM runner contains an emulation or host-network fallback' >&2
    exit 1
fi
if grep -F 'StrictHostKeyChecking=accept-new' "$runner" >/dev/null \
    || grep -Eq '(^|[[:space:]])kill[[:space:]]+-(TERM|KILL)' "$runner" \
    || grep -F 'qemu_pid=' "$runner" >/dev/null; then
    printf '%s\n' 'the VM runner contains TOFU or numeric QEMU signalling' >&2
    exit 1
fi
if grep -E '^console_log=\$output_directory/' "$runner" >/dev/null \
    || grep -F 'console.done.request' "$runner" >/dev/null \
    || grep -F 'ControlMaster=auto' "$runner" >/dev/null \
    || grep -E -- '^[[:space:]]+-F[[:space:]]+[^/]' "$runner" >/dev/null; then
    printf '%s\n' 'the VM runner contains mutable public console, request-temp, or host SSH configuration state' >&2
    exit 1
fi
if grep -Eq 'wget|git clone https?://' "$runner"; then
    printf '%s\n' 'the VM runner contains an unreviewed host-side download path' >&2
    exit 1
fi

# Exercise publication with injected copier, rename, and scanner failures. The
# reviewed functions are extracted verbatim so the test cannot drift to a mock.
publication_functions=$temporary_directory/console-publication-functions.sh
{
    sed -n '/^atomic_empty_file() {$/,/^}$/p' "$runner"
    sed -n '/^require_no_private_key_marker() {$/,/^}$/p' "$runner"
    sed -n '/^discard_console_publish_temporary() {$/,/^}$/p' "$runner"
    sed -n '/^publish_console() {$/,/^}$/p' "$runner"
} >"$publication_functions"
test "$(grep -c '^[_a-z].*() {$' "$publication_functions")" -eq 4
sh -n "$publication_functions"
# shellcheck disable=SC1090
. "$publication_functions"

publication_output=$temporary_directory/publication-output
publication_run=$temporary_directory/publication-run
publication_bin=$temporary_directory/publication-bin
mkdir -m 700 "$publication_output" "$publication_run" "$publication_bin"
output_directory=$publication_output
atomic_fixture=$publication_run/atomic-empty
atomic_empty_file "$atomic_fixture"
test -f "$atomic_fixture"
test ! -L "$atomic_fixture"
test "$(stat -Lc '%h:%u:%a:%s' "$atomic_fixture")" = "1:$(id -u):600:0"
set +e
atomic_empty_file "$atomic_fixture"
atomic_repeat_status=$?
set -e
test "$atomic_repeat_status" -ne 0
console_log=$publication_run/vm-console.log
published_console_log=$publication_output/vm-console.log
console_publish_temporary=
console_settled=yes
console_published=no
printf '%s\n' 'bounded safe console' >"$console_log"
chmod 0600 "$console_log"
for publication_tool in cp mv grep; do
    {
        printf '%s\n' '#!/bin/sh'
        printf 'tool=%s\n' "$publication_tool"
        printf '%s\n' \
            'if [ "${VOLPAROSSA_FAIL_PUBLICATION_TOOL:-}" = "$tool" ]; then' \
            '    [ "$tool" = grep ] && exit 2' \
            '    exit 1' \
            'fi' \
            'exec "/usr/bin/$tool" "$@"'
    } >"$publication_bin/$publication_tool"
    chmod 0700 "$publication_bin/$publication_tool"
done
original_path=$PATH
PATH=$publication_bin:$PATH
export PATH
for failed_publication_tool in cp mv grep; do
    VOLPAROSSA_FAIL_PUBLICATION_TOOL=$failed_publication_tool
    export VOLPAROSSA_FAIL_PUBLICATION_TOOL
    set +e
    publish_console >/dev/null 2>&1
    publication_status=$?
    set -e
    if [ "$publication_status" -eq 0 ] \
        || [ -n "$console_publish_temporary" ] \
        || [ -n "$(find "$publication_output" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        printf 'console publication did not fail cleanly for injected %s error\n' \
            "$failed_publication_tool" >&2
        exit 1
    fi
done
unset VOLPAROSSA_FAIL_PUBLICATION_TOOL
publish_console
PATH=$original_path
export PATH
test "$console_published" = yes
test -z "$console_publish_temporary"
test "$(stat -Lc '%h:%u:%a' "$published_console_log")" \
    = "1:$(id -u):600"
cmp -s "$console_log" "$published_console_log"
test "$(find "$publication_output" -mindepth 1 -maxdepth 1 -type f -printf '%f\n')" \
    = vm-console.log

# Early QEMU exits retain only canonical status fields plus the supervisor's
# bounded QMP event record and stream-scanned stderr tail in the allowlisted diagnostic file.
qemu_diagnostic_functions=$temporary_directory/qemu-diagnostic-functions.sh
{
    sed -n '/^validate_supervisor_record() {$/,/^}$/p' "$runner"
    sed -n '/^validate_supervisor_stderr() {$/,/^}$/p' "$runner"
    sed -n '/^validate_supervisor_qmp() {$/,/^}$/p' "$runner"
    sed -n '/^require_no_private_key_marker() {$/,/^}$/p' "$runner"
    sed -n '/^publish_qemu_failure_diagnostics() {$/,/^}$/p' "$runner"
    sed -n '/^scrub_supervisor_diagnostics() {$/,/^}$/p' "$runner"
} >"$qemu_diagnostic_functions"
test "$(grep -c '^[_a-z].*() {$' "$qemu_diagnostic_functions")" -eq 6
sh -n "$qemu_diagnostic_functions"
# shellcheck disable=SC1090
. "$qemu_diagnostic_functions"

qemu_status_fixture=$temporary_directory/qemu-fast-exit-status.json
qemu_qmp_fixture=$temporary_directory/qemu-fast-exit-qmp.json
qemu_stderr_fixture=$temporary_directory/qemu-fast-exit.stderr.log
proof_stderr_log=$temporary_directory/helper-boundary-proof.stderr.log
printf '%s\n' \
    '{"exit_code":1,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}' \
    >"$qemu_status_fixture"
printf '%s\n' \
    '{"events":[{"event":"RESET","guest":true,"reason":"guest-reset"}],"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"final","truncated":false}' \
    >"$qemu_qmp_fixture"
printf '%s\n' 'qemu: bounded runtime failure' >"$qemu_stderr_fixture"
: >"$proof_stderr_log"
chmod 0600 \
    "$qemu_status_fixture" "$qemu_qmp_fixture" "$qemu_stderr_fixture" \
    "$proof_stderr_log"
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_qmp_fixture" "$qemu_stderr_fixture"
test "$(stat -Lc '%h:%u:%a' "$proof_stderr_log")" = "1:$(id -u):600"
grep -Fx 'qemu_phase=provisioning' "$proof_stderr_log" >/dev/null
grep -Fx 'qemu_supervisor_status={"exit_code":1,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}' \
    "$proof_stderr_log" >/dev/null
grep -Fx 'qemu_event_record={"events":[{"event":"RESET","guest":true,"reason":"guest-reset"}],"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"final","truncated":false}' \
    "$proof_stderr_log" >/dev/null
grep -Fx 'qemu_stderr_tail_begin' "$proof_stderr_log" >/dev/null
grep -Fx 'qemu: bounded runtime failure' "$proof_stderr_log" >/dev/null
grep -Fx 'qemu_stderr_tail_end' "$proof_stderr_log" >/dev/null

qemu_qmp_link=$temporary_directory/qemu-fast-exit-qmp.link
ln -s "$qemu_qmp_fixture" "$qemu_qmp_link"
: >"$proof_stderr_log"
set +e
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_qmp_link" \
    "$qemu_stderr_fixture" >/dev/null 2>&1
linked_qmp_result=$?
set -e
test "$linked_qmp_result" -ne 0
test ! -s "$proof_stderr_log"

qemu_invalid_qmp=$temporary_directory/qemu-invalid-qmp.json
printf '%s\n' \
    '{"events":[{"event":"RESET","guest":true,"reason":"raw-attacker-token"}],"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"final","truncated":false}' \
    >"$qemu_invalid_qmp"
chmod 0600 "$qemu_invalid_qmp"
: >"$proof_stderr_log"
set +e
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_invalid_qmp" \
    "$qemu_stderr_fixture" >/dev/null 2>&1
invalid_qmp_result=$?
set -e
test "$invalid_qmp_result" -ne 0
test ! -s "$proof_stderr_log"

# GNU stat describes an empty file as "regular empty file". The runner proves
# the file type independently and must accept exact private empty QEMU stderr.
: >"$qemu_stderr_fixture"
: >"$proof_stderr_log"
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_qmp_fixture" "$qemu_stderr_fixture"
grep -Fx 'qemu_stderr_tail_begin' "$proof_stderr_log" >/dev/null
grep -Fx 'qemu_stderr_tail_end' "$proof_stderr_log" >/dev/null

printf '%s\n' '-----BEGIN PRIVATE KEY-----' >"$qemu_stderr_fixture"
: >"$proof_stderr_log"
set +e
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_qmp_fixture" \
    "$qemu_stderr_fixture" >/dev/null 2>&1
private_marker_result=$?
set -e
test "$private_marker_result" -ne 0
test ! -s "$proof_stderr_log"

qemu_secret_fixture=$temporary_directory/qemu-same-user-secret
qemu_stderr_link=$temporary_directory/qemu-fast-exit.stderr.link
printf '%s\n' 'same-user secret must not be followed' >"$qemu_secret_fixture"
chmod 0600 "$qemu_secret_fixture"
ln -s "$qemu_secret_fixture" "$qemu_stderr_link"
: >"$proof_stderr_log"
set +e
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_qmp_fixture" \
    "$qemu_stderr_link" >/dev/null 2>&1
linked_stderr_result=$?
set -e
test "$linked_stderr_result" -ne 0
test ! -s "$proof_stderr_log"

qemu_status_link=$temporary_directory/qemu-fast-exit-status.link
ln -s "$qemu_status_fixture" "$qemu_status_link"
printf '%s\n' 'qemu: bounded runtime failure' >"$qemu_stderr_fixture"
: >"$proof_stderr_log"
set +e
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_link" "$qemu_qmp_fixture" \
    "$qemu_stderr_fixture" >/dev/null 2>&1
linked_status_result=$?
set -e
test "$linked_status_result" -ne 0
test ! -s "$proof_stderr_log"

dd if=/dev/zero bs=65536 count=15 status=none >"$qemu_stderr_fixture"
: >"$proof_stderr_log"
set +e
publish_qemu_failure_diagnostics \
    provisioning "$qemu_status_fixture" "$qemu_qmp_fixture" \
    "$qemu_stderr_fixture" >/dev/null 2>&1
oversized_stderr_result=$?
set -e
test "$oversized_stderr_result" -ne 0
test ! -s "$proof_stderr_log"

# Uncertain cleanup removes an interrupted atomic stderr publication only when
# it is an exact private regular file under a fixed supervisor control path.
run_directory=$temporary_directory/scrub-run
mkdir -m 700 "$run_directory"
mkdir -m 700 "$run_directory/qemu-provisioning"
: >"$run_directory/qemu-provisioning/qmp"
: >"$run_directory/qemu-provisioning/.qmp.23456.tmp"
: >"$run_directory/qemu-provisioning/stderr"
: >"$run_directory/qemu-provisioning/.stderr.12345.tmp"
chmod 0600 \
    "$run_directory/qemu-provisioning/qmp" \
    "$run_directory/qemu-provisioning/.qmp.23456.tmp" \
    "$run_directory/qemu-provisioning/stderr" \
    "$run_directory/qemu-provisioning/.stderr.12345.tmp"
# A completed QMP record must be canonical before cleanup may remove it.
printf '%s\n' \
    '{"events":[],"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"failed","truncated":false}' \
    >"$run_directory/qemu-provisioning/qmp"
scrub_supervisor_diagnostics "$run_directory/qemu-provisioning"
test ! -e "$run_directory/qemu-provisioning/qmp"
test ! -e "$run_directory/qemu-provisioning/.qmp.23456.tmp"
test ! -e "$run_directory/qemu-provisioning/stderr"
test ! -e "$run_directory/qemu-provisioning/.stderr.12345.tmp"

printf '%s\n' 'invalid temporary name' \
    >"$run_directory/qemu-provisioning/.stderr.not-a-pid.tmp"
chmod 0600 "$run_directory/qemu-provisioning/.stderr.not-a-pid.tmp"
set +e
scrub_supervisor_diagnostics "$run_directory/qemu-provisioning" >/dev/null 2>&1
invalid_stderr_name_result=$?
set -e
test "$invalid_stderr_name_result" -ne 0
test -f "$run_directory/qemu-provisioning/.stderr.not-a-pid.tmp"

mkdir -m 700 "$run_directory/qemu-proof"
scrub_link_target=$temporary_directory/scrub-link-target
printf '%s\n' 'linked file must not be touched' >"$scrub_link_target"
chmod 0600 "$scrub_link_target"
ln -s "$scrub_link_target" "$run_directory/qemu-proof/.stderr.67890.tmp"
ln -s "$scrub_link_target" "$run_directory/qemu-proof/.qmp.54321.tmp"
set +e
scrub_supervisor_diagnostics "$run_directory/qemu-proof" >/dev/null 2>&1
linked_stderr_temporary_result=$?
set -e
test "$linked_stderr_temporary_result" -ne 0
test -L "$run_directory/qemu-proof/.stderr.67890.tmp"
test -L "$run_directory/qemu-proof/.qmp.54321.tmp"
grep -Fx 'linked file must not be touched' "$scrub_link_target" >/dev/null

for exact_workflow_text in \
    '  workflow_dispatch:' \
    '  contents: read' \
    'test "$SELECTED_REF" = refs/heads/main' \
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' \
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
    'persist-credentials: false' \
    'ref: ${{ github.ref }}' \
    'test "$(git symbolic-ref --quiet --short HEAD)" = main' \
    'retention-days: 90' \
    'prlimit --fsize=8388608:8388608' \
    'sudo getfacl --absolute-names --numeric /dev/kvm' \
    'sudo setfacl --modify "u:${runner_user}:rw-" /dev/kvm' \
    'sudo setfacl --restore="$acl_snapshot"' \
    'cmp -s "$acl_snapshot" "$restored_acl"' \
    '--connect-timeout 30' \
    '--max-time 1200' \
    '--max-filesize 2147483648' \
    '--max-redirs 3' \
    'tests/helper/run-helper-boundary-evidence-vm.sh' \
    'tests/helper/validate-helper-boundary-evidence-v1.sh' \
    'tests/helper/validate-helper-boundary-vm-environment-v1.sh' \
    "grep -aEq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'" \
    'RESTORE_KVM_ACL_OUTCOME: ${{ steps.restore_kvm_acl.outcome }}'
do
    grep -F -- "$exact_workflow_text" "$workflow" >/dev/null
done

test "$(grep -h -- '-no-user-config' "$runner" "$workflow" | wc -l)" -eq 2
test "$(grep -c -F 'sudo setfacl --modify "u:${runner_user}:rw-" /dev/kvm' "$workflow")" -eq 2
if grep -Eq '^[[:space:]]+-S([[:space:]]|$)' "$workflow"; then
    printf '%s\n' 'the KVM preflight does not execute a virtual CPU' >&2
    exit 1
fi
grep -F "steps.restore_kvm_acl.outcome == 'success'" "$workflow" >/dev/null
test "$(grep -c -F 'require_no_private_key_marker "$candidate" "$name"' "$workflow")" -eq 1
test "$(grep -c -F 'require_no_private_key_marker "$retained_candidate" "$name"' "$workflow")" -eq 1
grep -F 'if test "$scan_status" -ne 1; then' "$workflow" >/dev/null
vm_step_line=$(grep -n -m 1 -F 'name: Run the disposable Debian 13 proof VM' "$workflow" | cut -d: -f1)
vm_next_step_line=$(awk -v minimum="$vm_step_line" \
    'NR > minimum && /^      - name:/ { print NR; exit }' "$workflow")
if [ -z "$vm_step_line" ] || [ -z "$vm_next_step_line" ]; then
    printf '%s\n' 'the bounded VM run step cannot be isolated' >&2
    exit 1
fi
vm_step_fixture=$temporary_directory/vm-proof-step.yml
sed -n "${vm_step_line},$((vm_next_step_line - 1))p" "$workflow" >"$vm_step_fixture"
vm_identity_line=$(grep -n -m 1 -F 'test "$(stat -Lc' "$vm_step_fixture" | cut -d: -f1)
vm_acl_line=$(grep -n -m 1 -F 'sudo setfacl --modify "u:${runner_user}:rw-" /dev/kvm' \
    "$vm_step_fixture" | cut -d: -f1)
vm_read_line=$(grep -n -m 1 -F 'test -r /dev/kvm' "$vm_step_fixture" | cut -d: -f1)
vm_write_line=$(grep -n -m 1 -F 'test -w /dev/kvm' "$vm_step_fixture" | cut -d: -f1)
vm_runner_line=$(grep -n -m 1 -F 'tests/helper/run-helper-boundary-evidence-vm.sh' \
    "$vm_step_fixture" | cut -d: -f1)
if [ -z "$vm_identity_line" ] || [ -z "$vm_acl_line" ] \
    || [ -z "$vm_read_line" ] || [ -z "$vm_write_line" ] \
    || [ -z "$vm_runner_line" ] \
    || [ "$vm_identity_line" -ge "$vm_acl_line" ] \
    || [ "$vm_acl_line" -ge "$vm_read_line" ] \
    || [ "$vm_read_line" -ge "$vm_write_line" ] \
    || [ "$vm_write_line" -ge "$vm_runner_line" ]; then
    printf '%s\n' 'the KVM ACL is not reinforced inside the VM run step' >&2
    exit 1
fi
restore_acl_line=$(grep -n -m 1 -F 'name: Restore the exact KVM device ACL' "$workflow" | cut -d: -f1)
pass_upload_line=$(grep -n -m 1 -F 'name: Upload bounded helper-boundary evidence' "$workflow" | cut -d: -f1)
if [ -z "$restore_acl_line" ] || [ -z "$pass_upload_line" ] \
    || [ "$restore_acl_line" -ge "$pass_upload_line" ]; then
    printf '%s\n' 'the PASS artifact can be uploaded before exact KVM ACL restoration' >&2
    exit 1
fi

workflow_manifest_line=$(grep -n -m 1 -F 'manifest_sha256=c535c54e' "$workflow" | cut -d: -f1)
workflow_url_line=$(grep -n -m 1 -F 'image_url=$(jq' "$workflow" | cut -d: -f1)
workflow_curl_line=$(awk -v minimum="$workflow_url_line" \
    'NR > minimum && $1 == "curl" && $2 == "\\" { print NR; exit }' "$workflow")
if [ -z "$workflow_manifest_line" ] || [ -z "$workflow_url_line" ] \
    || [ -z "$workflow_curl_line" ] \
    || [ "$workflow_manifest_line" -ge "$workflow_url_line" ] \
    || [ "$workflow_url_line" -ge "$workflow_curl_line" ]; then
    printf '%s\n' 'the workflow does not validate the manifest before network use' >&2
    exit 1
fi

if grep -Eq 'pull_request_target:|pull_request:|push:|schedule:|secrets\.' "$workflow"; then
    printf '%s\n' 'the retained evidence workflow has an unsafe trigger or secret dependency' >&2
    exit 1
fi
uses_count=$(grep -c '^[[:space:]]*uses:' "$workflow")
if [ "$uses_count" -ne 3 ]; then
    printf 'expected exactly three pinned action uses, got %s\n' "$uses_count" >&2
    exit 1
fi

printf '%s\n' \
    'PASS: helper-boundary VM preview, image provenance, KVM-only runner, and main-only workflow contracts are exact.'
