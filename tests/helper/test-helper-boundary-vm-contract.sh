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
live_gate=$script_directory/require-live-worker-identity-proof.sh
manifest=$script_directory/debian13-amd64-image-v1.json
workflow=$repository_directory/.github/workflows/helper-boundary-evidence.yml
supervisor=$script_directory/qemu-pidfd-supervisor.py
environment_validator=$script_directory/validate-helper-boundary-vm-environment-v1.sh
environment_test=$script_directory/test-helper-boundary-vm-environment-v1.sh
evidence_fixture=$script_directory/fixtures/helper-boundary-evidence-v1.pass.json
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
    "$runner" "$live_gate" "$manifest" "$workflow" "$supervisor" \
    "$environment_validator" "$environment_test" "$evidence_fixture"
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
sh -n "$live_gate"
jq -e . "$manifest" >/dev/null

if [ "$(grep -Fc -- '--property=RestrictSUIDSGID=no' "$live_gate")" -ne 4 ] \
    || grep -F -- '--property=RestrictSUIDSGID=yes' "$live_gate" >/dev/null \
    || [ "$(grep -Fc -- \
        "capture_unit_property RestrictSUIDSGID \\" "$live_gate")" -ne 2 ]; then
    printf '%s\n' \
        'the VM payload does not preserve the helper-specific openat2 compatibility contract' >&2
    exit 1
fi
if [ "$(grep -Fc 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=' "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc 'VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=' "$live_gate")" -ne 1 ] \
    || [ "$(grep -Ec '^[[:space:]]*driver_phase=(staging|worker-launch|worker-terminal-observation|worker-retirement|production-launch|production-observation|production-retirement|restart-launch|restart-observation|restart-retirement|may-own-launch|may-own-first-crash|may-own-second-crash|may-own-recovery|may-own-retirement|final-verification)$' \
        "$live_gate")" -ne 16 ] \
    || [ "$(grep -Ec '^[[:space:]]*final_checkpoint=(host-state|structured-reporting|cleanup-summary|lifecycle-summary|artifact-integrity|source-integrity|report-times|report-generation|report-validation|restart-report-validation|publication-fence|stage-retirement)$' \
        "$live_gate")" -ne 12 ] \
    || [ "$(grep -Fc 'structured_failure_reported=yes' "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc 'report_unexpected_driver_phase "${driver_phase:-}" || :' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc 'report_unexpected_final_checkpoint "${final_checkpoint:-}" || :' \
        "$live_gate")" -ne 1 ]; then
    printf '%s\n' \
        'the VM payload does not preserve fixed unexpected driver and final-checkpoint records' >&2
    exit 1
fi
if [ "$(grep -Fxc '    identity_launch=' "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc 'if command exec 9<>"$production_lock_path"; then' \
        "$live_gate")" -ne 1 ] \
    || grep -F 'if exec 9<>"$production_lock_path"; then' "$live_gate" >/dev/null; then
    printf '%s\n' \
        'the VM payload does not preserve status-2-safe production observation and lock probing' >&2
    exit 1
fi
if [ "$(grep -Fc -- '--slice=system.slice' "$live_gate")" -ne 4 ] \
    || [ "$(grep -Fc -- \
        'capture_unit_property ControlGroup "$temporary_stage/unit-control-group"' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- \
        'capture_unit_property Slice "$temporary_stage/unit-slice"' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- '[ -n "$observed_terminal_control_group" ]' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- '[ "$observed_slice" != system.slice ]' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- \
        'worker_control_group=/system.slice/$unit_name' "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- \
        'capture_unit_property Slice "$temporary_stage/production-slice"' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- '[ "$production_slice" != system.slice ]' \
        "$live_gate")" -ne 1 ] \
    || [ "$(grep -Fc -- \
        'capture_unit_property ControlGroup "$temporary_stage/production-control-group"' \
        "$live_gate")" -ne 1 ]; then
    printf '%s\n' \
        'the VM payload does not preserve exact terminal worker placement and live production cgroup proof' >&2
    exit 1
fi

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
expect_status 64 "$runner" --preview --retained-main
expect_status 64 "$runner" --preview --image /tmp/image
expect_status 64 "$runner" --execute
expect_status 64 "$runner" --execute --yes --yes
expect_status 64 "$runner" --execute --yes --retained-main --non-retained-pr-smoke
expect_status 64 "$runner" --execute --yes --image
expect_status 64 "$runner" --execute --yes --image /tmp/image --output /tmp/output
expect_status 64 "$runner" --unknown
expect_status 77 "$runner" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output --expected-commit invalid \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity '1:2:a:b:character special file'

# Exercise the execute-mode argument parser independently of local VM tools.
# A canonical process/KVM contract must parse before any host inspection, while
# every missing, duplicated, or malformed affine expectation fails closed.
argument_parser_fixture=$temporary_directory/runner-argument-parser.sh
awk '
    /^if \[ "\$\(id -u\)" -eq 0 \]; then$/ { exit }
    { print }
' "$runner" >"$argument_parser_fixture"
test -s "$argument_parser_fixture"
sh -n "$argument_parser_fixture"
chmod 0700 "$argument_parser_fixture"
canonical_commit=1111111111111111111111111111111111111111
canonical_kvm_identity='1:2:a:b:character special file'

expect_status 0 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"

expect_status 0 "$argument_parser_fixture" --execute --yes --non-retained-pr-smoke \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/feature/helper-smoke \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"

expect_status 64 "$argument_parser_fixture" --execute --yes \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 77 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/feature/helper-smoke \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
grep -F 'retained evidence requires refs/heads/main' "$last_stderr" >/dev/null
expect_status 77 "$argument_parser_fixture" --execute --yes --non-retained-pr-smoke \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
grep -F 'main can never select non-retained PR smoke' "$last_stderr" >/dev/null
expect_status 77 "$argument_parser_fixture" --execute --yes --non-retained-pr-smoke \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/tags/not-a-branch \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
grep -F 'the expected source ref is not one branch ref' "$last_stderr" >/dev/null
expect_status 64 "$argument_parser_fixture" --execute --yes --non-retained-pr-smoke \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/feature/helper-smoke \
    --expected-source-ref refs/heads/feature/substitution \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 77 "$argument_parser_fixture" --execute --yes --non-retained-pr-smoke \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/-unsafe \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
grep -F 'the expected source ref is not canonical' "$last_stderr" >/dev/null

expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108

expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
expect_status 64 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity" \
    --expected-kvm-identity "$canonical_kvm_identity"

expect_status 77 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid invalid \
    --expected-kvm-gid 108 \
    --expected-kvm-identity "$canonical_kvm_identity"
grep -F 'the expected host UID is not canonical nonzero decimal' \
    "$last_stderr" >/dev/null
expect_status 77 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 0 \
    --expected-kvm-identity "$canonical_kvm_identity"
grep -F 'the expected KVM GID is not canonical nonzero decimal' \
    "$last_stderr" >/dev/null
expect_status 77 "$argument_parser_fixture" --execute --yes --retained-main \
    --image /tmp/image --output /tmp/output \
    --expected-commit "$canonical_commit" \
    --expected-source-ref refs/heads/main \
    --expected-host-uid 1000 \
    --expected-kvm-gid 108 \
    --expected-kvm-identity invalid
grep -F 'the expected KVM identity' "$last_stderr" >/dev/null

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
    '--retained-main' \
    '--non-retained-pr-smoke' \
    '--expected-source-ref refs/heads/BRANCH' \
    '[ "$expected_source_ref" = refs/heads/main ]' \
    '[ "$expected_source_ref" != refs/heads/main ]' \
    '[ "$source_branch" = "$expected_source_branch" ]' \
    'main can never run non-retained PR smoke' \
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
    '--branch "$expected_source_branch"' \
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
    'sudo -n -- ./tests/helper/require-live-worker-identity-proof.sh --execute --yes' \
    'cargo fetch --locked' \
    'cargo build --locked --offline' \
    'run the fixed helper-boundary proof plus exact CleanupConfirmed and MayOwn Relay restart slices as guest root;' \
    'shut down, rehash the base image, validate, and publish eleven bounded files;' \
    'proof_network: {external_https: "denied", mode: "qemu-user-restrict-on"}' \
    'post_image_sha512=$(sha512sum "$image_path"' \
    '[ "$safe_to_remove" = yes ] && [ "$proof_mode" = retained-main ]' \
    'if [ "$proof_mode" = retained-main ]; then' \
    'the non-retained PR smoke output directory is not empty' \
    'PASS: non-retained helper-boundary PR smoke completed in the disposable Debian 13 KVM.'
do
    grep -F -- "$exact_runner_text" "$runner" >/dev/null
done

success_console_start=$(grep -n -m 1 -F \
    "settle_console || failed 'the bounded console log did not settle'" \
    "$runner" | cut -d: -f1)
success_console_end=$(grep -n -m 1 -F \
    'post_image_sha512=$(sha512sum "$image_path"' "$runner" | cut -d: -f1)
if [ -z "$success_console_start" ] || [ -z "$success_console_end" ] \
    || [ "$success_console_start" -ge "$success_console_end" ]; then
    printf '%s\n' 'the successful console-publication fence is missing or reordered' >&2
    exit 1
fi
success_console_block=$temporary_directory/success-console-publication.sh
sed -n "${success_console_start},$((success_console_end - 1))p" "$runner" \
    >"$success_console_block"
if [ "$(grep -Fc 'if [ "$proof_mode" = retained-main ]; then' \
        "$success_console_block")" -ne 1 ] \
    || [ "$(grep -Fc \
        "publish_console || failed 'the bounded console log could not be published atomically'" \
        "$success_console_block")" -ne 1 ] \
    || ! awk '
        /if \[ "\$proof_mode" = retained-main \]; then/ { opened = NR }
        /publish_console \|\| failed/ { published = NR }
        /^fi$/ { closed = NR }
        END { if (!(opened < published && published < closed)) exit 1 }
      ' "$success_console_block"; then
    printf '%s\n' 'successful console publication is not retained-main-only' >&2
    exit 1
fi
if grep -F -- 'sudo -n prlimit --fsize=' "$guest_proof_fixture" >/dev/null \
    || grep -F -- 'prlimit --fsize=1048576:1048576 --' \
        "$guest_proof_fixture" >/dev/null; then
    printf '%s\n' 'the guest runner wraps the complete root proof in an outer file-size limit' >&2
    exit 1
fi

# The runner treats the workflow-supplied process and KVM facts as affine
# expectations. It checks the complete Linux credential/capability view at
# startup and again inside start_vm, before either supervised QEMU process.
kvm_contract_function=$temporary_directory/verify-kvm-contract.sh
sed -n '/^verify_kvm_contract() {$/,/^}$/p' "$runner" \
    >"$kvm_contract_function"
test "$(grep -c '^verify_kvm_contract() {$' "$kvm_contract_function")" -eq 1
sh -n "$kvm_contract_function"
for exact_kvm_contract_text in \
    '$expected_host_uid' \
    '$expected_kvm_gid' \
    '$expected_kvm_identity' \
    'expected_uid_quad="$expected_host_uid:$expected_host_uid:$expected_host_uid:$expected_host_uid"' \
    'expected_gid_quad="$expected_kvm_gid:$expected_kvm_gid:$expected_kvm_gid:$expected_kvm_gid"' \
    '/proc/self/status' \
    'Uid:' \
    'Gid:' \
    'Groups:' \
    'CapInh:' \
    'CapPrm:' \
    'CapEff:' \
    'CapBnd:' \
    'CapAmb:' \
    'NoNewPrivs:' \
    '/dev/kvm'
do
    grep -F -- "$exact_kvm_contract_text" "$kvm_contract_function" >/dev/null
done
if ! grep -Eq '\*\[!0\]\*|\^0\+\$|0000000000000000' \
    "$kvm_contract_function"; then
    printf '%s\n' 'the KVM process contract does not require zero capabilities' >&2
    exit 1
fi
grep -F -- '-c /dev/kvm' "$kvm_contract_function" >/dev/null
grep -F -- '-r /dev/kvm' "$kvm_contract_function" >/dev/null
grep -F -- '-w /dev/kvm' "$kvm_contract_function" >/dev/null
grep -F -- "stat -Lc '%d:%i:%t:%T:%F' /dev/kvm" \
    "$kvm_contract_function" >/dev/null
grep -F -- "stat -Lc '%u:%g' /dev/kvm" "$kvm_contract_function" >/dev/null
test "$(grep -Ec '^[[:space:]]*verify_kvm_contract[[:space:]]*\\?$' "$runner")" -ge 2
initial_kvm_contract_line=$(grep -n -m 1 -E \
    '^verify_kvm_contract[[:space:]]*\\?$' "$runner" | cut -d: -f1)
qemu_selection_line=$(grep -n -m 1 -F 'qemu_system=qemu-system-x86_64' \
    "$runner" | cut -d: -f1)
if [ -z "$initial_kvm_contract_line" ] || [ -z "$qemu_selection_line" ] \
    || [ "$initial_kvm_contract_line" -ge "$qemu_selection_line" ]; then
    printf '%s\n' 'the initial full KVM process contract is not checked before QEMU setup' >&2
    exit 1
fi

start_vm_function=$temporary_directory/start-vm.sh
sed -n '/^start_vm() {$/,/^}$/p' "$runner" >"$start_vm_function"
test "$(grep -c '^start_vm() {$' "$start_vm_function")" -eq 1
sh -n "$start_vm_function"
test "$(grep -c -F 'verify_kvm_contract' "$start_vm_function")" -eq 1
start_vm_kvm_line=$(grep -n -m 1 -F 'verify_kvm_contract' \
    "$start_vm_function" | cut -d: -f1)
start_vm_qemu_line=$(grep -n -m 1 -F 'python3 "$qemu_supervisor"' \
    "$start_vm_function" | cut -d: -f1)
if [ -z "$start_vm_kvm_line" ] || [ -z "$start_vm_qemu_line" ] \
    || [ "$start_vm_kvm_line" -ge "$start_vm_qemu_line" ]; then
    printf '%s\n' 'the full KVM process contract is not checked before QEMU' >&2
    exit 1
fi
test "$(grep -c '^start_vm [a-z]' "$runner")" -eq 2

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

# The in-guest validator classifier may publish only one fixed stage. Exercise
# the reviewed functions against every stage and adversarial private captures.
boundary_validator_functions=$temporary_directory/boundary-validator-functions.sh
{
    sed -n '/^boundary_validator_failure_stage_is_safe() {$/,/^}$/p' "$live_gate"
    sed -n '/^report_boundary_validator_failure_diagnostic() {$/,/^}$/p' "$live_gate"
} >"$boundary_validator_functions"
test "$(grep -c '^[_a-z].*() {$' "$boundary_validator_functions")" -eq 2
sh -n "$boundary_validator_functions"
# shellcheck disable=SC1090
. "$boundary_validator_functions"

vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -Lc '%h:%u:%a' "$1" 2>/dev/null || true)" \
        = "1:$(id -u):600" ]
}

boundary_validator_report=$temporary_directory/boundary-validator-report.json
boundary_validator_stdout=$temporary_directory/boundary-validator.stdout
boundary_validator_stderr=$temporary_directory/boundary-validator.stderr
boundary_validator_privacy_sentinel='private-validator-payload-must-not-escape'
reset_boundary_validator_inputs() {
    install -m 0600 -- "$evidence_fixture" "$boundary_validator_report"
    install -m 0600 /dev/null "$boundary_validator_stdout"
    printf '%s\n' "$boundary_validator_privacy_sentinel" \
        >"$boundary_validator_stderr"
    chmod 0600 "$boundary_validator_stderr"
}
expect_boundary_validator_stage() {
    expected_boundary_validator_stage=$1
    boundary_validator_test_status=$2
    expect_status 0 report_boundary_validator_failure_diagnostic \
        "$boundary_validator_report" "$boundary_validator_test_status" \
        "$boundary_validator_stdout" "$boundary_validator_stderr"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=$expected_boundary_validator_stage"
    if grep -F "$boundary_validator_privacy_sentinel" \
        "$last_stdout" "$last_stderr" >/dev/null; then
        printf '%s\n' 'validator classifier exposed a private payload' >&2
        exit 1
    fi
}

for boundary_validator_allowed_stage in \
    capture-unsafe status-invalid stdout-nonempty status-zero stderr-empty \
    input-size json-value canonical-encoding source-artifacts environment \
    clock-format clock-order invocations lifecycle host-state fixed-contract
do
    expect_status 0 boundary_validator_failure_stage_is_safe \
        "$boundary_validator_allowed_stage"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done
expect_status 1 boundary_validator_failure_stage_is_safe private-runtime-detail
test ! -s "$last_stdout" && test ! -s "$last_stderr"

reset_boundary_validator_inputs
chmod 0644 "$boundary_validator_report"
expect_boundary_validator_stage capture-unsafe 1
reset_boundary_validator_inputs
expect_boundary_validator_stage status-invalid 01
reset_boundary_validator_inputs
printf '%s\n' unexpected-validator-output >"$boundary_validator_stdout"
expect_boundary_validator_stage stdout-nonempty 1
reset_boundary_validator_inputs
expect_boundary_validator_stage status-zero 0
reset_boundary_validator_inputs
: >"$boundary_validator_stderr"
expect_boundary_validator_stage stderr-empty 1
reset_boundary_validator_inputs
dd if=/dev/zero of="$boundary_validator_report" bs=32769 count=1 \
    >/dev/null 2>&1
chmod 0600 "$boundary_validator_report"
expect_boundary_validator_stage input-size 1
reset_boundary_validator_inputs
printf '%s\n' not-json >"$boundary_validator_report"
expect_boundary_validator_stage json-value 1
reset_boundary_validator_inputs
jq . "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage canonical-encoding 1

# A failing canonicalization tool must not add its raw stderr to the one fixed
# diagnostic record. The first JSON-value probe still uses the real jq binary;
# only the following canonical-encoding probe emits the private sentinel.
boundary_validator_jq=$(command -v jq)
boundary_validator_jq_privacy_sentinel='private-canonical-jq-stderr-must-not-escape'
exercise_boundary_validator_jq_stderr() (
    boundary_validator_jq_binary=$1
    # Invoked indirectly by the extracted classifier under test.
    # shellcheck disable=SC2317
    jq() {
        if [ "$#" -ge 3 ] \
            && [ "$1" = -S ] && [ "$2" = -c ] && [ "$3" = . ]; then
            printf '%s\n' "$boundary_validator_jq_privacy_sentinel" >&2
            return 1
        fi
        "$boundary_validator_jq_binary" "$@"
    }
    report_boundary_validator_failure_diagnostic \
        "$boundary_validator_report" 1 \
        "$boundary_validator_stdout" "$boundary_validator_stderr"
)
reset_boundary_validator_inputs
expect_status 0 exercise_boundary_validator_jq_stderr "$boundary_validator_jq"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=canonical-encoding'
if grep -F "$boundary_validator_jq_privacy_sentinel" \
    "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'canonical jq stderr escaped the validator classifier' >&2
    exit 1
fi

reset_boundary_validator_inputs
jq -S -c '.observed_source.commit_sha = "0"' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage source-artifacts 1
reset_boundary_validator_inputs
jq -S -c '.observed_artifact_hashes.volparossa_helper_sha256 = ("0" * 64)' \
    "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage source-artifacts 1
reset_boundary_validator_inputs
jq -S -c '.environment.virtualization = "container"' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage environment 1
reset_boundary_validator_inputs
jq -S -c '.started_at = "invalid"' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage clock-format 1
reset_boundary_validator_inputs
jq -S -c '.finished_at = "2026-08-27T11:59:59Z"' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage clock-order 1
reset_boundary_validator_inputs
jq -S -c '.invocation_ids[1] = .invocation_ids[0]' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage invocations 1
reset_boundary_validator_inputs
jq -S -c '.production.fdstore_idle_observation = 1' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage lifecycle 1
reset_boundary_validator_inputs
jq -S -c '.worker.fdstore_before_retirement = 1' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage lifecycle 1
reset_boundary_validator_inputs
jq -S -c '.retirement.socket_absent = false' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage lifecycle 1
reset_boundary_validator_inputs
jq -S -c '.enumerated_host_state.equal_at_fences = false' \
    "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage host-state 1
reset_boundary_validator_inputs
jq -S -c '.overall = "FAIL"' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage fixed-contract 1
reset_boundary_validator_inputs
jq -S -c '.scope.helper_boundary_only = false' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage fixed-contract 1
reset_boundary_validator_inputs
jq -S -c '.checks[0].result = "FAIL"' "$evidence_fixture" \
    >"$boundary_validator_report"
expect_boundary_validator_stage fixed-contract 1

# Multiple faults must retain the first validator-ordered, value-free stage.
reset_boundary_validator_inputs
chmod 0644 "$boundary_validator_report"
printf '%s\n' unexpected-validator-output >"$boundary_validator_stdout"
expect_boundary_validator_stage capture-unsafe 01
reset_boundary_validator_inputs
printf '%s\n' unexpected-validator-output >"$boundary_validator_stdout"
expect_boundary_validator_stage status-invalid 01
reset_boundary_validator_inputs
jq -S -c '
    .schema_version = 2
    | .observed_source.commit_sha = "0"
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage fixed-contract 1
reset_boundary_validator_inputs
jq -S -c '
    .observed_source.commit_sha = "0"
    | .environment.virtualization = "container"
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage source-artifacts 1
reset_boundary_validator_inputs
jq -S -c '
    .environment.virtualization = "container"
    | .started_at = "invalid"
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage environment 1
reset_boundary_validator_inputs
jq -S -c '
    .finished_at = "2026-08-27T11:59:59Z"
    | .invocation_ids[1] = .invocation_ids[0]
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage clock-order 1
reset_boundary_validator_inputs
jq -S -c '
    .invocation_ids[1] = .invocation_ids[0]
    | .production.fdstore_idle_observation = 1
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage invocations 1
reset_boundary_validator_inputs
jq -S -c '
    .production.fdstore_idle_observation = 1
    | .enumerated_host_state.equal_at_fences = false
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage lifecycle 1
reset_boundary_validator_inputs
jq -S -c '
    .enumerated_host_state.equal_at_fences = false
    | .overall = "FAIL"
' "$evidence_fixture" >"$boundary_validator_report"
expect_boundary_validator_stage host-state 1

if ! awk '
    /^    report_boundary_validator_failure_diagnostic \\$/ {
        diagnostic_call = NR; diagnostic_call_count++
    }
    /^        "\$validator_stderr" \|\| :$/ {
        diagnostic_fallback = NR; diagnostic_fallback_count++
    }
    /^    failed '\''the helper-boundary report failed strict validation'\''$/ {
        strict_failure = NR; strict_failure_count++
    }
    END {
        valid = diagnostic_call_count == 1 && diagnostic_fallback_count == 1
        valid = valid && strict_failure_count == 1
        valid = valid && diagnostic_call < diagnostic_fallback
        valid = valid && diagnostic_fallback < strict_failure
        if (!valid) exit 1
    }
' "$live_gate"; then
    printf '%s\n' 'validator failure is not classified before fail-closed exit' >&2
    exit 1
fi

# A failed non-retained proof may publish only enumerated privacy-safe category
# and progress records. Exercise the reviewed parsers rather than test-only copies.
branch_failure_functions=$temporary_directory/branch-failure-functions.sh
{
    sed -n '/^non_retained_proof_failure_reason_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_blocked_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_blocked_status_is_exact() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_driver_phase_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_final_checkpoint_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^require_no_private_key_marker() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_blocked_category() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_proof_failure_reason() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_may_own_launch_failure_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_may_own_preexec_barrier_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_may_own_launch_failure_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_boundary_validator_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_boundary_validator_failure_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_successor_debugger_category_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_retirement_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_readiness_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_readiness_failure_detail_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_retirement_failure_detail_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_launch_failure_category() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_initial_hook_failure_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_initial_driver_failure_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_restart_initial_failure_detail_category() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_restart_launch_failure_category() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_restart_launch_diagnostic() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_restart_crash_record_diagnostic() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_driver_phase() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_final_checkpoint() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_worker_launch_diagnostic() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_worker_confinement_diagnostic() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_production_launch_stage_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^non_retained_functional_probe_failure_value_is_safe() {$/,/^}$/p' "$runner"
    sed -n '/^report_non_retained_production_launch_diagnostic() {$/,/^}$/p' "$runner"
} >"$branch_failure_functions"
test "$(grep -c '^[_a-z].*() {$' "$branch_failure_functions")" -eq 32
sh -n "$branch_failure_functions"
# shellcheck disable=SC1090
. "$branch_failure_functions"

expect_status 0 non_retained_blocked_status_is_exact 77
test ! -s "$last_stdout" && test ! -s "$last_stderr"
for non_blocked_status in 0 1 64 76 78 125 255; do
    expect_status 1 non_retained_blocked_status_is_exact "$non_blocked_status"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done

branch_failure_diagnostic=$temporary_directory/branch-failure-diagnostic
branch_failure_privacy_sentinel='private-runtime-payload-must-not-escape'
for boundary_validator_public_stage in \
    capture-unsafe status-invalid stdout-nonempty status-zero stderr-empty \
    input-size json-value canonical-encoding source-artifacts environment \
    clock-format clock-order invocations lifecycle host-state fixed-contract
do
    printf '%s\n%s\n%s=%s\n' \
        "$branch_failure_privacy_sentinel" \
        'live worker-identity proof failed: the helper-boundary report failed strict validation' \
        'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1' \
        "$boundary_validator_public_stage" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_boundary_validator_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke report-validation category: $boundary_validator_public_stage"
    if grep -F "$branch_failure_privacy_sentinel" \
        "$last_stdout" "$last_stderr" >/dev/null; then
        printf '%s\n' 'outer validator category exposed a private payload' >&2
        exit 1
    fi
done

printf '%s\n%s\n' \
    'live worker-identity proof failed: the helper-boundary report failed strict validation' \
    'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=private-runtime-detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_boundary_validator_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"
printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: the helper-boundary report failed strict validation' \
    'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=clock-order' \
    'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=clock-order' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_boundary_validator_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"
printf '%s\n' \
    'live worker-identity proof failed: the helper-boundary report failed strict validation' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_boundary_validator_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"
printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: the helper-boundary report failed strict validation' \
    'live worker-identity proof failed: private runtime detail' \
    'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=clock-order' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_boundary_validator_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"
chmod 0644 "$branch_failure_diagnostic"
expect_status 1 report_non_retained_boundary_validator_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"
chmod 0600 "$branch_failure_diagnostic"

printf '%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'BLOCKED: the fixed root-owned debugger is unavailable' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_blocked_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke blocked category: debugger'
if grep -F "$branch_failure_privacy_sentinel" \
    "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'blocked category exposed a non-allowlisted payload' >&2
    exit 1
fi

printf '%s\n' 'BLOCKED: required Debian tool is unavailable: gdb' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_blocked_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke blocked category: tool-gdb'

printf '%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash debugger did not complete' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=restart-launch' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: debugger-execution'

while IFS='|' read -r initial_identity_reason initial_identity_category; do
    printf 'live worker-identity proof failed: %s\n' \
        "$initial_identity_reason" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_restart_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke restart-launch category: $initial_identity_category"
done <<'EOF'
singleton restart initial MainPID is unavailable|initial-mainpid-read
singleton restart initial MainPID is invalid|initial-mainpid-shape
singleton restart initial invocation is not hook-bound|initial-invocation-binding
singleton restart initial MainPID is not hook-bound|initial-mainpid-binding
singleton restart initial hook PID is unavailable|initial-hook-pid-read
singleton restart initial hook PID is invalid|initial-hook-pid-shape
singleton restart initial ControlPID is not hook-bound|initial-controlpid-binding
singleton restart initial hook starttime is unavailable|initial-hook-starttime
EOF

while IFS='|' read -r sigkill_reason sigkill_category; do
    printf 'live worker-identity proof failed: %s\n' \
        "$sigkill_reason" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_restart_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke restart-launch category: $sigkill_category"
done <<'EOF'
post-crash forced-helper MainPID is not zero|sigkill-mainpid
post-crash forced-helper restart count is not zero|sigkill-restart-count
post-crash forced-helper result is not signal|sigkill-result
post-crash forced-helper code is not CLD_KILLED|sigkill-code
post-crash forced-helper status is not SIGKILL|sigkill-status
initial forced-crash start failure record was not consumed exactly|initial-diagnostic-absent
EOF

for restart_initial_hook_stage in \
    preflight publication ack-path ack-payload ack-lineage ack-pins \
    ack-timeout post-lineage post-pins cleanup terminal-publication \
    terminal-ack-path terminal-ack-payload terminal-ack-lineage \
    terminal-ack-pins terminal-ack-timeout terminal-post-lineage \
    terminal-post-pins
do
    printf '%s\n%s=%s\n' \
        'live worker-identity proof failed: initial forced-crash start failure record was not consumed exactly' \
        'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_HOOK_V1' \
        "$restart_initial_hook_stage" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_restart_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke restart-launch category: initial-hook-$restart_initial_hook_stage"
done
for restart_initial_driver_stage in \
    appearance unsafe-pending-path main-pid restart-count invocation marker \
    start-payload hook-payload terminal-payload stable-inode unlink absence \
    control-pid hook-identity hook-quiescence
do
    printf '%s\n%s=%s\n' \
        'live worker-identity proof failed: initial forced-crash start failure record was not consumed exactly' \
        'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_DRIVER_V1' \
        "$restart_initial_driver_stage" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_restart_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke restart-launch category: initial-driver-$restart_initial_driver_stage"
done
printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash start failure record was not consumed exactly' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_START_V1=publication' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_DRIVER_V1=start-payload' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: initial-driver-start-payload-publication'
printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash start failure record was not consumed exactly' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_START_V1=private-runtime-payload' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_DRIVER_V1=start-payload' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: initial-diagnostic-invalid'
printf '%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash start failure record was not consumed exactly' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_HOOK_V1=private-runtime-payload' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: initial-diagnostic-invalid'
if grep -F 'private-runtime-payload' "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'initial restart category exposed private diagnostic payload' >&2
    exit 1
fi
printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash start failure record was not consumed exactly' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_HOOK_V1=preflight' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_DRIVER_V1=appearance' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: initial-diagnostic-invalid'

printf '%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash terminal handshake was not released exactly' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_HOOK_V1=terminal-post-pins' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: initial-hook-terminal-post-pins'

while IFS='|' read -r successor_reason successor_category; do
    printf 'live worker-identity proof failed: %s\n' \
        "$successor_reason" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_restart_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke restart-launch category: $successor_category"
done <<'EOF'
restart successor did not become manager-bound|successor-mainpid
restart successor changed before its pre-exec barrier|successor-mainpid
restart successor pre-exec barrier did not appear|successor-barrier
restart successor pre-exec barrier is oversized|successor-barrier
restart successor barrier invocation is unavailable|successor-barrier
restart successor barrier PID is unavailable|successor-barrier
restart successor barrier expectation could not be created|successor-barrier
restart successor barrier expectation is unavailable|successor-barrier
restart successor pre-exec barrier is not manager-bound|successor-barrier
restart successor starttime is unavailable|successor-identity
restart successor count is unavailable|successor-identity
restart successor count is not exactly one|successor-identity
restart successor lost the ownership marker|successor-identity
restart successor lineage could not be adopted|successor-identity
restart successor invocation is invalid|successor-identity
restart successor lineage changed after adoption|successor-identity
successor debugger commands could not be written|successor-debugger-command
successor debugger starttime is unavailable|successor-debugger-start
successor debugger exited before arming|successor-debugger-start
successor debugger did not arm|successor-debugger-start
successor debugger readiness record is unsafe|successor-debugger-start
successor debugger readiness record is oversized|successor-debugger-start
successor debugger readiness record is invalid|successor-debugger-start
restart successor release FIFO changed before release|successor-release
restart successor pre-exec barrier could not be released|successor-release
restart successor release FIFO changed after release|successor-release
successor recovery-boundary debugger did not complete|successor-debugger-execution
successor recovery boundary is not exact|successor-debugger-execution
successor debugger failure classification is invalid|successor-debugger-classification
successor recovery-boundary debugger failed: exec-not-caught|successor-debugger-exec-not-caught
successor recovery-boundary debugger failed: breakpoint-not-installed|successor-debugger-breakpoint-not-installed
successor recovery-boundary debugger failed: breakpoint-not-reached|successor-debugger-breakpoint-not-reached
successor recovery-boundary debugger failed: marker-invalid|successor-debugger-marker-invalid
successor recovery-boundary debugger failed: observer-manager-binding|successor-debugger-observer-manager-binding
successor recovery-boundary debugger failed: observer-precrash-record|successor-debugger-observer-precrash-record
successor recovery-boundary debugger failed: observer-fdstore-read|successor-debugger-observer-fdstore-read
successor recovery-boundary debugger failed: observer-fdstore-count|successor-debugger-observer-fdstore-count
successor recovery-boundary debugger failed: observer-fdstore-name|successor-debugger-observer-fdstore-name
successor recovery-boundary debugger failed: observer-journal-read|successor-debugger-observer-journal-read
successor recovery-boundary debugger failed: observer-journal-value|successor-debugger-observer-journal-value
successor recovery-boundary debugger failed: observer-invocation-read|successor-debugger-observer-invocation-read
successor recovery-boundary debugger failed: observer-invocation-reuse|successor-debugger-observer-invocation-reuse
successor recovery-boundary debugger failed: observer-mainpid-reuse|successor-debugger-observer-mainpid-reuse
successor recovery-boundary debugger failed: observer-restart-count|successor-debugger-observer-restart-count
successor recovery-boundary debugger failed: observer-socket-change|successor-debugger-observer-socket-change
successor recovery-boundary debugger failed: observer-time|successor-debugger-observer-time
successor recovery-boundary debugger failed: observer-starttime|successor-debugger-observer-starttime
successor recovery-boundary debugger failed: observer-record-build|successor-debugger-observer-record-build
successor recovery-boundary debugger failed: observer-record-publication|successor-debugger-observer-record-publication
successor recovery-boundary debugger failed: observer-timeout|successor-debugger-observer-timeout
successor recovery-boundary debugger failed: observer-other|successor-debugger-observer-other
successor recovery-boundary debugger failed: post-observer|successor-debugger-post-observer
successor debugger log is unsafe|successor-debugger-log
successor debugger log exceeds 1 MiB|successor-debugger-log
restart ExactPresent settlement did not complete|successor-settlement
restart successor start failure record is invalid|successor-start-record
restart successor pending start failure record is unsafe|successor-start-record
restart successor start failure category is invalid|successor-start-record
restart successor start hook failed during preflight|successor-start-preflight
restart successor start hook failed during recovery wait|successor-start-recovery
restart successor start hook failed during lineage validation|successor-start-lineage
restart successor start hook failed during descriptor settlement|successor-start-descriptor
restart successor readiness diagnostic is invalid|successor-start-readiness-classification
restart successor start hook failed during publication|successor-start-publication
restart successor invocation record is unavailable|successor-settlement-binding
restart successor invocation record is invalid|successor-settlement-binding
restart settlement changed the adopted successor invocation|successor-settlement-binding
restart boundary starttime is unavailable|successor-starttime-boundary-read
restart boundary starttime is invalid|successor-starttime-boundary-shape
restart successor starttime is unavailable after descriptor settlement|successor-starttime-post-detach-read
restart successor starttime changed after recovery|successor-starttime-post-detach-change
restart successor retirement failure category is invalid|successor-retirement-classification
restart successor retirement diagnostic could not be reported|successor-retirement-classification
restart unit was not collected|successor-collection
restart journal lock remained held|successor-lock-held
restart journal lock could not be opened after retirement|successor-lock-open
restart runtime did not retire cleanly|successor-runtime-retirement
restart final journal could not be revalidated|successor-final-journal-read
restart final journal proof is invalid|successor-final-journal-value
internal production proof failure state is inconsistent|successor-proof-state
EOF

for restart_readiness_reason in \
    'restart successor start hook failed during journal settlement' \
    'restart successor start hook failed during socket validation'
do
    for restart_readiness_stage in \
        preflight clock-read clock-backwards lineage-pid lineage-invocation \
        socket-capture \
        initial-journal-value stage-transition bind-runtime-read \
        bind-runtime-value final-journal-read final-journal-value journal-next \
        journal-state-before journal-state-after journal-state-change \
        socket-stability final-lineage-pid final-lineage-invocation timeout
    do
        printf 'live worker-identity proof failed: %s\n%s=%s\n' \
            "$restart_readiness_reason" \
            'VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1' \
            "$restart_readiness_stage" >"$branch_failure_diagnostic"
        expect_status 0 report_non_retained_restart_launch_failure_category \
            "$branch_failure_diagnostic"
        test ! -s "$last_stdout"
        test "$(cat "$last_stderr")" = \
            "non-retained helper-boundary PR smoke restart-launch category: successor-start-readiness-$restart_readiness_stage"
    done
done

printf '%s\n' \
    'live worker-identity proof failed: restart successor start hook failed during journal settlement' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: successor-start-journal'
printf '%s\n' \
    'live worker-identity proof failed: restart successor start hook failed during socket validation' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'live worker-identity proof failed: restart successor start hook failed during socket validation' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=private-runtime-detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: restart successor start hook failed during socket validation' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=timeout' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=timeout' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'live worker-identity proof failed: successor recovery-boundary debugger failed: private-runtime-detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

while IFS='|' read -r retirement_stage retirement_category; do
    printf '%s\n%s\n' \
        'live worker-identity proof failed: restart successor could not be retired' \
        "VOLPAROSSA_HELPER_LIVE_RESTART_RETIREMENT_DIAGNOSTIC_V1=$retirement_stage" \
        >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_restart_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke restart-launch category: $retirement_category"
done <<'EOF'
adoption|successor-retirement-adoption
identity|successor-retirement-identity
initial-snapshot|successor-retirement-initial-snapshot
stop-request|successor-retirement-stop-request
stop-wait|successor-retirement-stop-wait
reset-failed|successor-retirement-reset-failed
reset-wait|successor-retirement-reset-wait
fdstore-clean|successor-retirement-fdstore-clean
post-clean|successor-retirement-post-clean
final-reset|successor-retirement-final-reset
collection|successor-retirement-collection
EOF

printf '%s\n%s\n' \
    'live worker-identity proof failed: restart successor could not be retired' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_RETIREMENT_DIAGNOSTIC_V1=private-runtime-detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_LAUNCH_DIAGNOSTIC_V1=captures-yes,json-no,fresh-no,stdout-empty,stderr-empty,manager-no' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart launch diagnostic: captures-yes,json-no,fresh-no,stdout-empty,stderr-empty,manager-no'

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_LAUNCH_DIAGNOSTIC_V1=captures-yes,json-no,fresh-no,stdout-unit-only,stderr-empty,manager-no' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart launch diagnostic: captures-yes,json-no,fresh-no,stdout-unit-only,stderr-empty,manager-no'

printf '%s\n%s\n' \
    'live worker-identity proof failed: forced-crash boundary record is unavailable' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-fdstore-read' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_crash_record_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart crash-record diagnostic: record-absent,observer-fdstore-read'

printf '%s\n%s\n' \
    'live worker-identity proof failed: forced-crash boundary record is unavailable' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-control-binding' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_crash_record_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart crash-record diagnostic: record-absent,observer-control-binding'

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-fdstore-read' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=malformed' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_crash_record_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-private-runtime-detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_crash_record_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_LAUNCH_DIAGNOSTIC_V1=captures-yes,json-no,fresh-no,stdout-empty,stderr-empty,manager-yes' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'live worker-identity proof failed: singleton restart manager binding is invalid' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke restart-launch category: manager-binding'

printf '%s\n' \
    'live worker-identity proof failed: private restart detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

while IFS='|' read -r may_own_reason may_own_category may_own_phase; do
    printf 'live worker-identity proof failed: %s\n' "$may_own_reason" \
        >"$branch_failure_diagnostic"
    if [ "$may_own_category" = preexec-barrier ]; then
        printf '%s\n' \
            'VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1=shape-cgroup-stat' \
            >>"$branch_failure_diagnostic"
    fi
    printf 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=%s\n' "$may_own_phase" \
        >>"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_may_own_launch_failure_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    if [ "$may_own_category" = preexec-barrier ]; then
        test "$(cat "$last_stderr")" = \
            "$(printf '%s\n%s' \
                'non-retained helper-boundary PR smoke MayOwn launch category: preexec-barrier' \
                'non-retained helper-boundary PR smoke MayOwn preexec category: shape-cgroup-stat')"
    else
        test "$(cat "$last_stderr")" = \
            "non-retained helper-boundary PR smoke MayOwn launch category: $may_own_category"
    fi
done <<'EOF'
ExactPresent retirement was not confirmed before MayOwn proof|prerequisite|restart-retirement
MayOwn singleton unit name is unsafe|unit-name|may-own-launch
MayOwn singleton unit state could not be determined|unit-state-read|may-own-launch
MayOwn singleton unit name is already loaded|unit-state-present|may-own-launch
MayOwn debugger symbols could not be inspected|symbols-read|may-own-launch
MayOwn debugger symbols are not exact and unique|symbols-shape|may-own-launch
MayOwn ownership marker could not be derived|marker-derive|may-own-launch
MayOwn ownership marker is non-canonical|marker-canonical|may-own-launch
MayOwn ownership marker is unsafe|marker-shape|may-own-launch
MayOwn debugger command path was not initially absent|debugger-path|may-own-launch
MayOwn singleton unit could not be launched|launch-status|may-own-launch
MayOwn singleton launch envelope is invalid|launch-envelope|may-own-launch
MayOwn first MainPID did not appear|mainpid-appearance|may-own-launch
MayOwn first MainPID birth token is unavailable|mainpid-starttime|may-own-launch
MayOwn first private namespaces did not become stable|namespaces|may-own-launch
MayOwn first pre-exec barrier is not manager-bound|preexec-barrier|may-own-launch
MayOwn first external pre-exec observer did not arm|preexec-observer|may-own-launch
MayOwn first freeze handshake path is unsafe|handshake-path|may-own-launch
EOF

for may_own_preexec_category in \
    arguments \
    starttime \
    publication-unsafe \
    publication-timeout \
    lineage-mainpid \
    lineage-invocation \
    lineage-starttime \
    lineage-marker \
    shape-mainpid-argument \
    shape-invocation-argument \
    shape-count-arguments \
    shape-type \
    shape-restart-usec \
    shape-control-pid \
    shape-main-pid \
    shape-invocation \
    shape-restarts \
    shape-fdstore-count \
    shape-fdstore-max \
    shape-fdstore-preserve \
    shape-exec-start-post \
    shape-control-group \
    shape-control-group-id \
    shape-cgroup-path \
    shape-cgroup-procs \
    shape-cgroup-members \
    shape-cgroup-type \
    shape-cgroup-stat \
    record-size \
    expectation-create \
    expectation-write \
    record-content \
    launcher-executable \
    freezer
do
    expect_status 0 non_retained_may_own_preexec_barrier_stage_is_safe \
        "$may_own_preexec_category"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done
for unsafe_may_own_preexec_category in \
    '' private-detail shape-private /tmp/value 'shape-type value'
do
    expect_status 1 non_retained_may_own_preexec_barrier_stage_is_safe \
        "$unsafe_may_own_preexec_category"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done

printf '%s\n%s\n%s\n' \
    'live worker-identity proof failed: MayOwn first pre-exec barrier is not manager-bound' \
    'VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1=private-detail' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=may-own-launch' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_may_own_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n%s\n' \
    'live worker-identity proof failed: MayOwn first pre-exec barrier is not manager-bound' \
    'VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1=shape-type' \
    'VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1=freezer' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=may-own-launch' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_may_own_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'live worker-identity proof failed: private MayOwn launch detail' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_may_own_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'live worker-identity proof failed: MayOwn singleton unit name is unsafe' \
    'live worker-identity proof failed: MayOwn singleton unit state could not be determined' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_may_own_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

if ! awk '
    /^if \[ "\$guest_status" -ne 0 \]; then$/ { guest_failure = NR }
    /^        elif report_non_retained_boundary_validator_failure_category \\$/ {
        validator_call = NR; validator_call_count++
    }
    /^        elif report_non_retained_restart_launch_failure_category \\$/ {
        parser_call = NR; parser_call_count++
    }
    /^                report_non_retained_restart_crash_record_diagnostic \\$/ {
        crash_call = NR; crash_call_count++
    }
    /^        elif report_non_retained_may_own_launch_failure_category \\$/ {
        may_own_call = NR; may_own_call_count++
    }
    /non-retained helper-boundary PR smoke failure category: unclassified/ {
        unclassified = NR
    }
    END {
        valid = validator_call_count == 1 && parser_call_count == 1
        valid = valid && guest_failure < validator_call
        valid = valid && validator_call < parser_call
        valid = valid && crash_call_count == 1 && may_own_call_count == 1
        valid = valid && parser_call < crash_call && crash_call < may_own_call
        valid = valid && may_own_call < unclassified
        if (!valid) exit 1
    }
' "$runner"; then
    printf '%s\n' 'restart diagnostics are not confined to guest proof failure' >&2
    exit 1
fi

printf '%s\n%s\n' \
    'live worker-identity proof failed: initial forced-crash debugger did not complete' \
    'live worker-identity proof failed: initial debugger log is unsafe' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_restart_launch_failure_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

while IFS='|' read -r blocked_category blocked_reason; do
    printf 'BLOCKED: %s\n' "$blocked_reason" >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_blocked_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    test "$(cat "$last_stderr")" = \
        "non-retained helper-boundary PR smoke blocked category: $blocked_category"
done <<'EOF'
environment|execution requires exact systemd v257
service-identity|the systemd-resolved service GID is non-canonical
service-runtime|the canonical root-owned systemd notify socket is unavailable
workspace-owner|the repository must be owned by one canonical unprivileged identity
workspace-helper-missing|build target/debug/volparossa-helper as an unprivileged workspace user first
workspace-helper-metadata|the helper source must be one bounded workspace-owned 0755 regular file
workspace-probe-missing|build the production IPC probe as an unprivileged workspace user first
workspace-probe-metadata|the production IPC probe must be one bounded workspace-owned 0755 regular file
workspace-hook-missing|the production IPC unit hook must be one executable regular file with one hard link
workspace-hook-metadata|the production IPC unit hook has unsafe workspace metadata
workspace-observer-missing|the restart observer must be one executable regular file with one hard link
workspace-observer-metadata|the restart observer has unsafe workspace metadata
staging-parent|/var/tmp is not the canonical root-owned sticky staging parent
identity-range|no collision-free synthetic service identity range is available
EOF

for blocked_mutant in \
    'BLOCKED: required Debian tool is unavailable: secret-tool' \
    'BLOCKED: private runtime detail'; do
    printf '%s\n' "$blocked_mutant" >"$branch_failure_diagnostic"
    expect_status 1 report_non_retained_blocked_category \
        "$branch_failure_diagnostic"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done
printf '%s\n%s\n' \
    'BLOCKED: the fixed root-owned debugger is unavailable' \
    'BLOCKED: the fixed debugger could not be hashed' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_blocked_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"
printf '%s\n%s\n' \
    '-----BEGIN PRIVATE KEY-----' \
    'BLOCKED: the fixed root-owned debugger is unavailable' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_blocked_category \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'the bounded diagnostic contains private-key material'
if grep -F -- '-----BEGIN PRIVATE KEY-----' "$last_stderr" >/dev/null \
    || grep -F 'blocked category:' "$last_stderr" >/dev/null; then
    printf '%s\n' 'blocked category parser exposed private material' >&2
    exit 1
fi

for non_retained_driver_phase in \
    staging worker-launch worker-terminal-observation worker-retirement \
    production-launch production-observation production-retirement \
    restart-launch restart-observation restart-retirement final-verification; do
    non_retained_driver_phase_is_safe "$non_retained_driver_phase" || {
        printf 'non-retained parser rejected fixed driver phase: %s\n' \
            "$non_retained_driver_phase" >&2
        exit 1
    }
done
for non_retained_driver_mutant in \
    '' restart restart-secret-observation restart-observation-extra; do
    if non_retained_driver_phase_is_safe "$non_retained_driver_mutant"; then
        printf 'non-retained parser accepted driver-phase mutant: %s\n' \
            "$non_retained_driver_mutant" >&2
        exit 1
    fi
done

for non_retained_final_checkpoint in \
    host-state structured-reporting cleanup-summary lifecycle-summary \
    artifact-integrity source-integrity report-times report-generation \
    report-validation restart-report-validation publication-fence stage-retirement; do
    non_retained_final_checkpoint_is_safe "$non_retained_final_checkpoint" || {
        printf 'non-retained parser rejected fixed final checkpoint: %s\n' \
            "$non_retained_final_checkpoint" >&2
        exit 1
    }
done

for non_retained_production_stage in \
    functional-worker-observation functional-relay-fixture \
    functional-relay-traffic functional-relay-cleanup \
    functional-client-release functional-client-cleanup functional-exit-ready \
    functional-exit-worker-observation functional-exit-relay-fixture \
    functional-exit-relay-traffic functional-exit-relay-cleanup \
    functional-exit-release functional-exit-cleanup \
    functional-relay-pair-ready functional-relay-pair-worker-observation \
    functional-relay-pair-fixtures functional-relay-pair-traffic \
    functional-relay-pair-cleanup \
    functional-probe-finish; do
    non_retained_production_launch_stage_is_safe \
        "$non_retained_production_stage" || {
            printf 'non-retained parser rejected production stage: %s\n' \
                "$non_retained_production_stage" >&2
            exit 1
        }
done

for non_retained_functional_phase in \
    plan connect bind prepare activate shutdown ready release reconnect commit destroy \
    second-cycle-plan second-cycle-bind second-cycle-prepare \
    second-cycle-activate reuse second-cycle-shutdown second-cycle-ready \
    second-cycle-release second-cycle-reconnect second-cycle-commit \
    second-cycle-destroy relay-pair-plan relay-pair-bind relay-pair-prepare \
    relay-pair-activate relay-pair-reuse relay-pair-shutdown relay-pair-ready \
    relay-pair-release relay-pair-reconnect relay-pair-commit \
    relay-pair-destroy final-shutdown; do
    for non_retained_functional_class in \
        random protocol io timeout untrusted correlation unexpected-response; do
        non_retained_functional_probe_failure_value_is_safe \
            "$non_retained_functional_phase,$non_retained_functional_class" || {
            printf 'non-retained parser rejected fixed functional value: %s,%s\n' \
                "$non_retained_functional_phase" \
                "$non_retained_functional_class" >&2
            exit 1
        }
    done
done
for non_retained_functional_mutant in \
    '' private,io prepare,private prepare,io,extra prepare/io; do
    if non_retained_functional_probe_failure_value_is_safe \
        "$non_retained_functional_mutant"; then
        printf 'non-retained parser accepted functional mutant: %s\n' \
            "$non_retained_functional_mutant" >&2
        exit 1
    fi
done

branch_failure_diagnostic=$temporary_directory/branch-proof.stderr.log
branch_failure_privacy_sentinel='private-runtime-payload-must-not-escape'
printf '%s\n%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=run-nonzero,captures-yes,json-no,manager-no,client-stderr-nonempty,terminal-failed-exit-status-203,stage-publication' \
    'live worker-identity proof failed: predicate rejected: worker-launch-status' \
    >"$branch_failure_diagnostic"
chmod 0600 "$branch_failure_diagnostic"
expect_status 0 report_non_retained_proof_failure_reason \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
grep -Fx \
    'non-retained helper-boundary PR smoke failure category: worker-launch-status' \
    "$last_stderr" >/dev/null
expect_status 0 report_non_retained_worker_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
grep -Fx \
    'non-retained helper-boundary PR smoke worker launch diagnostic: run-nonzero,captures-yes,json-no,manager-no,client-stderr-nonempty,terminal-failed-exit-status-203,stage-publication' \
    "$last_stderr" >/dev/null
if grep -F "$branch_failure_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'branch failure diagnostic exposed a non-allowlisted payload' >&2
    exit 1
fi

printf '%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=lifecycle-summary' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_final_checkpoint "$branch_failure_diagnostic"
test ! -s "$last_stdout"
grep -Fx \
    'non-retained helper-boundary PR smoke final checkpoint: lifecycle-summary' \
    "$last_stderr" >/dev/null
test "$(wc -l <"$last_stderr")" -eq 1
if grep -F "$branch_failure_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'final checkpoint exposed a non-allowlisted payload' >&2
    exit 1
fi

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=report-validation' \
    'VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=report-validation' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_final_checkpoint "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=secret-publication' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_final_checkpoint "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-probe-ready' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_proof_failure_reason \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke failure category: production-launch-status'
expect_status 0 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'non-retained helper-boundary PR smoke production launch diagnostic: functional-probe-ready'
if grep -F "$branch_failure_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'production launch diagnostic exposed a non-allowlisted payload' >&2
    exit 1
fi

printf '%s\n%s\n%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-probe-wait' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=prepare,unexpected-response' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'non-retained helper-boundary PR smoke production launch diagnostic: functional-probe-wait' \
    'non-retained helper-boundary PR smoke Client/Exit/Relay-pair lease diagnostic: prepare,unexpected-response' \
    >"$temporary_directory/expected-branch-functional-diagnostic"
cmp -s "$temporary_directory/expected-branch-functional-diagnostic" "$last_stderr"
if grep -F "$branch_failure_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'functional probe diagnostic exposed a private payload' >&2
    exit 1
fi

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-client-release' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=second-cycle-ready,timeout' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'non-retained helper-boundary PR smoke production launch diagnostic: functional-client-release' \
    'non-retained helper-boundary PR smoke Client/Exit/Relay-pair lease diagnostic: second-cycle-ready,timeout' \
    >"$temporary_directory/expected-branch-functional-exit-ready-diagnostic"
cmp -s \
    "$temporary_directory/expected-branch-functional-exit-ready-diagnostic" \
    "$last_stderr"

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-exit-release' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=relay-pair-ready,timeout' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'non-retained helper-boundary PR smoke production launch diagnostic: functional-exit-release' \
    'non-retained helper-boundary PR smoke Client/Exit/Relay-pair lease diagnostic: relay-pair-ready,timeout' \
    >"$temporary_directory/expected-branch-functional-pair-ready-diagnostic"
cmp -s \
    "$temporary_directory/expected-branch-functional-pair-ready-diagnostic" \
    "$last_stderr"

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-probe-finish' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=relay-pair-commit,correlation' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'non-retained helper-boundary PR smoke production launch diagnostic: functional-probe-finish' \
    'non-retained helper-boundary PR smoke Client/Exit/Relay-pair lease diagnostic: relay-pair-commit,correlation' \
    >"$temporary_directory/expected-branch-functional-pair-commit-diagnostic"
cmp -s \
    "$temporary_directory/expected-branch-functional-pair-commit-diagnostic" \
    "$last_stderr"

while read -r functional_mutant_name functional_mutant_stage \
    functional_mutant_value; do
    printf '%s\n%s\n%s\n' \
        "VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=$functional_mutant_stage" \
        "VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=$functional_mutant_value" \
        'live worker-identity proof failed: predicate rejected: production-launch-status' \
        >"$branch_failure_diagnostic"
    expect_status 1 report_non_retained_production_launch_diagnostic \
        "$branch_failure_diagnostic"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'functional diagnostic mutant escaped: %s\n' \
            "$functional_mutant_name" >&2
        exit 1
    fi
done <<'EOF'
private-phase functional-probe-wait private,io
private-class functional-probe-wait prepare,private
extra-field functional-probe-wait prepare,io,extra
wrong-stage functional-probe-identity prepare,io
EOF

printf '%s\n%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-probe-wait' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=prepare,io' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=connect,io' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-probe-wait' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=prepare,io' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

# Missing, duplicate, malformed, mixed and private-key-bearing production
# launch records fail closed without printing any captured payload.
printf '%s\n' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=identity-process' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=publication' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=private-stage' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-cleanup' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=ambient' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    '-----BEGIN PRIVATE KEY-----' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-underlay' \
    'live worker-identity proof failed: predicate rejected: production-launch-status' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
if grep -F -- '-----BEGIN PRIVATE KEY-----' "$last_stderr" >/dev/null \
    || grep -F 'production launch diagnostic:' "$last_stderr" >/dev/null; then
    printf '%s\n' 'production launch parser exposed private or invalid diagnostics' >&2
    exit 1
fi

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=active-lock' \
    'live worker-identity proof failed: predicate rejected: production-running-state' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_production_launch_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

# An unclassified unexpected exit may expose exactly one fixed phase and no
# captured payload. Missing, duplicate, invalid and mixed records fail closed.
printf '%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-observation' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout"
grep -Fx \
    'non-retained helper-boundary PR smoke driver phase: production-observation' \
    "$last_stderr" >/dev/null
test "$(wc -l <"$last_stderr")" -eq 1
if grep -F "$branch_failure_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'driver phase exposed a non-allowlisted payload' >&2
    exit 1
fi

for restart_driver_phase in \
    restart-launch restart-observation restart-retirement; do
    printf '%s\n%s\n' \
        "$branch_failure_privacy_sentinel" \
        "VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=$restart_driver_phase" \
        >"$branch_failure_diagnostic"
    expect_status 0 report_non_retained_driver_phase "$branch_failure_diagnostic"
    test ! -s "$last_stdout"
    grep -Fx \
        "non-retained helper-boundary PR smoke driver phase: $restart_driver_phase" \
        "$last_stderr" >/dev/null
    test "$(wc -l <"$last_stderr")" -eq 1
    if grep -F "$branch_failure_privacy_sentinel" \
        "$last_stdout" "$last_stderr" >/dev/null; then
        printf 'restart driver phase exposed a non-allowlisted payload: %s\n' \
            "$restart_driver_phase" >&2
        exit 1
    fi
done

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=restart-secret-observation' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' "$branch_failure_privacy_sentinel" >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=worker-retirement' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=worker-retirement' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-secret-observation' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-retirement' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-secret-observation' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=final-verification' \
    'live worker-identity proof failed: predicate rejected: production-retirement' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

printf '%s\n%s\n' \
    '-----BEGIN PRIVATE KEY-----' \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-launch' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_driver_phase "$branch_failure_diagnostic"
test ! -s "$last_stdout"
if grep -F -- '-----BEGIN PRIVATE KEY-----' "$last_stderr" >/dev/null \
    || grep -F 'driver phase:' "$last_stderr" >/dev/null; then
    printf '%s\n' 'driver phase parser exposed private or invalid diagnostics' >&2
    exit 1
fi

printf '%s\n%s\n%s\n' \
    "$branch_failure_privacy_sentinel" \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=ambient' \
    'live worker-identity proof failed: predicate rejected: worker-confinement' \
    >"$branch_failure_diagnostic"
expect_status 0 report_non_retained_proof_failure_reason \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
grep -Fx \
    'non-retained helper-boundary PR smoke failure category: worker-confinement' \
    "$last_stderr" >/dev/null
expect_status 0 report_non_retained_worker_confinement_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
grep -Fx \
    'non-retained helper-boundary PR smoke worker confinement diagnostic: ambient' \
    "$last_stderr" >/dev/null
if grep -F "$branch_failure_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'worker confinement diagnostic exposed a non-allowlisted payload' >&2
    exit 1
fi

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=bounding' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=control-group' \
    'live worker-identity proof failed: predicate rejected: worker-confinement' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_worker_confinement_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test ! -s "$last_stderr"

printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=private-record' \
    'live worker-identity proof failed: predicate rejected: worker-confinement' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_worker_confinement_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test ! -s "$last_stderr"

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=ambient' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=private-record' \
    'live worker-identity proof failed: predicate rejected: worker-confinement' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_worker_confinement_diagnostic \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test ! -s "$last_stderr"

printf '%s\n' 'attacker-controlled diagnostic payload' >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_proof_failure_reason \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test ! -s "$last_stderr"

printf '%s\n' \
    'live worker-identity proof failed: predicate rejected: production-secret-leak' \
    >"$branch_failure_diagnostic"
expect_status 1 report_non_retained_proof_failure_reason \
    "$branch_failure_diagnostic"
test ! -s "$last_stdout"
test ! -s "$last_stderr"

branch_failure_link=$temporary_directory/branch-proof.stderr.link
ln -s "$branch_failure_diagnostic" "$branch_failure_link"
expect_status 1 report_non_retained_proof_failure_reason "$branch_failure_link"
test ! -s "$last_stdout"
test ! -s "$last_stderr"

grep -F \
    'report_non_retained_proof_failure_reason "$proof_stderr_log"' \
    "$runner" >/dev/null
grep -F \
    'non-retained helper-boundary PR smoke failure category: unclassified' \
    "$runner" >/dev/null
grep -F \
    'report_non_retained_driver_phase "$proof_stderr_log" || true' \
    "$runner" >/dev/null
grep -F \
    'report_non_retained_final_checkpoint "$proof_stderr_log" || true' \
    "$runner" >/dev/null
grep -E \
    '^[[:space:]]+report_non_retained_worker_launch_diagnostic([[:space:]]|$)' \
    "$runner" >/dev/null
grep -E \
    '^[[:space:]]+report_non_retained_worker_confinement_diagnostic([[:space:]]|$)' \
    "$runner" >/dev/null
grep -E \
    '^[[:space:]]+report_non_retained_production_launch_diagnostic([[:space:]]|$)' \
    "$runner" >/dev/null
grep -F \
    'elif [ "$non_retained_failure_reason" = worker-confinement ]; then' \
    "$runner" >/dev/null
grep -F \
    'elif [ "$non_retained_failure_reason" = production-launch-status ]; then' \
    "$runner" >/dev/null

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
    'id: source_selection' \
    'test "$SELECTED_REF" = refs/heads/main' \
    'proof_mode=retained-main' \
    'proof_mode=non-retained-pr-smoke' \
    'test "$selected_branch" != main' \
    'PROOF_MODE: ${{ steps.source_selection.outputs.proof_mode }}' \
    'proof_mode_flag=--retained-main' \
    'proof_mode_flag=--non-retained-pr-smoke' \
    '"$proof_mode_flag"' \
    '--expected-source-ref "$SELECTED_REF"' \
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' \
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
    'persist-credentials: false' \
    'ref: ${{ github.ref }}' \
    'test "$(git symbolic-ref --quiet --short HEAD)" = main' \
    'retention-days: 90' \
    'prlimit --fsize=8388608:8388608' \
    'getfacl --absolute-names --numeric /dev/kvm' \
    'stat -Lc '\''%d:%i:%t:%T:%F'\'' /dev/kvm >"$acl_identity"' \
    'runner_uid=$(id -u)' \
    'kvm_gid=$(stat -Lc '\''%g'\'' /dev/kvm)' \
    'while test "$kvm_attempt" -le 2' \
    'udevadm settle --timeout=10' \
    'test ! -L /usr/bin/setpriv' \
    'test "$(stat -Lc '\''%F:%u:%g:%a'\'' /usr/bin/setpriv)"' \
    '= '\''regular file:0:0:755'\''' \
    'cmp -s "$acl_snapshot" "$final_acl"' \
    '--connect-timeout 30' \
    '--max-time 1200' \
    '--max-filesize 2147483648' \
    '--max-redirs 3' \
    'runner_path="$(pwd -P)/tests/helper/run-helper-boundary-evidence-vm.sh"' \
    'test "$(readlink -f -- "$runner_path")" = "$runner_path"' \
    '"$runner_path"' \
    '--expected-host-uid "$runner_uid"' \
    '--expected-kvm-gid "$kvm_gid"' \
    '--expected-kvm-identity "$(cat "$acl_identity")"' \
    'tests/helper/validate-helper-boundary-evidence-v1.sh' \
    'tests/helper/validate-helper-boundary-vm-environment-v1.sh' \
    "grep -aEq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'" \
    'VERIFY_KVM_STATE_OUTCOME: ${{ steps.verify_kvm_state.outcome }}' \
    "steps.source_selection.outputs.proof_mode == 'retained-main'" \
    "steps.source_selection.outputs.proof_mode == 'non-retained-pr-smoke'" \
    'name: Require a non-retained PR smoke PASS' \
    'test "$GITHUB_REF" != refs/heads/main' \
    'PASS: exact branch/SHA completed the non-retained disposable KVM smoke.'
do
    grep -F -- "$exact_workflow_text" "$workflow" >/dev/null
done

# Join only explicit shell continuations so exact process-scoped launches can
# be counted without requiring one particular YAML line wrapping style.
logical_shell_lines() {
    awk '
        {
            current = $0
            if (continued) {
                sub(/^[[:space:]]*/, "", current)
                logical = logical " " current
            } else {
                logical = current
            }
            if (logical ~ /\\[[:space:]]*$/) {
                sub(/[[:space:]]*\\[[:space:]]*$/, "", logical)
                continued = 1
                next
            }
            print logical
            logical = ""
            continued = 0
        }
        END {
            if (continued) exit 1
        }
    ' "$1"
}
workflow_logical=$temporary_directory/helper-boundary-workflow.logical
logical_shell_lines "$workflow" >"$workflow_logical"

setpriv_launch='sudo -n -- /usr/bin/setpriv --reuid "$runner_uid" --regid "$kvm_gid" --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs --reset-env --'
if [ "$(grep -c -F -- "$setpriv_launch" "$workflow_logical")" -ne 2 ]; then
    printf '%s\n' 'the workflow must contain exactly two complete setpriv KVM launches' >&2
    exit 1
fi
if grep -Eq '(^|[;&|[:space:]])([^;&|[:space:]]*/)?setfacl[[:space:]]+--(modify|restore)(=|[[:space:]])' \
    "$workflow_logical" \
    || grep -Eq 'sudo[^;&|]*getfacl([[:space:]]|$)' "$workflow_logical" \
    || grep -Eq '(^|[;&|[:space:]])([^;&|[:space:]]*/)?(usermod|gpasswd|chgrp)([[:space:]]|$)' \
        "$workflow_logical" \
    || grep -Eq '(^|[;&|[:space:]])([^;&|[:space:]]*/)?chmod([[:space:]][^;&|]*)?/dev/kvm' \
        "$workflow_logical"; then
    printf '%s\n' 'the workflow contains a persistent KVM authority mutation' >&2
    exit 1
fi
if grep -Eq 'sudo[^;&|]*(--user|--group)(=|[[:space:]])' "$workflow_logical"; then
    printf '%s\n' 'sudo user/group switching cannot replace the exact setpriv boundary' >&2
    exit 1
fi

test "$(grep -h -- '-no-user-config' "$runner" "$workflow" | wc -l)" -eq 2
if grep -Eq '^[[:space:]]+-S([[:space:]]|$)' "$workflow"; then
    printf '%s\n' 'the KVM preflight does not execute a virtual CPU' >&2
    exit 1
fi
grep -F "steps.verify_kvm_state.outcome == 'success'" "$workflow" >/dev/null
test "$(grep -c -F 'require_no_private_key_marker "$candidate" "$name"' "$workflow")" -eq 1
test "$(grep -c -F 'require_no_private_key_marker "$retained_candidate" "$name"' "$workflow")" -eq 1
grep -F 'if test "$scan_status" -ne 1; then' "$workflow" >/dev/null

preflight_step_line=$(grep -n -m 1 -F 'name: Require usable KVM without emulation fallback' \
    "$workflow" | cut -d: -f1)
preflight_next_step_line=$(awk -v minimum="$preflight_step_line" \
    'NR > minimum && /^      - name:/ { print NR; exit }' "$workflow")
if [ -z "$preflight_step_line" ] || [ -z "$preflight_next_step_line" ]; then
    printf '%s\n' 'the KVM preflight step cannot be isolated' >&2
    exit 1
fi
preflight_step_fixture=$temporary_directory/kvm-preflight-step.yml
sed -n "${preflight_step_line},$((preflight_next_step_line - 1))p" "$workflow" \
    >"$preflight_step_fixture"
preflight_step_logical=$temporary_directory/kvm-preflight-step.logical
logical_shell_lines "$preflight_step_fixture" >"$preflight_step_logical"
test "$(grep -c -F -- "$setpriv_launch" "$preflight_step_logical")" -eq 1
preflight_acl_line=$(grep -n -m 1 -F \
    'getfacl --absolute-names --numeric /dev/kvm >"$acl_snapshot"' \
    "$preflight_step_logical" | cut -d: -f1)
preflight_identity_line=$(grep -n -m 1 -F \
    "stat -Lc '%d:%i:%t:%T:%F' /dev/kvm >\"\$acl_identity\"" \
    "$preflight_step_logical" | cut -d: -f1)
preflight_setpriv_line=$(grep -n -m 1 -F -- "$setpriv_launch" \
    "$preflight_step_logical" | cut -d: -f1)
preflight_qemu_line=$(grep -n -F 'qemu-system-x86_64' \
    "$preflight_step_logical" | tail -n 1 | cut -d: -f1)
preflight_acl_compare_line=$(grep -n -m 1 -F \
    'cmp -s "$acl_snapshot" "$post_preflight_acl"' \
    "$preflight_step_logical" | cut -d: -f1)
if [ -z "$preflight_acl_line" ] || [ -z "$preflight_identity_line" ] \
    || [ -z "$preflight_setpriv_line" ] || [ -z "$preflight_qemu_line" ] \
    || [ -z "$preflight_acl_compare_line" ] \
    || [ "$preflight_acl_line" -ge "$preflight_setpriv_line" ] \
    || [ "$preflight_identity_line" -ge "$preflight_setpriv_line" ] \
    || [ "$preflight_setpriv_line" -ge "$preflight_qemu_line" ] \
    || [ "$preflight_qemu_line" -ge "$preflight_acl_compare_line" ]; then
    printf '%s\n' 'the original KVM state is not fenced before grouped KVM preflight' >&2
    exit 1
fi

vm_step_line=$(grep -n -m 1 -F 'name: Run the disposable Debian 13 proof VM' "$workflow" | cut -d: -f1)
vm_next_step_line=$(awk -v minimum="$vm_step_line" \
    'NR > minimum && /^      - name:/ { print NR; exit }' "$workflow")
if [ -z "$vm_step_line" ] || [ -z "$vm_next_step_line" ]; then
    printf '%s\n' 'the bounded VM run step cannot be isolated' >&2
    exit 1
fi
vm_step_fixture=$temporary_directory/vm-proof-step.yml
sed -n "${vm_step_line},$((vm_next_step_line - 1))p" "$workflow" >"$vm_step_fixture"
vm_step_logical=$temporary_directory/vm-proof-step.logical
logical_shell_lines "$vm_step_fixture" >"$vm_step_logical"
test "$(grep -c -F -- "$setpriv_launch" "$vm_step_logical")" -eq 1
vm_identity_line=$(grep -n -m 1 -F \
    'test "$(stat -Lc '\''%d:%i:%t:%T:%F'\'' /dev/kvm)" = "$(cat "$acl_identity")"' \
    "$vm_step_logical" | cut -d: -f1)
vm_acl_line=$(grep -n -m 1 -F 'cmp -s "$acl_snapshot" "$pre_run_acl"' \
    "$vm_step_logical" | cut -d: -f1)
vm_setpriv_line=$(grep -n -m 1 -F -- "$setpriv_launch" \
    "$vm_step_logical" | cut -d: -f1)
vm_runner_line=$(grep -n -m 1 -F -- \
    '-- "$runner_path" --execute' \
    "$vm_step_logical" | cut -d: -f1)
if [ -z "$vm_identity_line" ] || [ -z "$vm_acl_line" ] \
    || [ -z "$vm_setpriv_line" ] || [ -z "$vm_runner_line" ] \
    || [ "$vm_identity_line" -ge "$vm_acl_line" ] \
    || [ "$vm_acl_line" -ge "$vm_setpriv_line" ] \
    || [ "$vm_setpriv_line" -gt "$vm_runner_line" ]; then
    printf '%s\n' 'the unchanged KVM state is not fenced before the scoped VM runner' >&2
    exit 1
fi

verify_kvm_state_line=$(grep -n -m 1 -F \
    'name: Verify the KVM device and ACL remained unchanged' "$workflow" | cut -d: -f1)
pass_upload_line=$(grep -n -m 1 -F 'name: Upload bounded helper-boundary evidence' "$workflow" | cut -d: -f1)
failure_upload_line=$(grep -n -m 1 -F 'name: Upload bounded failure diagnostics' \
    "$workflow" | cut -d: -f1)
restart_upload_line=$(grep -n -m 1 -F \
    'name: Upload bounded singleton restart evidence' \
    "$workflow" | cut -d: -f1)
retained_gate_line=$(grep -n -m 1 -F 'name: Require a retained PASS' \
    "$workflow" | cut -d: -f1)
smoke_gate_line=$(grep -n -m 1 -F 'name: Require a non-retained PR smoke PASS' \
    "$workflow" | cut -d: -f1)
if [ -z "$verify_kvm_state_line" ] || [ -z "$pass_upload_line" ] \
    || [ -z "$failure_upload_line" ] || [ -z "$retained_gate_line" ] \
    || [ -z "$restart_upload_line" ] \
    || [ -z "$smoke_gate_line" ] \
    || [ "$verify_kvm_state_line" -ge "$pass_upload_line" ] \
    || [ "$pass_upload_line" -ge "$failure_upload_line" ] \
    || [ "$failure_upload_line" -ge "$restart_upload_line" ] \
    || [ "$restart_upload_line" -ge "$retained_gate_line" ] \
    || [ "$retained_gate_line" -ge "$smoke_gate_line" ]; then
    printf '%s\n' 'the PASS artifact can be uploaded before exact KVM state comparison' >&2
    exit 1
fi
pass_upload_fixture=$temporary_directory/pass-upload-step.yml
failure_upload_fixture=$temporary_directory/failure-upload-step.yml
restart_upload_fixture=$temporary_directory/restart-upload-step.yml
smoke_gate_fixture=$temporary_directory/non-retained-smoke-step.yml
sed -n "${pass_upload_line},$((failure_upload_line - 1))p" "$workflow" \
    >"$pass_upload_fixture"
sed -n "${failure_upload_line},$((restart_upload_line - 1))p" "$workflow" \
    >"$failure_upload_fixture"
sed -n "${restart_upload_line},$((retained_gate_line - 1))p" "$workflow" \
    >"$restart_upload_fixture"
sed -n "${smoke_gate_line},\$p" "$workflow" >"$smoke_gate_fixture"
for retained_upload_fixture in \
    "$pass_upload_fixture" "$failure_upload_fixture" "$restart_upload_fixture"
do
    grep -F "steps.source_selection.outputs.proof_mode == 'retained-main'" \
        "$retained_upload_fixture" >/dev/null
    if grep -F 'non-retained-pr-smoke' "$retained_upload_fixture" >/dev/null; then
        printf '%s\n' 'a retained upload step is reachable from PR smoke' >&2
        exit 1
    fi
done
grep -F "steps.source_selection.outputs.proof_mode == 'non-retained-pr-smoke'" \
    "$smoke_gate_fixture" >/dev/null
grep -F 'test "$GITHUB_REF" != refs/heads/main' "$smoke_gate_fixture" >/dev/null
if grep -F 'uses: actions/upload-artifact@' "$smoke_gate_fixture" >/dev/null; then
    printf '%s\n' 'the non-retained smoke gate uploads an artifact' >&2
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
if [ "$uses_count" -ne 5 ]; then
    printf 'expected exactly five pinned action uses, got %s\n' "$uses_count" >&2
    exit 1
fi

printf '%s\n' \
    'PASS: helper-boundary VM preview, retained-main, non-retained branch smoke, and KVM contracts are exact.'
