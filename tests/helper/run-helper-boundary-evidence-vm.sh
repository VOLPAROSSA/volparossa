#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Build and run the helper-boundary proof in a disposable, KVM-only Debian 13 VM.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode=preview
approval=no
proof_mode=
image_path=
output_directory=
expected_commit=
expected_source_ref=
expected_host_uid=
expected_kvm_gid=
expected_kvm_identity=
seen_mode=no
seen_approval=no
seen_proof_mode=no
seen_image=no
seen_output=no
seen_commit=no
seen_source_ref=no
seen_host_uid=no
seen_kvm_gid=no
seen_kvm_identity=no

usage() {
    printf '%s\n' \
        'usage: tests/helper/run-helper-boundary-evidence-vm.sh [--preview]' \
        '       tests/helper/run-helper-boundary-evidence-vm.sh --execute --yes' \
        '         (--retained-main|--non-retained-pr-smoke)' \
        '         --image PATH --output DIRECTORY --expected-commit SHA' \
        '         --expected-source-ref refs/heads/BRANCH' \
        '         --expected-host-uid UID --expected-kvm-gid GID' \
        '         --expected-kvm-identity IDENTITY'
}

print_plan() {
    if [ "$proof_mode" = non-retained-pr-smoke ]; then
        printf '%s\n' \
            'VOLPAROSSA non-retained helper-boundary PR smoke VM plan:' \
            '  require an unprivileged host user and usable KVM; never fall back to TCG;' \
            '  require one exact clean non-main branch commit and clone only its tracked Git state;' \
            '  require the reviewed Debian 13 amd64 genericcloud image by exact SHA-512;' \
            '  create one temporary qcow2 overlay, NoCloud seed and ephemeral SSH keys;' \
            '  pin the injected guest host key before the first SSH connection;' \
            '  provision and fetch locked dependencies in a first disposable KVM boot;' \
            '  restart with QEMU user-network egress denied and prove that denial;' \
            '  build fully offline as the unprivileged guest user in the restricted boot;' \
            '  run the fixed helper-boundary proof plus exact CleanupConfirmed and MayOwn Relay restart slices as guest root;' \
            '  require three canonical reports, fixed FIFO pre-exec barriers, exact GDB SIGKILL/quit-0 boundaries,' \
            '    non-empty shape-checked crash-only freezer use, and complete observer/unit teardown;' \
            '  shut down, rehash the base image, validate, and discard all proof files;' \
            '  bind QEMU lifecycle to pidfds and remove keys, seed and overlay on exit.' \
            'No bridge, TAP device, host route, firewall, DNS, sysctl or VPN state is changed.'
        return
    fi
    printf '%s\n' \
        'VOLPAROSSA helper-boundary evidence VM plan:' \
        '  require an unprivileged host user and usable KVM; never fall back to TCG;' \
        '  require one clean main-branch commit and clone only its tracked Git state;' \
        '  require the reviewed Debian 13 amd64 genericcloud image by exact SHA-512;' \
        '  create one temporary qcow2 overlay, NoCloud seed and ephemeral SSH keys;' \
        '  pin the injected guest host key before the first SSH connection;' \
        '  provision and fetch locked dependencies in a first disposable KVM boot;' \
        '  restart with QEMU user-network egress denied and prove that denial;' \
        '  build fully offline as the unprivileged guest user in the restricted boot;' \
        '  run the fixed helper-boundary proof plus exact CleanupConfirmed and MayOwn Relay restart slices as guest root;' \
        '  require exactly three canonical reports, fixed FIFO pre-exec barriers, exact GDB SIGKILL/quit-0 boundaries,' \
        '    non-empty shape-checked crash-only freezer use, and complete observer/unit teardown;' \
        '  shut down, rehash the base image, validate, and publish eleven bounded files;' \
        '  bind QEMU lifecycle to pidfds and remove keys, seed and overlay on exit.' \
        'No bridge, TAP device, host route, firewall, DNS, sysctl or VPN state is changed.'
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --preview)
            [ "$seen_mode" = no ] || { usage >&2; exit 64; }
            mode=preview
            seen_mode=yes
            ;;
        --execute)
            [ "$seen_mode" = no ] || { usage >&2; exit 64; }
            mode=execute
            seen_mode=yes
            ;;
        --yes)
            [ "$seen_approval" = no ] || { usage >&2; exit 64; }
            approval=yes
            seen_approval=yes
            ;;
        --retained-main)
            [ "$seen_proof_mode" = no ] || { usage >&2; exit 64; }
            proof_mode=retained-main
            seen_proof_mode=yes
            ;;
        --non-retained-pr-smoke)
            [ "$seen_proof_mode" = no ] || { usage >&2; exit 64; }
            proof_mode=non-retained-pr-smoke
            seen_proof_mode=yes
            ;;
        --image)
            if [ "$seen_image" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            image_path=$2
            seen_image=yes
            shift
            ;;
        --output)
            if [ "$seen_output" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            output_directory=$2
            seen_output=yes
            shift
            ;;
        --expected-commit)
            if [ "$seen_commit" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            expected_commit=$2
            seen_commit=yes
            shift
            ;;
        --expected-source-ref)
            if [ "$seen_source_ref" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            expected_source_ref=$2
            seen_source_ref=yes
            shift
            ;;
        --expected-host-uid)
            if [ "$seen_host_uid" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            expected_host_uid=$2
            seen_host_uid=yes
            shift
            ;;
        --expected-kvm-gid)
            if [ "$seen_kvm_gid" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            expected_kvm_gid=$2
            seen_kvm_gid=yes
            shift
            ;;
        --expected-kvm-identity)
            if [ "$seen_kvm_identity" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            expected_kvm_identity=$2
            seen_kvm_identity=yes
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 64
            ;;
    esac
    shift
done

if [ "$mode" = preview ]; then
    if [ "$approval" = yes ] || [ "$seen_proof_mode" = yes ] \
        || [ "$seen_image" = yes ] \
        || [ "$seen_output" = yes ] || [ "$seen_commit" = yes ] \
        || [ "$seen_source_ref" = yes ] \
        || [ "$seen_host_uid" = yes ] || [ "$seen_kvm_gid" = yes ] \
        || [ "$seen_kvm_identity" = yes ]; then
        usage >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no image, VM, key, file, service, or network state was changed.'
    exit 0
fi

if [ "$approval" != yes ] || [ "$seen_proof_mode" != yes ] \
    || [ "$seen_image" != yes ] \
    || [ "$seen_output" != yes ] || [ "$seen_commit" != yes ] \
    || [ "$seen_source_ref" != yes ] \
    || [ "$seen_host_uid" != yes ] || [ "$seen_kvm_gid" != yes ] \
    || [ "$seen_kvm_identity" != yes ]; then
    print_plan >&2
    usage >&2
    exit 64
fi
print_plan >&2

blocked() {
    printf 'BLOCKED: %s\n' "$1" >&2
    exit 77
}

failed() {
    printf 'helper-boundary evidence VM failed: %s\n' "$1" >&2
    exit 1
}

non_retained_proof_failure_reason_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        worker-launch-status|\
        worker-launch-envelope|\
        worker-manager-binding|\
        worker-helper-parent-contract|\
        worker-helper-runtime-preparation|\
        worker-helper-worker-spawn|\
        worker-helper-publication|\
        worker-helper-retirement-cleanup|\
        worker-terminal-state|\
        worker-unit-contract|\
        worker-proof-records|\
        worker-confinement|\
        worker-retirement|\
        production-launch-status|\
        production-launch-envelope|\
        production-manager-binding|\
        production-running-state|\
        production-unit-contract|\
        production-confinement|\
        production-process-identity|\
        production-socket-identity|\
        production-start-records|\
        production-runtime-layout|\
        production-process-stability|\
        production-retirement|\
        production-lock-release|\
        production-stop-records)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_blocked_category() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        'required Debian tool is unavailable: '*)
            non_retained_blocked_tool=${1#required Debian tool is unavailable: }
            case $non_retained_blocked_tool in
                awk|base64|busctl|cat|chmod|chown|cmp|cp|date|dpkg|find|flock|gdb|\
                getent|git|id|install|ip|jq|mkfifo|mktemp|mv|nft|nm|nsenter|paste|\
                ping|prlimit|readlink|rm|sed|setpriv|sha256sum|sleep|sort|stat|\
                systemctl|systemd-detect-virt|systemd-run|tc|timeout|tr|uname|wc|wg)
                    printf 'tool-%s\n' "$non_retained_blocked_tool"
                    ;;
                *) return 1 ;;
            esac
            ;;
        'execution requires root inside the disposable VM'|\
        'operating-system identity is unavailable'|\
        'execution requires Debian 13'|\
        'execution requires Debian 13 amd64 on x86_64'|\
        'PID 1 is not the system systemd manager'|\
        'containers cannot provide the required disposable-host evidence'|\
        'execution is restricted to a recognised disposable virtual machine'|\
        'the systemd manager version is unavailable'|\
        'execution requires exact systemd v257'|\
        'the system systemd manager is not operational')
            printf '%s\n' environment
            ;;
        'the fixed root-owned systemd bus client is unavailable')
            printf '%s\n' tool-busctl
            ;;
        'the fixed root-owned setpriv credential trampoline is unavailable')
            printf '%s\n' tool-setpriv
            ;;
        'the systemd-resolved service UID is unavailable'|\
        'the systemd-resolved service GID is unavailable'|\
        'the systemd-resolved service UID is non-canonical'|\
        'the systemd-resolved service GID is non-canonical')
            printf '%s\n' service-identity
            ;;
        'the canonical root-owned system bus socket is unavailable'|\
        'the canonical root-owned systemd notify socket is unavailable'|\
        'the disposable host /run/volparossa path must initially be absent')
            printf '%s\n' service-runtime
            ;;
        'the helper-boundary evidence validator is not one executable regular file')
            printf '%s\n' validator-helper-boundary
            ;;
        'the restart evidence validator is not one executable regular file')
            printf '%s\n' validator-restart
            ;;
        'the fixed root-owned debugger is unavailable'|\
        'the fixed debugger could not be hashed')
            printf '%s\n' debugger
            ;;
        'the repository owner UID is unavailable'|\
        'the repository owner GID is unavailable'|\
        'the repository must be owned by one canonical unprivileged identity')
            printf '%s\n' workspace-owner
            ;;
        'build target/debug/volparossa-helper as an unprivileged workspace user first')
            printf '%s\n' workspace-helper-missing
            ;;
        'the helper source must be one bounded workspace-owned 0755 regular file')
            printf '%s\n' workspace-helper-metadata
            ;;
        'build the production IPC probe as an unprivileged workspace user first')
            printf '%s\n' workspace-probe-missing
            ;;
        'the production IPC probe must be one bounded workspace-owned 0755 regular file')
            printf '%s\n' workspace-probe-metadata
            ;;
        'the production IPC unit hook must be one executable regular file with one hard link')
            printf '%s\n' workspace-hook-missing
            ;;
        'the production IPC unit hook has unsafe workspace metadata')
            printf '%s\n' workspace-hook-metadata
            ;;
        'the restart observer must be one executable regular file with one hard link')
            printf '%s\n' workspace-observer-missing
            ;;
        'the restart observer has unsafe workspace metadata')
            printf '%s\n' workspace-observer-metadata
            ;;
        '/var/tmp is not the canonical root-owned sticky staging parent')
            printf '%s\n' staging-parent
            ;;
        'the repository root cannot be established'|\
        'the live proof is not running from the exact repository root'|\
        'the source commit cannot be established'|\
        'the source commit is not a canonical Git revision'|\
        'the source worktree state cannot be established'|\
        'the source worktree must be clean before live evidence execution')
            printf '%s\n' source
            ;;
        'the kernel release cannot be established'|\
        'the kernel release is not bounded ASCII metadata'|\
        'the execution environment metadata exceeds its fixed bound'|\
        'the execution start time cannot be established')
            printf '%s\n' metadata
            ;;
        'no collision-free synthetic service identity range is available')
            printf '%s\n' identity-range
            ;;
        *) return 1 ;;
    esac
}

non_retained_blocked_status_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$1" -eq 77 ]
}

report_non_retained_blocked_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    [ "$(grep -Ec '^BLOCKED: ' "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_blocked_record=$(grep -E '^BLOCKED: ' \
        "$non_retained_diagnostic") || return 1
    non_retained_blocked_reason=${non_retained_blocked_record#BLOCKED: }
    non_retained_blocked_category=$(non_retained_blocked_category \
        "$non_retained_blocked_reason") || return 1
    printf 'non-retained helper-boundary PR smoke blocked category: %s\n' \
        "$non_retained_blocked_category" >&2
}

non_retained_driver_phase_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        staging|\
        worker-launch|\
        worker-terminal-observation|\
        worker-retirement|\
        production-launch|\
        production-observation|\
        production-retirement|\
        restart-launch|\
        restart-observation|\
        restart-retirement|\
        may-own-launch|\
        may-own-first-crash|\
        may-own-second-crash|\
        may-own-recovery|\
        may-own-retirement|\
        final-verification)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_final_checkpoint_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        host-state|\
        structured-reporting|\
        cleanup-summary|\
        lifecycle-summary|\
        artifact-integrity|\
        source-integrity|\
        report-times|\
        report-generation|\
        report-validation|\
        restart-report-validation|\
        publication-fence|\
        stage-retirement)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_non_retained_proof_failure_reason() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_failure_line=$(tail -n 1 -- "$non_retained_diagnostic") \
        || return 1
    non_retained_failure_prefix='live worker-identity proof failed: predicate rejected: '
    case $non_retained_failure_line in
        "$non_retained_failure_prefix"*)
            non_retained_failure_reason=${non_retained_failure_line#"$non_retained_failure_prefix"}
            ;;
        *) return 1 ;;
    esac
    non_retained_proof_failure_reason_is_safe "$non_retained_failure_reason" \
        || return 1
    printf 'non-retained helper-boundary PR smoke failure category: %s\n' \
        "$non_retained_failure_reason" >&2
}

non_retained_may_own_launch_failure_category() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        'ExactPresent retirement was not confirmed before MayOwn proof')
            printf '%s\n' prerequisite ;;
        'MayOwn singleton unit name is unsafe')
            printf '%s\n' unit-name ;;
        'MayOwn singleton unit state could not be determined')
            printf '%s\n' unit-state-read ;;
        'MayOwn singleton unit name is already loaded')
            printf '%s\n' unit-state-present ;;
        'MayOwn debugger symbols could not be inspected')
            printf '%s\n' symbols-read ;;
        'MayOwn debugger symbols are not exact and unique')
            printf '%s\n' symbols-shape ;;
        'MayOwn ownership marker could not be derived')
            printf '%s\n' marker-derive ;;
        'MayOwn ownership marker is non-canonical')
            printf '%s\n' marker-canonical ;;
        'MayOwn ownership marker is unsafe')
            printf '%s\n' marker-shape ;;
        'MayOwn debugger command path was not initially absent')
            printf '%s\n' debugger-path ;;
        'MayOwn singleton unit could not be launched')
            printf '%s\n' launch-status ;;
        'MayOwn singleton launch envelope is invalid')
            printf '%s\n' launch-envelope ;;
        'MayOwn first MainPID did not appear')
            printf '%s\n' mainpid-appearance ;;
        'MayOwn first MainPID birth token is unavailable')
            printf '%s\n' mainpid-starttime ;;
        'MayOwn first private namespaces did not become stable')
            printf '%s\n' namespaces ;;
        'MayOwn first pre-exec barrier is not manager-bound')
            printf '%s\n' preexec-barrier ;;
        'MayOwn first external pre-exec observer did not arm')
            printf '%s\n' preexec-observer ;;
        'MayOwn first freeze handshake path is unsafe')
            printf '%s\n' handshake-path ;;
        'MayOwn first debugger commands could not be written')
            printf '%s\n' debugger-command-write ;;
        'MayOwn first debugger identity is unavailable')
            printf '%s\n' debugger-identity ;;
        'MayOwn first debugger exited before exec-catch readiness')
            printf '%s\n' exec-catch-exit ;;
        'MayOwn first debugger did not arm its exec catch')
            printf '%s\n' exec-catch-timeout ;;
        'MayOwn first debugger readiness record is invalid')
            printf '%s\n' exec-catch-marker ;;
        'MayOwn first pre-exec barrier could not be released')
            printf '%s\n' preexec-release ;;
        'MayOwn first debugger exited before helper exec')
            printf '%s\n' helper-exec-exit ;;
        'MayOwn first helper exec was not observed')
            printf '%s\n' helper-exec-timeout ;;
        'MayOwn first external pre-exec observer did not retire')
            printf '%s\n' preexec-observer-retire ;;
        'MayOwn first mount keeper identity is unavailable')
            printf '%s\n' mount-keeper-identity ;;
        'MayOwn first driver-side observer could not be started')
            printf '%s\n' driver-observer-start ;;
        'MayOwn first driver-side observer exited before identity proof')
            printf '%s\n' identity-observer-exit ;;
        'MayOwn first invocation identity did not appear')
            printf '%s\n' identity-timeout ;;
        'MayOwn first invocation is not hook-bound')
            printf '%s\n' identity-binding ;;
        'MayOwn first service shape is not production-exact')
            printf '%s\n' service-shape ;;
        'MayOwn first active-custody diagnostic is invalid')
            printf '%s\n' active-custody-diagnostic ;;
        'MayOwn first active-custody boundary is unsafe')
            printf '%s\n' service-shape ;;
        'MayOwn first driver-side observer exited before active custody')
            printf '%s\n' service-observer-exit ;;
        'MayOwn first debugger exited before active custody')
            printf '%s\n' service-debugger-exit ;;
        'MayOwn first invocation changed before active custody')
            printf '%s\n' service-invocation-drift ;;
        'MayOwn first MainPID changed before active custody')
            printf '%s\n' service-mainpid-drift ;;
        'MayOwn first active custody did not become observable')
            printf '%s\n' service-shape ;;
        'MayOwn first active worker PID is unavailable')
            printf '%s\n' active-worker-pid ;;
        'MayOwn first active worker birth token is unavailable')
            printf '%s\n' active-worker-starttime ;;
        'MayOwn cgroup freezer is unavailable')
            printf '%s\n' freezer-shape ;;
        'MayOwn first debugger driver release could not be published')
            printf '%s\n' driver-release ;;
        'MayOwn first debugger exited before the freeze fence')
            printf '%s\n' freeze-fence-exit ;;
        'MayOwn first debugger did not reach the crash boundary')
            printf '%s\n' freeze-fence-timeout ;;
        'MayOwn first kill-ready marker is invalid')
            printf '%s\n' kill-marker ;;
        'MayOwn cgroup did not freeze before the first crash')
            printf '%s\n' cgroup-freeze ;;
        'MayOwn first freeze release could not be published')
            printf '%s\n' freeze-release ;;
        'MayOwn first forced-crash debugger did not complete')
            printf '%s\n' debugger-complete ;;
        'MayOwn first crash did not settle')
            printf '%s\n' crash-settle ;;
        'MayOwn first forced-crash fence is not exact')
            printf '%s\n' crash-fence ;;
        'MayOwn first crash freezer was not retired before restart')
            printf '%s\n' cgroup-thaw ;;
        'MayOwn first driver-side observer did not terminate at the forced crash')
            printf '%s\n' driver-observer-stop ;;
        'MayOwn first crash time is unavailable')
            printf '%s\n' crash-time ;;
        'MayOwn first crash did not preserve exact Relay custody')
            printf '%s\n' custody-preservation ;;
        *) return 1 ;;
    esac
}

non_retained_may_own_preexec_barrier_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        arguments|\
        starttime|\
        publication-unsafe|\
        publication-timeout|\
        lineage-mainpid|\
        lineage-invocation|\
        lineage-starttime|\
        lineage-marker|\
        shape-mainpid-argument|\
        shape-invocation-argument|\
        shape-count-arguments|\
        shape-membership-mode|\
        shape-type|\
        shape-restart-usec|\
        shape-control-pid|\
        shape-main-pid|\
        shape-invocation|\
        shape-restarts|\
        shape-fdstore-count|\
        shape-fdstore-max|\
        shape-fdstore-preserve|\
        shape-exec-start-post|\
        shape-control-group|\
        shape-control-group-id|\
        shape-cgroup-path|\
        shape-cgroup-procs|\
        shape-active-boundary|\
        shape-worker-child|\
        shape-worker-starttime|\
        shape-worker-parent|\
        shape-worker-cgroup|\
        shape-cgroup-members|\
        shape-worker-stability|\
        shape-cgroup-type|\
        shape-cgroup-stat|\
        record-size|\
        expectation-create|\
        expectation-write|\
        record-content|\
        launcher-executable|\
        launcher-script-fd|\
        launcher-script-flags|\
        freezer)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_may_own_driver_entry_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        arguments|\
        unit-name|\
        gid|\
        main-pid|\
        service-cgroup-argument|\
        observer-pid|\
        proc-records|\
        process-credentials|\
        observer-cgroup-record|\
        observer-cgroup-length|\
        observer-cgroup-boundary|\
        manager-main-pid|\
        network-namespace|\
        control-pid|\
        service-cgroup-root|\
        service-cgroup-filesystem|\
        service-cgroup-type|\
        service-cgroup-stat|\
        service-cgroup-procs|\
        service-cgroup-members|\
        service-cgroup-stability)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_non_retained_may_own_launch_failure_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_may_own_prefix='live worker-identity proof failed: '
    [ "$(grep -Fc "$non_retained_may_own_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_may_own_line=$(grep -F \
        "$non_retained_may_own_prefix" "$non_retained_diagnostic") \
        || return 1
    case $non_retained_may_own_line in
        "$non_retained_may_own_prefix"*)
            non_retained_may_own_reason=${non_retained_may_own_line#"$non_retained_may_own_prefix"}
            ;;
        *) return 1 ;;
    esac
    non_retained_may_own_category=$( \
        non_retained_may_own_launch_failure_category \
            "$non_retained_may_own_reason" \
    ) || return 1
    non_retained_may_own_preexec_category=
    if [ "$non_retained_may_own_category" = preexec-barrier ] \
        || [ "$non_retained_may_own_category" = service-shape ]; then
        non_retained_may_own_preexec_prefix='VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1='
        [ "$(grep -Fc "$non_retained_may_own_preexec_prefix" \
            "$non_retained_diagnostic")" -eq 1 ] || return 1
        non_retained_may_own_preexec_line=$(grep -F \
            "$non_retained_may_own_preexec_prefix" \
            "$non_retained_diagnostic") || return 1
        case $non_retained_may_own_preexec_line in
            "$non_retained_may_own_preexec_prefix"*)
                non_retained_may_own_preexec_category=${non_retained_may_own_preexec_line#"$non_retained_may_own_preexec_prefix"}
                ;;
            *) return 1 ;;
        esac
        non_retained_may_own_preexec_barrier_stage_is_safe \
            "$non_retained_may_own_preexec_category" || return 1
    fi
    non_retained_may_own_driver_start_stage=
    non_retained_may_own_driver_start_prefix=VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_START_FAILURE_V1=
    non_retained_may_own_driver_start_count=$(grep -Fc \
        "$non_retained_may_own_driver_start_prefix" \
        "$non_retained_diagnostic") || :
    case $non_retained_may_own_category:$non_retained_may_own_driver_start_count in
        identity-observer-exit:1|service-observer-exit:1)
            non_retained_may_own_driver_start_line=$(grep -F \
                "$non_retained_may_own_driver_start_prefix" \
                "$non_retained_diagnostic") || return 1
            case $non_retained_may_own_driver_start_line in
                "$non_retained_may_own_driver_start_prefix"*)
                    non_retained_may_own_driver_start_stage=${non_retained_may_own_driver_start_line#"$non_retained_may_own_driver_start_prefix"}
                    ;;
                *) return 1 ;;
            esac
            non_retained_production_launch_stage_is_safe \
                "$non_retained_may_own_driver_start_stage" || return 1
            ;;
        identity-observer-exit:*|service-observer-exit:*) return 1 ;;
        *:0) ;;
        *) return 1 ;;
    esac
    non_retained_may_own_driver_entry_stage=
    non_retained_may_own_driver_entry_prefix=VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=
    non_retained_may_own_driver_entry_count=$(grep -Fc \
        "$non_retained_may_own_driver_entry_prefix" \
        "$non_retained_diagnostic") || :
    case $non_retained_may_own_category:$non_retained_may_own_driver_start_stage:$non_retained_may_own_driver_entry_count in
        identity-observer-exit:preflight-runtime:1|\
        service-observer-exit:preflight-runtime:1)
            non_retained_may_own_driver_entry_line=$(grep -F \
                "$non_retained_may_own_driver_entry_prefix" \
                "$non_retained_diagnostic") || return 1
            case $non_retained_may_own_driver_entry_line in
                "$non_retained_may_own_driver_entry_prefix"*)
                    non_retained_may_own_driver_entry_stage=${non_retained_may_own_driver_entry_line#"$non_retained_may_own_driver_entry_prefix"}
                    ;;
                *) return 1 ;;
            esac
            non_retained_may_own_driver_entry_stage_is_safe \
                "$non_retained_may_own_driver_entry_stage" || return 1
            ;;
        identity-observer-exit:preflight-runtime:0|\
        service-observer-exit:preflight-runtime:0) ;;
        *:*:0) ;;
        *) return 1 ;;
    esac
    printf 'non-retained helper-boundary PR smoke MayOwn launch category: %s\n' \
        "$non_retained_may_own_category" >&2
    if [ -n "$non_retained_may_own_preexec_category" ]; then
        printf 'non-retained helper-boundary PR smoke MayOwn preexec category: %s\n' \
            "$non_retained_may_own_preexec_category" >&2
    fi
    if [ -n "$non_retained_may_own_driver_start_stage" ]; then
        printf 'non-retained helper-boundary PR smoke MayOwn observer failure stage: %s\n' \
            "$non_retained_may_own_driver_start_stage" >&2
    fi
    if [ -n "$non_retained_may_own_driver_entry_stage" ]; then
        printf 'non-retained helper-boundary PR smoke MayOwn driver-entry failure stage: %s\n' \
            "$non_retained_may_own_driver_entry_stage" >&2
    fi
}

non_retained_boundary_validator_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        capture-unsafe|\
        status-invalid|\
        stdout-nonempty|\
        status-zero|\
        stderr-empty|\
        input-size|\
        json-value|\
        canonical-encoding|\
        source-artifacts|\
        environment|\
        clock-format|\
        clock-order|\
        invocations|\
        lifecycle|\
        host-state|\
        fixed-contract)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_non_retained_boundary_validator_failure_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_validator_diagnostic=$1
    [ -f "$non_retained_validator_diagnostic" ] \
        && [ ! -L "$non_retained_validator_diagnostic" ] || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_validator_diagnostic" \
        2>/dev/null || true)" = "1:$(id -u):600" ] || return 1
    non_retained_validator_diagnostic_size=$(stat -Lc '%s' \
        "$non_retained_validator_diagnostic") || return 1
    [ "$non_retained_validator_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_validator_diagnostic" || return 1

    non_retained_validator_failure_record='live worker-identity proof failed: the helper-boundary report failed strict validation'
    [ "$(grep -Fxc "$non_retained_validator_failure_record" \
        "$non_retained_validator_diagnostic")" -eq 1 ] || return 1
    [ "$(grep -Fc 'live worker-identity proof failed: ' \
        "$non_retained_validator_diagnostic")" -eq 1 ] || return 1
    non_retained_validator_prefix=VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=
    [ "$(grep -Fc "$non_retained_validator_prefix" \
        "$non_retained_validator_diagnostic")" -eq 1 ] || return 1
    non_retained_validator_pattern='^VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=(capture-unsafe|status-invalid|stdout-nonempty|status-zero|stderr-empty|input-size|json-value|canonical-encoding|source-artifacts|environment|clock-format|clock-order|invocations|lifecycle|host-state|fixed-contract)$'
    [ "$(grep -Ec "$non_retained_validator_pattern" \
        "$non_retained_validator_diagnostic")" -eq 1 ] || return 1
    non_retained_validator_stage=$(grep -E "$non_retained_validator_pattern" \
        "$non_retained_validator_diagnostic") || return 1
    non_retained_validator_stage=${non_retained_validator_stage#"$non_retained_validator_prefix"}
    non_retained_boundary_validator_stage_is_safe \
        "$non_retained_validator_stage" || return 1
    printf 'non-retained helper-boundary PR smoke report-validation category: %s\n' \
        "$non_retained_validator_stage" >&2
}

non_retained_restart_successor_debugger_category_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        exec-not-caught|\
        breakpoint-not-installed|\
        breakpoint-not-reached|\
        marker-invalid|\
        observer-manager-binding|\
        observer-precrash-record|\
        observer-fdstore-read|\
        observer-fdstore-count|\
        observer-fdstore-name|\
        observer-journal-read|\
        observer-journal-value|\
        observer-invocation-read|\
        observer-invocation-reuse|\
        observer-mainpid-reuse|\
        observer-restart-count|\
        observer-socket-change|\
        observer-time|\
        observer-starttime|\
        observer-record-build|\
        observer-record-publication|\
        observer-timeout|\
        observer-other|\
        post-observer)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_restart_retirement_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        adoption|identity|initial-snapshot|stop-request|stop-wait|reset-failed|\
        reset-wait|fdstore-clean|post-clean|final-reset|collection)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_restart_readiness_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        preflight|clock-read|clock-backwards|lineage-pid|lineage-invocation|\
        socket-capture|\
        initial-journal-value|stage-transition|bind-runtime-read|\
        bind-runtime-value|final-journal-read|final-journal-value|journal-next|\
        journal-state-before|journal-state-after|journal-state-change|\
        socket-stability|final-lineage-pid|final-lineage-invocation|timeout)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_restart_readiness_failure_detail_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_readiness_diagnostic=$1
    [ -f "$non_retained_readiness_diagnostic" ] \
        && [ ! -L "$non_retained_readiness_diagnostic" ] || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_readiness_diagnostic" \
        2>/dev/null || true)" = "1:$(id -u):600" ] || return 1
    non_retained_readiness_diagnostic_size=$(stat -Lc '%s' \
        "$non_retained_readiness_diagnostic") || return 1
    [ "$non_retained_readiness_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_readiness_diagnostic" || return 1
    non_retained_readiness_prefix=VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=
    [ "$(grep -Fc "$non_retained_readiness_prefix" \
        "$non_retained_readiness_diagnostic")" -eq 1 ] || return 1
    non_retained_readiness_line=$(grep -F \
        "$non_retained_readiness_prefix" \
        "$non_retained_readiness_diagnostic") || return 1
    case $non_retained_readiness_line in
        "$non_retained_readiness_prefix"*) ;;
        *) return 1 ;;
    esac
    non_retained_readiness_detail=${non_retained_readiness_line#"$non_retained_readiness_prefix"}
    non_retained_restart_readiness_stage_is_safe \
        "$non_retained_readiness_detail" || return 1
    printf '%s\n' "$non_retained_readiness_detail"
}

non_retained_restart_retirement_failure_detail_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_retirement_diagnostic=$1
    [ -f "$non_retained_retirement_diagnostic" ] \
        && [ ! -L "$non_retained_retirement_diagnostic" ] || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_retirement_diagnostic" \
        2>/dev/null || true)" = "1:$(id -u):600" ] || return 1
    non_retained_retirement_diagnostic_size=$(stat -Lc '%s' \
        "$non_retained_retirement_diagnostic") || return 1
    [ "$non_retained_retirement_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_retirement_diagnostic" || return 1
    non_retained_retirement_prefix=VOLPAROSSA_HELPER_LIVE_RESTART_RETIREMENT_DIAGNOSTIC_V1=
    [ "$(grep -Fc "$non_retained_retirement_prefix" \
        "$non_retained_retirement_diagnostic")" -eq 1 ] || return 1
    non_retained_retirement_line=$(grep -F \
        "$non_retained_retirement_prefix" \
        "$non_retained_retirement_diagnostic") || return 1
    case $non_retained_retirement_line in
        "$non_retained_retirement_prefix"*) ;;
        *) return 1 ;;
    esac
    non_retained_retirement_detail=${non_retained_retirement_line#"$non_retained_retirement_prefix"}
    non_retained_restart_retirement_stage_is_safe \
        "$non_retained_retirement_detail" || return 1
    printf '%s\n' "$non_retained_retirement_detail"
}

non_retained_restart_launch_failure_category() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        'restart debugger symbols could not be inspected'|\
        'restart debugger symbols are not exact and unique')
            printf '%s\n' debugger-symbols ;;
        'restart ownership marker could not be derived'|\
        'restart ownership marker is non-canonical'|\
        'restart ownership marker is unsafe')
            printf '%s\n' ownership-marker ;;
        'restart debugger path was not initially absent')
            printf '%s\n' debugger-paths ;;
        'singleton restart unit name is unsafe'|\
        'singleton restart unit name is not distinct'|\
        'singleton restart unit state could not be determined'|\
        'singleton restart unit name is already loaded'|\
        'singleton restart unit could not be launched')
            printf '%s\n' unit-launch ;;
        'singleton restart launch envelope is invalid')
            printf '%s\n' launch-envelope ;;
        'singleton restart manager binding is invalid')
            printf '%s\n' manager-binding ;;
        'singleton restart precrash identity did not appear')
            printf '%s\n' precrash-record ;;
        'singleton restart initial MainPID is unavailable')
            printf '%s\n' initial-mainpid-read ;;
        'singleton restart initial MainPID is invalid')
            printf '%s\n' initial-mainpid-shape ;;
        'singleton restart initial invocation is not hook-bound')
            printf '%s\n' initial-invocation-binding ;;
        'singleton restart initial MainPID is not hook-bound')
            printf '%s\n' initial-mainpid-binding ;;
        'singleton restart initial hook PID is unavailable')
            printf '%s\n' initial-hook-pid-read ;;
        'singleton restart initial hook PID is invalid')
            printf '%s\n' initial-hook-pid-shape ;;
        'singleton restart initial ControlPID is not hook-bound')
            printf '%s\n' initial-controlpid-binding ;;
        'singleton restart initial hook starttime is unavailable')
            printf '%s\n' initial-hook-starttime ;;
        'restart mount keeper PID is invalid'|\
        'restart mount keeper starttime is unavailable'|\
        'restart mount namespace keeper did not survive')
            printf '%s\n' mount-keeper ;;
        'initial restart debugger commands could not be written')
            printf '%s\n' debugger-command ;;
        'initial forced-crash debugger did not complete')
            printf '%s\n' debugger-execution ;;
        'initial forced-crash start failure record was not consumed exactly')
            printf '%s\n' initial-start-failure ;;
        'post-crash restart MainPID is unavailable'|\
        'post-crash forced-helper MainPID is not zero')
            printf '%s\n' sigkill-mainpid ;;
        'post-crash restart count is unavailable'|\
        'post-crash forced-helper restart count is not zero')
            printf '%s\n' sigkill-restart-count ;;
        'restart unit result is unavailable'|\
        'post-crash forced-helper result is not signal')
            printf '%s\n' sigkill-result ;;
        'restart ExecMainCode is unavailable'|\
        'post-crash forced-helper code is not CLD_KILLED')
            printf '%s\n' sigkill-code ;;
        'restart ExecMainStatus is unavailable'|\
        'post-crash forced-helper status is not SIGKILL')
            printf '%s\n' sigkill-status ;;
        'post-crash failed invocation lost its exact ownership fence')
            printf '%s\n' ownership-fence ;;
        'forced-crash boundary record is unavailable')
            printf '%s\n' crash-record ;;
        'initial debugger log is unsafe'|\
        'initial debugger log exceeds 1 MiB')
            printf '%s\n' debugger-log ;;
        'forced-crash time is unavailable')
            printf '%s\n' crash-time ;;
        'post-crash exact custody was not preserved')
            printf '%s\n' exact-custody ;;
        'restart successor did not become manager-bound'|\
        'restart successor changed before its pre-exec barrier')
            printf '%s\n' successor-mainpid ;;
        'restart successor pre-exec barrier did not appear'|\
        'restart successor pre-exec barrier is oversized'|\
        'restart successor barrier invocation is unavailable'|\
        'restart successor barrier PID is unavailable'|\
        'restart successor barrier expectation could not be created'|\
        'restart successor barrier expectation is unavailable'|\
        'restart successor pre-exec barrier is not manager-bound')
            printf '%s\n' successor-barrier ;;
        'restart successor starttime is unavailable'|\
        'restart successor count is unavailable'|\
        'restart successor count is not exactly one'|\
        'restart successor lost the ownership marker'|\
        'restart successor lineage could not be adopted'|\
        'restart successor invocation is invalid'|\
        'restart successor lineage changed after adoption')
            printf '%s\n' successor-identity ;;
        'successor debugger commands could not be written')
            printf '%s\n' successor-debugger-command ;;
        'successor debugger starttime is unavailable'|\
        'successor debugger exited before arming'|\
        'successor debugger did not arm'|\
        'successor debugger readiness record is unsafe'|\
        'successor debugger readiness record is oversized'|\
        'successor debugger readiness record is invalid')
            printf '%s\n' successor-debugger-start ;;
        'restart successor release FIFO changed before release'|\
        'restart successor pre-exec barrier could not be released'|\
        'restart successor release FIFO changed after release')
            printf '%s\n' successor-release ;;
        'successor recovery-boundary debugger did not complete'|\
        'successor recovery boundary is not exact')
            printf '%s\n' successor-debugger-execution ;;
        'successor debugger failure classification is invalid')
            printf '%s\n' successor-debugger-classification ;;
        'successor recovery-boundary debugger failed: '*)
            non_retained_restart_successor_detail=${1#successor recovery-boundary debugger failed: }
            non_retained_restart_successor_debugger_category_is_safe \
                "$non_retained_restart_successor_detail" || return 1
            printf 'successor-debugger-%s\n' \
                "$non_retained_restart_successor_detail"
            ;;
        'successor debugger log is unsafe'|\
        'successor debugger log exceeds 1 MiB')
            printf '%s\n' successor-debugger-log ;;
        'restart ExactPresent settlement did not complete')
            printf '%s\n' successor-settlement ;;
        'restart successor start failure record is invalid'|\
        'restart successor pending start failure record is unsafe'|\
        'restart successor start failure category is invalid')
            printf '%s\n' successor-start-record ;;
        'restart successor readiness diagnostic is invalid')
            printf '%s\n' successor-start-readiness-classification ;;
        'restart successor start hook failed during preflight')
            printf '%s\n' successor-start-preflight ;;
        'restart successor start hook failed during recovery wait')
            printf '%s\n' successor-start-recovery ;;
        'restart successor start hook failed during lineage validation')
            printf '%s\n' successor-start-lineage ;;
        'restart successor start hook failed during descriptor settlement')
            printf '%s\n' successor-start-descriptor ;;
        'restart successor start hook failed during journal settlement')
            printf '%s\n' successor-start-journal ;;
        'restart successor start hook failed during socket validation')
            printf '%s\n' successor-start-socket ;;
        'restart successor start hook failed during publication')
            printf '%s\n' successor-start-publication ;;
        'restart successor invocation record is unavailable'|\
        'restart successor invocation record is invalid'|\
        'restart settlement changed the adopted successor invocation')
            printf '%s\n' successor-settlement-binding ;;
        'restart boundary starttime is unavailable')
            printf '%s\n' successor-starttime-boundary-read ;;
        'restart boundary starttime is invalid')
            printf '%s\n' successor-starttime-boundary-shape ;;
        'restart successor starttime is unavailable after descriptor settlement')
            printf '%s\n' successor-starttime-post-detach-read ;;
        'restart successor starttime changed after recovery')
            printf '%s\n' successor-starttime-post-detach-change ;;
        'restart successor retirement failure category is invalid')
            printf '%s\n' successor-retirement-classification ;;
        'restart successor retirement diagnostic could not be reported')
            printf '%s\n' successor-retirement-classification ;;
        'restart successor could not be retired')
            printf '%s\n' successor-retirement ;;
        'restart unit was not collected')
            printf '%s\n' successor-collection ;;
        'restart journal lock remained held')
            printf '%s\n' successor-lock-held ;;
        'restart journal lock could not be opened after retirement')
            printf '%s\n' successor-lock-open ;;
        'restart runtime did not retire cleanly')
            printf '%s\n' successor-runtime-retirement ;;
        'restart final journal could not be revalidated')
            printf '%s\n' successor-final-journal-read ;;
        'restart final journal proof is invalid')
            printf '%s\n' successor-final-journal-value ;;
        'internal production proof failure state is inconsistent')
            printf '%s\n' successor-proof-state ;;
        *) return 1 ;;
    esac
}

non_retained_restart_initial_hook_failure_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        preflight|\
        publication|\
        ack-path|\
        ack-payload|\
        ack-lineage|\
        ack-pins|\
        ack-timeout|\
        post-lineage|\
        post-pins|\
        cleanup|\
        terminal-publication|\
        terminal-ack-path|\
        terminal-ack-payload|\
        terminal-ack-lineage|\
        terminal-ack-pins|\
        terminal-ack-timeout|\
        terminal-post-lineage|\
        terminal-post-pins)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_restart_initial_driver_failure_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        appearance|\
        unsafe-pending-path|\
        main-pid|\
        restart-count|\
        invocation|\
        marker|\
        start-payload|\
        hook-payload|\
        terminal-payload|\
        stable-inode|\
        unlink|\
        absence|\
        control-pid|\
        hook-identity|\
        hook-quiescence)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_restart_initial_failure_detail_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_restart_initial_detail_file=$1
    non_retained_restart_initial_hook_prefix=VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_HOOK_V1=
    non_retained_restart_initial_driver_prefix=VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_DRIVER_V1=
    non_retained_restart_initial_start_prefix=VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_START_V1=
    non_retained_restart_initial_hook_count=$(grep -Fc \
        "$non_retained_restart_initial_hook_prefix" \
        "$non_retained_restart_initial_detail_file" || true)
    non_retained_restart_initial_driver_count=$(grep -Fc \
        "$non_retained_restart_initial_driver_prefix" \
        "$non_retained_restart_initial_detail_file" || true)
    non_retained_restart_initial_start_count=$(grep -Fc \
        "$non_retained_restart_initial_start_prefix" \
        "$non_retained_restart_initial_detail_file" || true)
    case $non_retained_restart_initial_hook_count:$non_retained_restart_initial_driver_count in
        *[!0-9:]*|:*|*:) return 1 ;;
    esac
    case $non_retained_restart_initial_start_count in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$non_retained_restart_initial_hook_count" -eq 0 ] \
        && [ "$non_retained_restart_initial_driver_count" -eq 0 ]; then
        printf '%s\n' initial-diagnostic-absent
        return 0
    fi
    if [ $((non_retained_restart_initial_hook_count \
        + non_retained_restart_initial_driver_count)) -ne 1 ]; then
        printf '%s\n' initial-diagnostic-invalid
        return 0
    fi
    if [ "$non_retained_restart_initial_hook_count" -eq 1 ]; then
        if [ "$non_retained_restart_initial_start_count" -ne 0 ]; then
            printf '%s\n' initial-diagnostic-invalid
            return 0
        fi
        non_retained_restart_initial_detail_line=$(grep -F \
            "$non_retained_restart_initial_hook_prefix" \
            "$non_retained_restart_initial_detail_file") || return 1
        case $non_retained_restart_initial_detail_line in
            "$non_retained_restart_initial_hook_prefix"*) ;;
            *)
                printf '%s\n' initial-diagnostic-invalid
                return 0
                ;;
        esac
        non_retained_restart_initial_detail_stage=${non_retained_restart_initial_detail_line#"$non_retained_restart_initial_hook_prefix"}
        if non_retained_restart_initial_hook_failure_stage_is_safe \
            "$non_retained_restart_initial_detail_stage"; then
            printf 'initial-hook-%s\n' \
                "$non_retained_restart_initial_detail_stage"
        else
            printf '%s\n' initial-diagnostic-invalid
        fi
        return 0
    fi
    non_retained_restart_initial_detail_line=$(grep -F \
        "$non_retained_restart_initial_driver_prefix" \
        "$non_retained_restart_initial_detail_file") || return 1
    case $non_retained_restart_initial_detail_line in
        "$non_retained_restart_initial_driver_prefix"*) ;;
        *)
            printf '%s\n' initial-diagnostic-invalid
            return 0
            ;;
    esac
    non_retained_restart_initial_detail_stage=${non_retained_restart_initial_detail_line#"$non_retained_restart_initial_driver_prefix"}
    if non_retained_restart_initial_driver_failure_stage_is_safe \
        "$non_retained_restart_initial_detail_stage"; then
        if [ "$non_retained_restart_initial_start_count" -eq 0 ]; then
            printf 'initial-driver-%s\n' \
                "$non_retained_restart_initial_detail_stage"
        elif [ "$non_retained_restart_initial_start_count" -eq 1 ] \
            && [ "$non_retained_restart_initial_detail_stage" = start-payload ]; then
            non_retained_restart_initial_start_line=$(grep -F \
                "$non_retained_restart_initial_start_prefix" \
                "$non_retained_restart_initial_detail_file") || return 1
            case $non_retained_restart_initial_start_line in
                "$non_retained_restart_initial_start_prefix"*) ;;
                *)
                    printf '%s\n' initial-diagnostic-invalid
                    return 0
                    ;;
            esac
            non_retained_restart_initial_start_stage=${non_retained_restart_initial_start_line#"$non_retained_restart_initial_start_prefix"}
            if non_retained_production_launch_stage_is_safe \
                "$non_retained_restart_initial_start_stage"; then
                printf 'initial-driver-start-payload-%s\n' \
                    "$non_retained_restart_initial_start_stage"
            else
                printf '%s\n' initial-diagnostic-invalid
            fi
        else
            printf '%s\n' initial-diagnostic-invalid
        fi
    else
        printf '%s\n' initial-diagnostic-invalid
    fi
}

report_non_retained_restart_launch_failure_category() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_restart_failure_prefix='live worker-identity proof failed: '
    [ "$(grep -Fc "$non_retained_restart_failure_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_restart_failure_line=$(grep -F \
        "$non_retained_restart_failure_prefix" "$non_retained_diagnostic") \
        || return 1
    case $non_retained_restart_failure_line in
        "$non_retained_restart_failure_prefix"*) ;;
        *) return 1 ;;
    esac
    non_retained_restart_failure_reason=${non_retained_restart_failure_line#"$non_retained_restart_failure_prefix"}
    if [ "$non_retained_restart_failure_reason" = \
        'initial forced-crash start failure record was not consumed exactly' ] \
        || [ "$non_retained_restart_failure_reason" = \
            'initial forced-crash terminal handshake was not released exactly' ]; then
        non_retained_restart_failure_category=$( \
            non_retained_restart_initial_failure_detail_category \
                "$non_retained_diagnostic"
        ) || return 1
    elif [ "$non_retained_restart_failure_reason" = \
        'restart successor could not be retired' ]; then
        non_retained_restart_retirement_detail=$( \
            non_retained_restart_retirement_failure_detail_category \
                "$non_retained_diagnostic"
        ) || return 1
        non_retained_restart_failure_category=successor-retirement-$non_retained_restart_retirement_detail
    elif [ "$non_retained_restart_failure_reason" = \
        'restart successor start hook failed during socket validation' ]; then
        non_retained_restart_readiness_detail=$( \
            non_retained_restart_readiness_failure_detail_category \
                "$non_retained_diagnostic"
        ) || return 1
        non_retained_restart_failure_category=successor-start-readiness-$non_retained_restart_readiness_detail
    elif [ "$non_retained_restart_failure_reason" = \
        'restart successor start hook failed during journal settlement' ] \
        && grep -Fq \
            'VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=' \
            "$non_retained_diagnostic"; then
        non_retained_restart_readiness_detail=$( \
            non_retained_restart_readiness_failure_detail_category \
                "$non_retained_diagnostic"
        ) || return 1
        non_retained_restart_failure_category=successor-start-readiness-$non_retained_restart_readiness_detail
    else
        non_retained_restart_failure_category=$( \
            non_retained_restart_launch_failure_category \
                "$non_retained_restart_failure_reason"
        ) || return 1
    fi
    printf 'non-retained helper-boundary PR smoke restart-launch category: %s\n' \
        "$non_retained_restart_failure_category" >&2
}

report_non_retained_restart_launch_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_restart_launch_diagnostic_pattern='^VOLPAROSSA_HELPER_LIVE_RESTART_LAUNCH_DIAGNOSTIC_V1=captures-(yes|no),json-(yes|no),fresh-(yes|no),stdout-(empty|unit-only|nonempty|unsafe),stderr-(empty|nonempty|unsafe),manager-no$'
    [ "$(grep -Ec "$non_retained_restart_launch_diagnostic_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_restart_launch_diagnostic=$(grep -E \
        "$non_retained_restart_launch_diagnostic_pattern" \
        "$non_retained_diagnostic") || return 1
    printf 'non-retained helper-boundary PR smoke restart launch diagnostic: %s\n' \
        "${non_retained_restart_launch_diagnostic#VOLPAROSSA_HELPER_LIVE_RESTART_LAUNCH_DIAGNOSTIC_V1=}" >&2
}

report_non_retained_restart_crash_record_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_restart_crash_diagnostic_prefix=VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=
    [ "$(grep -Fc "$non_retained_restart_crash_diagnostic_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_restart_crash_diagnostic_pattern='^VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-(absent|unsafe),observer-(fdstore-read|fdstore-count|fdstore-name|journal-read|journal-value|control-binding|pin-open|pin-change|process-live|wireguard-live|publication|manager-binding|precrash|stderr-empty|stderr-other|stderr-unsafe)$'
    [ "$(grep -Ec "$non_retained_restart_crash_diagnostic_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_restart_crash_diagnostic=$(grep -E \
        "$non_retained_restart_crash_diagnostic_pattern" \
        "$non_retained_diagnostic") || return 1
    printf 'non-retained helper-boundary PR smoke restart crash-record diagnostic: %s\n' \
        "${non_retained_restart_crash_diagnostic#VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=}" >&2
}

report_non_retained_driver_phase() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_driver_phase_prefix=VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=
    [ "$(grep -Ec "^$non_retained_driver_phase_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_driver_phase_pattern='^VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=(staging|worker-launch|worker-terminal-observation|worker-retirement|production-launch|production-observation|production-retirement|restart-launch|restart-observation|restart-retirement|may-own-launch|may-own-first-crash|may-own-second-crash|may-own-recovery|may-own-retirement|final-verification)$'
    [ "$(grep -Ec "$non_retained_driver_phase_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_mixed_diagnostic_pattern='^(live worker-identity proof failed: predicate rejected: |VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=|VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=)'
    [ "$(grep -Ec "$non_retained_mixed_diagnostic_pattern" \
        "$non_retained_diagnostic")" -eq 0 ] || return 1
    non_retained_driver_phase=$(grep -E "$non_retained_driver_phase_pattern" \
        "$non_retained_diagnostic") || return 1
    non_retained_driver_phase=${non_retained_driver_phase#"$non_retained_driver_phase_prefix"}
    non_retained_driver_phase_is_safe "$non_retained_driver_phase" || return 1
    printf 'non-retained helper-boundary PR smoke driver phase: %s\n' \
        "$non_retained_driver_phase" >&2
}

report_non_retained_final_checkpoint() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_checkpoint_prefix=VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=
    [ "$(grep -Ec "^$non_retained_checkpoint_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_checkpoint_pattern='^VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=(host-state|structured-reporting|cleanup-summary|lifecycle-summary|artifact-integrity|source-integrity|report-times|report-generation|report-validation|restart-report-validation|publication-fence|stage-retirement)$'
    [ "$(grep -Ec "$non_retained_checkpoint_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_checkpoint=$(grep -E "$non_retained_checkpoint_pattern" \
        "$non_retained_diagnostic") || return 1
    non_retained_checkpoint=${non_retained_checkpoint#"$non_retained_checkpoint_prefix"}
    non_retained_final_checkpoint_is_safe "$non_retained_checkpoint" || return 1
    printf 'non-retained helper-boundary PR smoke final checkpoint: %s\n' \
        "$non_retained_checkpoint" >&2
}

report_non_retained_worker_launch_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_worker_diagnostic_pattern='^VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=run-(zero|nonzero|invalid),captures-(yes|no|invalid),json-(yes|no|invalid),manager-(yes|no|invalid),client-stderr-(empty|nonempty|unsafe),terminal-(success|failed-exit-one|failed-exit-status-(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])|other),stage-(empty|parent-contract|runtime-preparation|worker-spawn|publication|retirement-cleanup|other|unsafe)$'
    [ "$(grep -Ec "$non_retained_worker_diagnostic_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_worker_diagnostic=$(grep -E \
        "$non_retained_worker_diagnostic_pattern" "$non_retained_diagnostic") \
        || return 1
    non_retained_worker_diagnostic_prefix=VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=
    case $non_retained_worker_diagnostic in
        "$non_retained_worker_diagnostic_prefix"*) ;;
        *) return 1 ;;
    esac
    printf 'non-retained helper-boundary PR smoke worker launch diagnostic: %s\n' \
        "${non_retained_worker_diagnostic#"$non_retained_worker_diagnostic_prefix"}" >&2
}

report_non_retained_worker_confinement_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_confinement_diagnostic_prefix=VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=
    [ "$(grep -Ec "^$non_retained_confinement_diagnostic_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_confinement_diagnostic_pattern='^VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=(bounding|ambient|private-network|control-group)$'
    [ "$(grep -Ec "$non_retained_confinement_diagnostic_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_confinement_diagnostic=$(grep -E \
        "$non_retained_confinement_diagnostic_pattern" "$non_retained_diagnostic") \
        || return 1
    case $non_retained_confinement_diagnostic in
        "$non_retained_confinement_diagnostic_prefix"*) ;;
        *) return 1 ;;
    esac
    printf 'non-retained helper-boundary PR smoke worker confinement diagnostic: %s\n' \
        "${non_retained_confinement_diagnostic#"$non_retained_confinement_diagnostic_prefix"}" >&2
}

non_retained_production_launch_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        preflight-runtime|\
        identity-socket|\
        identity-lock|\
        identity-manager|\
        identity-launch|\
        identity-birth|\
        identity-process|\
        identity-stability|\
        identity-publication|\
        active-lock|\
        protocol-bind-before|\
        protocol-frame-bounds|\
        protocol-wire-shapes|\
        protocol-wrong-uid|\
        protocol-wrong-gid|\
        protocol-root-peer|\
        protocol-bind-after|\
        functional-underlay|\
        functional-underlay-parent-contract|\
        functional-underlay-pristine-namespace|\
        functional-underlay-pristine-link|\
        functional-underlay-pristine-ipv-four|\
        functional-underlay-pristine-ipv-six|\
        functional-underlay-absent|\
        functional-underlay-link|\
        functional-underlay-address|\
        functional-underlay-route|\
        functional-underlay-ifindex|\
        functional-underlay-readback-link|\
        functional-underlay-readback-address|\
        functional-underlay-readback-route|\
        functional-probe-ready|\
        functional-probe-fixture|\
        functional-probe-launch|\
        functional-probe-wait|\
        functional-probe-identity|\
        functional-probe-socket|\
        functional-probe-fdstore|\
        functional-worker-observation|\
        functional-relay-fixture|\
        functional-relay-traffic|\
        functional-relay-cleanup|\
        functional-client-release|\
        functional-client-cleanup|\
        functional-exit-ready|\
        functional-exit-worker-observation|\
        functional-exit-relay-fixture|\
        functional-exit-relay-traffic|\
        functional-exit-relay-cleanup|\
        functional-exit-release|\
        functional-exit-cleanup|\
        functional-relay-pair-ready|\
        functional-relay-pair-worker-observation|\
        functional-relay-pair-fixtures|\
        functional-relay-pair-traffic|\
        functional-relay-pair-cleanup|\
        functional-probe-finish|\
        functional-cleanup|\
        publication)
            return 0
            ;;
        *) return 1 ;;
    esac
}

non_retained_functional_probe_failure_value_is_safe() {
    [ "$#" -eq 1 ] || return 1
    non_retained_functional_failure_value=$1
    non_retained_functional_failure_phase=${non_retained_functional_failure_value%%,*}
    non_retained_functional_failure_class=${non_retained_functional_failure_value#*,}
    [ "$non_retained_functional_failure_value" = \
        "$non_retained_functional_failure_phase,$non_retained_functional_failure_class" ] \
        || return 1
    case $non_retained_functional_failure_phase in
        plan|connect|bind|prepare|activate|shutdown|ready|release|reconnect|commit|destroy|\
        client-settled|client-settlement-release|\
        second-cycle-plan|second-cycle-bind|second-cycle-prepare|\
        second-cycle-activate|reuse|second-cycle-shutdown|second-cycle-ready|\
        second-cycle-release|second-cycle-reconnect|second-cycle-commit|\
        second-cycle-destroy|second-cycle-settlement-release|\
        relay-pair-plan|relay-pair-bind|relay-pair-prepare|\
        relay-pair-activate|relay-pair-reuse|relay-pair-shutdown|relay-pair-ready|\
        relay-pair-release|relay-pair-reconnect|relay-pair-commit|\
        relay-pair-destroy|final-shutdown)
            ;;
        *) return 1 ;;
    esac
    case $non_retained_functional_failure_class in
        random|protocol|io|timeout|untrusted|correlation|unexpected-response)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_non_retained_production_launch_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    non_retained_diagnostic=$1
    [ -f "$non_retained_diagnostic" ] && [ ! -L "$non_retained_diagnostic" ] \
        || return 1
    [ "$(stat -Lc '%h:%u:%a' "$non_retained_diagnostic" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    non_retained_diagnostic_size=$(stat -Lc '%s' "$non_retained_diagnostic") \
        || return 1
    [ "$non_retained_diagnostic_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$non_retained_diagnostic" || return 1
    non_retained_production_failure='live worker-identity proof failed: predicate rejected: production-launch-status'
    [ "$(grep -Fxc "$non_retained_production_failure" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    [ "$(tail -n 1 -- "$non_retained_diagnostic")" = \
        "$non_retained_production_failure" ] || return 1
    non_retained_failure_pattern='^live worker-identity proof failed: predicate rejected: '
    [ "$(grep -Ec "$non_retained_failure_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_production_diagnostic_prefix=VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=
    [ "$(grep -Ec "^$non_retained_production_diagnostic_prefix" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_production_diagnostic_pattern='^VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=(preflight-runtime|identity-socket|identity-lock|identity-manager|identity-launch|identity-birth|identity-process|identity-stability|identity-publication|active-lock|protocol-bind-before|protocol-frame-bounds|protocol-wire-shapes|protocol-wrong-uid|protocol-wrong-gid|protocol-root-peer|protocol-bind-after|functional-underlay|functional-underlay-parent-contract|functional-underlay-pristine-namespace|functional-underlay-pristine-link|functional-underlay-pristine-ipv-four|functional-underlay-pristine-ipv-six|functional-underlay-absent|functional-underlay-link|functional-underlay-address|functional-underlay-route|functional-underlay-ifindex|functional-underlay-readback-link|functional-underlay-readback-address|functional-underlay-readback-route|functional-probe-ready|functional-probe-fixture|functional-probe-launch|functional-probe-wait|functional-probe-identity|functional-probe-socket|functional-probe-fdstore|functional-worker-observation|functional-relay-fixture|functional-relay-traffic|functional-relay-cleanup|functional-client-release|functional-client-cleanup|functional-exit-ready|functional-exit-worker-observation|functional-exit-relay-fixture|functional-exit-relay-traffic|functional-exit-relay-cleanup|functional-exit-release|functional-exit-cleanup|functional-relay-pair-ready|functional-relay-pair-worker-observation|functional-relay-pair-fixtures|functional-relay-pair-traffic|functional-relay-pair-cleanup|functional-probe-finish|functional-cleanup|publication)$'
    [ "$(grep -Ec "$non_retained_production_diagnostic_pattern" \
        "$non_retained_diagnostic")" -eq 1 ] || return 1
    non_retained_functional_diagnostic_prefix=VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=
    if non_retained_functional_diagnostic_count=$(grep -Ec \
        "^$non_retained_functional_diagnostic_prefix" \
        "$non_retained_diagnostic"); then
        :
    else
        non_retained_functional_grep_status=$?
        [ "$non_retained_functional_grep_status" -eq 1 ] || return 1
    fi
    case $non_retained_functional_diagnostic_count in
        0)
            non_retained_functional_failure_value=
            ;;
        1)
            non_retained_functional_diagnostic_pattern='^VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=(plan|connect|bind|prepare|activate|shutdown|ready|release|reconnect|commit|destroy|client-settled|client-settlement-release|second-cycle-plan|second-cycle-bind|second-cycle-prepare|second-cycle-activate|reuse|second-cycle-shutdown|second-cycle-ready|second-cycle-release|second-cycle-reconnect|second-cycle-commit|second-cycle-destroy|second-cycle-settlement-release|relay-pair-plan|relay-pair-bind|relay-pair-prepare|relay-pair-activate|relay-pair-reuse|relay-pair-shutdown|relay-pair-ready|relay-pair-release|relay-pair-reconnect|relay-pair-commit|relay-pair-destroy|final-shutdown),(random|protocol|io|timeout|untrusted|correlation|unexpected-response)$'
            [ "$(grep -Ec "$non_retained_functional_diagnostic_pattern" \
                "$non_retained_diagnostic")" -eq 1 ] || return 1
            non_retained_functional_diagnostic=$(grep -E \
                "$non_retained_functional_diagnostic_pattern" \
                "$non_retained_diagnostic") || return 1
            non_retained_functional_failure_value=${non_retained_functional_diagnostic#"$non_retained_functional_diagnostic_prefix"}
            non_retained_functional_probe_failure_value_is_safe \
                "$non_retained_functional_failure_value" || return 1
            ;;
        *) return 1 ;;
    esac
    non_retained_production_mixed_pattern='^(VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=|VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=|VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=|VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=|VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=)'
    [ "$(grep -Ec "$non_retained_production_mixed_pattern" \
        "$non_retained_diagnostic")" -eq 0 ] || return 1
    non_retained_production_diagnostic=$(grep -E \
        "$non_retained_production_diagnostic_pattern" "$non_retained_diagnostic") \
        || return 1
    non_retained_production_stage=${non_retained_production_diagnostic#"$non_retained_production_diagnostic_prefix"}
    non_retained_production_launch_stage_is_safe "$non_retained_production_stage" \
        || return 1
    if [ -n "$non_retained_functional_failure_value" ]; then
        case $non_retained_production_stage in
            functional-probe-wait|functional-client-release|functional-exit-release|\
            functional-probe-finish) ;;
            *) return 1 ;;
        esac
    fi
    printf 'non-retained helper-boundary PR smoke production launch diagnostic: %s\n' \
        "$non_retained_production_stage" >&2
    if [ -n "$non_retained_functional_failure_value" ]; then
        printf 'non-retained helper-boundary PR smoke Client/Exit/Relay-pair lease diagnostic: %s\n' \
            "$non_retained_functional_failure_value" >&2
    fi
}

case ${#expected_commit} in
    40|64) ;;
    *) blocked 'the expected commit is not a canonical Git object ID' ;;
esac
case $expected_commit in
    *[!0-9a-f]*|0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
        blocked 'the expected commit is not lowercase nonzero hexadecimal'
        ;;
esac
case $expected_source_ref in
    refs/heads/*) expected_source_branch=${expected_source_ref#refs/heads/} ;;
    *) blocked 'the expected source ref is not one branch ref' ;;
esac
if [ -z "$expected_source_branch" ] || [ "${#expected_source_ref}" -gt 255 ] \
    || ! git check-ref-format "$expected_source_ref" >/dev/null 2>&1 \
    || ! git check-ref-format --branch "$expected_source_branch" >/dev/null 2>&1; then
    blocked 'the expected source ref is not canonical'
fi
case $proof_mode in
    retained-main)
        [ "$expected_source_ref" = refs/heads/main ] \
            || blocked 'retained evidence requires refs/heads/main'
        ;;
    non-retained-pr-smoke)
        [ "$expected_source_ref" != refs/heads/main ] \
            || blocked 'main can never select non-retained PR smoke'
        ;;
    *) blocked 'the proof mode is not canonical' ;;
esac
case $expected_host_uid in
    ''|0|0*|*[!0-9]*) blocked 'the expected host UID is not canonical nonzero decimal' ;;
esac
case $expected_kvm_gid in
    ''|0|0*|*[!0-9]*) blocked 'the expected KVM GID is not canonical nonzero decimal' ;;
esac
if [ "${#expected_host_uid}" -gt 10 ] || [ "${#expected_kvm_gid}" -gt 10 ]; then
    blocked 'the expected host UID or KVM GID is outside the bounded form'
fi
case $expected_kvm_identity in
    *:*:*:*:'character special file') ;;
    *) blocked 'the expected KVM identity has the wrong shape' ;;
esac
kvm_identity_numbers="${expected_kvm_identity%:character special file}"
case $kvm_identity_numbers in
    ''|*[!0-9a-f:]*) blocked 'the expected KVM identity is not canonical' ;;
esac
if [ "${#expected_kvm_identity}" -gt 128 ]; then
    blocked 'the expected KVM identity is outside the bounded form'
fi

if [ "$(id -u)" -eq 0 ]; then
    blocked 'the VM runner itself must remain unprivileged'
fi
for command_name in \
    awk cat chmod cmp cp cloud-localds cut dd dirname find git grep id install jq mkfifo \
    mktemp mv python3 qemu-img qemu-system-x86_64 readlink rm scp sed sha256sum \
    sha512sum sleep ssh ssh-keygen ss stat tail tar timeout udevadm uname
do
    command -v "$command_name" >/dev/null 2>&1 \
        || blocked "required host tool is unavailable: $command_name"
done

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd -P)
manifest=$script_directory/debian13-amd64-image-v1.json
report_validator=$script_directory/validate-helper-boundary-evidence-v1.sh
restart_report_validator=$script_directory/validate-helper-restart-exact-present-evidence-v1.sh
may_own_report_validator=$script_directory/validate-helper-restart-may-own-custody-relay-evidence-v1.sh
environment_validator=$script_directory/validate-helper-boundary-vm-environment-v1.sh
restart_environment_validator=$script_directory/validate-helper-restart-vm-environment-v1.sh
may_own_environment_validator=$script_directory/validate-helper-restart-may-own-custody-relay-vm-environment-v1.sh
qemu_supervisor=$script_directory/qemu-pidfd-supervisor.py
manifest_sha256=c535c54e44f724aa05278fe2bfa7bf607ecd285b83f35e136f16b99d1b99392a
image_sha512=184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
image_filename=debian-13-genericcloud-amd64-20260826-2582.qcow2

if [ ! -f "$manifest" ] || [ -L "$manifest" ] \
    || [ "$(stat -Lc '%h' "$manifest" 2>/dev/null || true)" != 1 ]; then
    blocked 'the reviewed Debian image manifest is not one regular file'
fi
actual_manifest_sha256=$(sha256sum "$manifest" | awk '{print $1}') \
    || blocked 'the Debian image manifest cannot be hashed'
[ "$actual_manifest_sha256" = "$manifest_sha256" ] \
    || blocked 'the Debian image manifest differs from the reviewed v1 bytes'
jq -e \
    --arg filename "$image_filename" \
    --arg sha512 "$image_sha512" \
    '. == {
      architecture: "amd64",
      checksum_provenance: "manually-reviewed-upstream-sha512-no-detached-signature",
      checksum_url: "https://cloud.debian.org/images/cloud/trixie/20260826-2582/SHA512SUMS",
      debian_version: "13",
      filename: $filename,
      format: "qcow2",
      image_kind: "reviewed-debian-genericcloud",
      release_build: "20260826-2582",
      release_codename: "trixie",
      release_date: "2026-08-26",
      schema_version: 1,
      sha512: $sha512,
      systemd_version: 257,
      url: ("https://cloud.debian.org/images/cloud/trixie/20260826-2582/" + $filename)
    }' "$manifest" >/dev/null || blocked 'the Debian image manifest semantics are not exact'
jq -S -c . "$manifest" | cmp -s - "$manifest" \
    || blocked 'the Debian image manifest serialization is not canonical'
for fixed_tool in "$report_validator" "$restart_report_validator" \
    "$may_own_report_validator" "$environment_validator" \
    "$restart_environment_validator" "$may_own_environment_validator" \
    "$qemu_supervisor"; do
    if [ ! -f "$fixed_tool" ] || [ -L "$fixed_tool" ] \
        || [ "$(stat -Lc '%h' "$fixed_tool" 2>/dev/null || true)" != 1 ]; then
        blocked "a fixed evidence tool is unavailable: ${fixed_tool##*/}"
    fi
done
if [ ! -x "$report_validator" ] || [ ! -x "$environment_validator" ] \
    || [ ! -x "$qemu_supervisor" ]; then
    blocked 'the fixed evidence tools are not executable'
fi
python3 -c 'import os, signal, sys; sys.exit(0 if callable(getattr(os, "pidfd_open", None)) and callable(getattr(signal, "pidfd_send_signal", None)) else 1)' \
    || blocked 'Python pidfd lifecycle support is unavailable'

source_root=$(git -C "$repository_directory" rev-parse --show-toplevel 2>/dev/null) \
    || blocked 'the repository root cannot be established'
[ "$source_root" = "$repository_directory" ] \
    || blocked 'the VM runner is not inside the exact repository root'
source_head=$(git -C "$repository_directory" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
    || blocked 'the source HEAD cannot be established'
[ "$source_head" = "$expected_commit" ] || blocked 'HEAD differs from the expected commit'
source_branch=$(git -C "$repository_directory" symbolic-ref --quiet --short HEAD 2>/dev/null) \
    || blocked 'the source must be one checked-out branch'
[ "$source_branch" = "$expected_source_branch" ] \
    || blocked 'the checked-out branch differs from the expected source ref'
if [ "$proof_mode" = retained-main ]; then
    [ "$source_branch" = main ] || blocked 'retained VM evidence is restricted to main'
else
    [ "$source_branch" != main ] || blocked 'main can never run non-retained PR smoke'
fi
source_status=$(GIT_OPTIONAL_LOCKS=0 git -C "$repository_directory" \
    status --porcelain=v1 --untracked-files=normal --ignore-submodules=none 2>/dev/null) \
    || blocked 'the source worktree state cannot be established'
[ -z "$source_status" ] || blocked 'the source worktree must be clean'
if git -C "$repository_directory" ls-files --stage \
    | awk '$1 == "160000" { found=1 } END { exit !found }'; then
    blocked 'submodules are outside the fixed VM source-transfer contract'
fi

case $image_path in
    /*) ;;
    *) blocked 'the Debian image path must be absolute' ;;
esac
case $output_directory in
    /*) ;;
    *) blocked 'the output directory path must be absolute' ;;
esac
[ "$(readlink -f -- "$image_path" 2>/dev/null || true)" = "$image_path" ] \
    || blocked 'the Debian image path is not canonical'
[ "${image_path##*/}" = "$image_filename" ] \
    || blocked 'the Debian image filename is not the reviewed filename'
if [ ! -f "$image_path" ] || [ -L "$image_path" ]; then
    blocked 'the Debian image is not one regular file'
fi
image_stat=$(stat -Lc '%F:%h:%u:%a:%s' "$image_path" 2>/dev/null) \
    || blocked 'the Debian image metadata is unavailable'
image_type=${image_stat%%:*}
image_rest=${image_stat#*:}
image_links=${image_rest%%:*}
image_rest=${image_rest#*:}
image_owner=${image_rest%%:*}
image_rest=${image_rest#*:}
image_mode=${image_rest%%:*}
image_size=${image_rest##*:}
if [ "$image_type" != 'regular file' ] || [ "$image_links" != 1 ] \
    || [ "$image_owner" != "$(id -u)" ]; then
    blocked 'the Debian image ownership is unsafe'
fi
case $image_mode in
    400|440|444|600|640|644) ;;
    *) blocked 'the Debian image mode is broader than the reviewed read contract' ;;
esac
if [ "$image_size" -le 0 ] || [ "$image_size" -gt 2147483648 ]; then
    blocked 'the Debian image size is outside the bounded contract'
fi
actual_image_sha512=$(sha512sum "$image_path" | awk '{print $1}') \
    || blocked 'the Debian image cannot be hashed'
[ "$actual_image_sha512" = "$image_sha512" ] \
    || blocked 'the Debian image SHA-512 does not match the reviewed image'
image_info=$(qemu-img info --output=json "$image_path" 2>/dev/null) \
    || blocked 'the Debian image is not parseable as a qcow2 image'
printf '%s\n' "$image_info" | jq -e \
    '.format == "qcow2"
     and .["virtual-size"] >= 1073741824
     and .["virtual-size"] <= 21474836480
     and (has("backing-filename") | not)' >/dev/null \
    || blocked 'the Debian image qcow2 structure is outside the fixed contract'

[ "$(readlink -f -- "$output_directory" 2>/dev/null || true)" = "$output_directory" ] \
    || blocked 'the output directory path is not canonical'
if [ ! -d "$output_directory" ] || [ -L "$output_directory" ]; then
    blocked 'the output directory is not one real directory'
fi
[ "$(stat -Lc '%u:%a' "$output_directory" 2>/dev/null || true)" = "$(id -u):700" ] \
    || blocked 'the output directory must be owned by the runner and mode 0700'
if find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    blocked 'the output directory must start empty'
fi

verify_kvm_contract() {
    expected_uid_quad="$expected_host_uid:$expected_host_uid:$expected_host_uid:$expected_host_uid"
    expected_gid_quad="$expected_kvm_gid:$expected_kvm_gid:$expected_kvm_gid:$expected_kvm_gid"
    actual_uid_quad=$(
        awk '$1 == "Uid:" { print $2 ":" $3 ":" $4 ":" $5 }' \
            /proc/self/status 2>/dev/null
    ) || return 1
    actual_gid_quad=$(
        awk '$1 == "Gid:" { print $2 ":" $3 ":" $4 ":" $5 }' \
            /proc/self/status 2>/dev/null
    ) || return 1
    [ "$actual_uid_quad" = "$expected_uid_quad" ] || return 1
    [ "$actual_gid_quad" = "$expected_gid_quad" ] || return 1
    [ "$(awk '$1 == "Groups:" { print NF }' /proc/self/status 2>/dev/null)" \
        = 1 ] || return 1
    for capability_name in CapInh: CapPrm: CapEff: CapBnd: CapAmb:
    do
        capability_value=$(
            awk -v name="$capability_name" '$1 == name { print $2 }' \
                /proc/self/status 2>/dev/null
        ) || return 1
        case $capability_value in
            ''|*[!0]*) return 1 ;;
        esac
    done
    [ "$(awk '$1 == "NoNewPrivs:" { print $2 }' \
        /proc/self/status 2>/dev/null)" = 1 ] || return 1
    [ -c /dev/kvm ] || return 1
    [ "$(stat -Lc '%d:%i:%t:%T:%F' /dev/kvm 2>/dev/null || true)" \
        = "$expected_kvm_identity" ] || return 1
    [ "$(stat -Lc '%u:%g' /dev/kvm 2>/dev/null || true)" \
        = "0:$expected_kvm_gid" ] || return 1
    [ -r /dev/kvm ] && [ -w /dev/kvm ] || return 1
}

verify_kvm_contract \
    || blocked 'the process-scoped unprivileged KVM authority is invalid'
qemu_system=qemu-system-x86_64
if ! "$qemu_system" -accel help 2>/dev/null | grep -Fx kvm >/dev/null; then
    blocked 'this QEMU binary does not expose KVM acceleration'
fi
if ss -H -ltn 2>/dev/null | awk '$4 ~ /:22222$/ { found=1 } END { exit !found }'; then
    blocked 'the fixed loopback SSH port 22222 is already occupied'
fi

run_directory=
qemu_control=
qemu_supervisor_pid=
console_pid=
console_done=
console_sentinel_open=no
console_settled=no
console_published=no
console_log=
published_console_log=
console_publish_temporary=
image_was_used=no
safe_to_remove=yes

atomic_empty_file() {
    atomic_target=$1
    [ ! -e "$atomic_target" ] && [ ! -L "$atomic_target" ] || return 1
    (
        umask 077
        set -C
        : >"$atomic_target"
    ) 2>/dev/null || return 1
    [ -f "$atomic_target" ] && [ ! -L "$atomic_target" ] \
        && [ "$(stat -Lc '%h:%u:%a:%s' "$atomic_target" 2>/dev/null || true)" \
            = "1:$(id -u):600:0" ]
}

wait_for_path() {
    waited_path=$1
    waited_limit=$2
    waited_count=0
    while [ ! -f "$waited_path" ] || [ -L "$waited_path" ]; do
        [ "$waited_count" -lt "$waited_limit" ] || return 1
        sleep 1
        waited_count=$((waited_count + 1))
    done
}

validate_supervisor_record() {
    supervisor_record=$1
    supervisor_state=$2
    [ -f "$supervisor_record" ] && [ ! -L "$supervisor_record" ] || return 1
    [ "$(stat -c '%h:%u:%a' "$supervisor_record" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    jq -e -s 'length == 1' "$supervisor_record" >/dev/null 2>&1 || return 1
    jq -S -c . "$supervisor_record" | cmp -s - "$supervisor_record" || return 1
    if [ "$supervisor_state" = ready ]; then
        jq -e '. == {protocol: "volparossa-qemu-pidfd-supervisor-v3", state: "ready"}' \
            "$supervisor_record" >/dev/null
    elif [ "$supervisor_state" = status ]; then
        jq -e '
          . == {
            error: "supervisor-failure",
            protocol: "volparossa-qemu-pidfd-supervisor-v3",
            state: "failed"
          }
          or (
            type == "object"
            and keys == (["exit_code", "exit_signal", "protocol", "state", "termination", "trigger"] | sort)
            and .protocol == "volparossa-qemu-pidfd-supervisor-v3"
            and .state == "exited"
            and ((.exit_code | type == "number") != (.exit_signal | type == "number"))
            and (.exit_code == null or (.exit_code >= 0 and .exit_code <= 255 and (.exit_code | floor) == .exit_code))
            and (.exit_signal == null or (.exit_signal >= 1 and .exit_signal <= 64 and (.exit_signal | floor) == .exit_signal))
            and (.termination == "none" or .termination == "term" or .termination == "kill")
            and (.trigger == "child-exit" or .trigger == "stop-requested"
              or .trigger == "parent-death" or .trigger == "supervisor-signal"
              or .trigger == "control-error")
          )' \
            "$supervisor_record" >/dev/null
    else
        return 1
    fi
}

validate_supervisor_stderr() {
    supervisor_stderr=$1
    [ -f "$supervisor_stderr" ] && [ ! -L "$supervisor_stderr" ] || return 1
    [ "$(stat -c '%h:%u:%a' "$supervisor_stderr" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    supervisor_stderr_size=$(stat -c '%s' "$supervisor_stderr") || return 1
    [ "$supervisor_stderr_size" -le 917504 ]
}

validate_supervisor_qmp() {
    supervisor_qmp=$1
    [ -f "$supervisor_qmp" ] && [ ! -L "$supervisor_qmp" ] || return 1
    [ "$(stat -c '%h:%u:%a' "$supervisor_qmp" 2>/dev/null || true)" \
        = "1:$(id -u):600" ] || return 1
    supervisor_qmp_size=$(stat -c '%s' "$supervisor_qmp") || return 1
    [ "$supervisor_qmp_size" -le 65536 ] || return 1
    jq -e -s 'length == 1' "$supervisor_qmp" >/dev/null 2>&1 || return 1
    jq -S -c . "$supervisor_qmp" | cmp -s - "$supervisor_qmp" || return 1
    jq -e '
      type == "object"
      and keys == (["events", "protocol", "state", "truncated"] | sort)
      and .protocol == "volparossa-qemu-pidfd-supervisor-v3"
      and (.state == "final" or .state == "failed")
      and (.truncated | type == "boolean")
      and (.events | type == "array" and length <= 64)
      and all(.events[];
        if .event == "STOP" then
          . == {event: "STOP"}
        elif .event == "RESET" or .event == "SHUTDOWN" then
          type == "object"
          and keys == (["event", "guest", "reason"] | sort)
          and (.guest | type == "boolean")
          and (.reason == "unavailable" or .reason == "guest-panic"
            or .reason == "guest-reset" or .reason == "guest-shutdown"
            or .reason == "host-error" or .reason == "host-qmp-quit"
            or .reason == "host-qmp-system-reset" or .reason == "host-signal"
            or .reason == "host-ui" or .reason == "none"
            or .reason == "snapshot-load" or .reason == "subsystem-reset")
        elif .event == "GUEST_PANICKED" then
          type == "object"
          and keys == (["action", "event"] | sort)
          and (.action == "pause" or .action == "poweroff"
            or .action == "run" or .action == "unavailable")
        else false
        end)
      and (if .truncated then .state == "failed" else true end)' \
        "$supervisor_qmp" >/dev/null
}

wait_for_supervisor_ready() {
    waited_limit=$1
    waited_count=0
    while [ "$waited_count" -lt "$waited_limit" ]; do
        if [ -f "$qemu_control/ready" ] && [ ! -L "$qemu_control/ready" ]; then
            if [ -e "$qemu_control/status" ] || [ -L "$qemu_control/status" ]; then
                return 3
            fi
            return 0
        fi
        if [ -e "$qemu_control/status" ] || [ -L "$qemu_control/status" ]; then
            return 2
        fi
        sleep 1
        waited_count=$((waited_count + 1))
    done
    return 1
}

publish_reap_failure_diagnostics() {
    reaped_control=$1
    case $reaped_control in
        "$run_directory"/qemu-provisioning) reaped_phase=provisioning ;;
        "$run_directory"/qemu-proof) reaped_phase=proof ;;
        *) return 1 ;;
    esac
    publish_qemu_failure_diagnostics \
        "$reaped_phase" "$reaped_control/status" "$reaped_control/qmp" \
        "$reaped_control/stderr"
}

reap_qemu() {
    require_clean_exit=$1
    if [ -z "$qemu_supervisor_pid" ] || [ -z "$qemu_control" ]; then
        return 0
    fi
    if ! wait_for_path "$qemu_control/status" 90; then
        atomic_empty_file "$qemu_control/stop" || true
        if ! wait_for_path "$qemu_control/status" 30; then
            printf '%s\n' 'QEMU supervisor did not produce bounded status' >&2
            safe_to_remove=no
            return 1
        fi
    fi
    validate_supervisor_record "$qemu_control/status" status || {
        printf '%s\n' 'QEMU supervisor status is not canonical' >&2
        safe_to_remove=no
        return 1
    }
    validate_supervisor_qmp "$qemu_control/qmp" || {
        printf '%s\n' 'QEMU supervisor QMP record is not canonical' >&2
        safe_to_remove=no
        return 1
    }
    validate_supervisor_stderr "$qemu_control/stderr" || {
        printf '%s\n' 'QEMU supervisor stderr is not private and bounded' >&2
        safe_to_remove=no
        return 1
    }
    qemu_status_state=$(jq -r '.state' "$qemu_control/status")
    if [ "$qemu_status_state" = failed ]; then
        if [ "$require_clean_exit" = yes ] \
            && ! publish_reap_failure_diagnostics "$qemu_control"; then
            printf '%s\n' 'failed QEMU diagnostics could not be published' >&2
        fi
        atomic_empty_file "$qemu_control/ack" || {
            printf '%s\n' 'QEMU supervisor acknowledgement could not be published' >&2
            safe_to_remove=no
            return 1
        }
        set +e
        wait "$qemu_supervisor_pid"
        supervisor_exit=$?
        set -e
        qemu_supervisor_pid=
        qemu_control=
        if [ "$supervisor_exit" -eq 0 ]; then
            printf '%s\n' 'QEMU supervisor reported failure but exited successfully' >&2
        else
            printf 'QEMU supervisor failed before a usable VM lifecycle; status=%s\n' \
                "$supervisor_exit" >&2
        fi
        return 1
    fi
    qemu_exit_code=$(jq -r '.exit_code // "null"' "$qemu_control/status")
    qemu_exit_signal=$(jq -r '.exit_signal // "null"' "$qemu_control/status")
    qemu_trigger=$(jq -r '.trigger' "$qemu_control/status")
    qemu_termination=$(jq -r '.termination' "$qemu_control/status")
    qemu_clean_shutdown=no
    if jq -e '
      .state == "final"
      and .truncated == false
      and .events[-1] == {
        event: "SHUTDOWN", guest: true, reason: "guest-shutdown"
      }' "$qemu_control/qmp" >/dev/null; then
        qemu_clean_shutdown=yes
    fi
    qemu_clean_lifecycle=no
    if [ "$qemu_exit_code" = 0 ] && [ "$qemu_exit_signal" = null ] \
        && [ "$qemu_trigger" = child-exit ] && [ "$qemu_termination" = none ] \
        && [ "$qemu_clean_shutdown" = yes ]; then
        qemu_clean_lifecycle=yes
    fi
    if [ "$require_clean_exit" = yes ] && [ "$qemu_clean_lifecycle" != yes ] \
        && ! publish_reap_failure_diagnostics "$qemu_control"; then
        printf '%s\n' 'non-clean QEMU diagnostics could not be published' >&2
    fi
    atomic_empty_file "$qemu_control/ack" || {
        printf '%s\n' 'QEMU supervisor acknowledgement could not be published' >&2
        safe_to_remove=no
        return 1
    }
    set +e
    wait "$qemu_supervisor_pid"
    supervisor_exit=$?
    set -e
    qemu_supervisor_pid=
    qemu_control=
    if [ "$supervisor_exit" -ne 0 ]; then
        printf 'QEMU supervisor exited with status %s\n' "$supervisor_exit" >&2
        return 1
    fi
    if [ "$require_clean_exit" = yes ] && {
        [ "$qemu_exit_code" != 0 ] || [ "$qemu_exit_signal" != null ] \
            || [ "$qemu_trigger" != child-exit ] || [ "$qemu_termination" != none ];
    }; then
        printf 'QEMU did not exit cleanly: code=%s signal=%s trigger=%s termination=%s\n' \
            "$qemu_exit_code" "$qemu_exit_signal" "$qemu_trigger" "$qemu_termination" >&2
        return 1
    fi
    if [ "$require_clean_exit" = yes ] && [ "$qemu_clean_shutdown" != yes ]; then
        printf '%s\n' \
            'QEMU exit lacks the exact final guest-shutdown QMP event' >&2
        return 1
    fi
}

settle_console() {
    if [ "$console_settled" = yes ]; then
        return 0
    fi
    if [ "$console_sentinel_open" = yes ]; then
        exec 9>&-
        console_sentinel_open=no
    fi
    if [ -n "$console_pid" ]; then
        if ! wait_for_path "$console_done" 20; then
            printf '%s\n' 'bounded console collector did not settle' >&2
            safe_to_remove=no
            return 1
        fi
        set +e
        wait "$console_pid"
        console_status=$?
        set -e
        console_pid=
        if [ "$console_status" -ne 0 ]; then
            printf 'bounded console collector exited with status %s\n' "$console_status" >&2
            return 1
        fi
        console_settled=yes
    fi
}

require_no_private_key_marker() {
    scanned_path=$1
    if grep -aEq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$scanned_path"; then
        printf '%s\n' 'the bounded diagnostic contains private-key material' >&2
        return 1
    else
        scan_status=$?
        if [ "$scan_status" -ne 1 ]; then
            printf '%s\n' 'the bounded diagnostic could not be scanned for private-key material' >&2
            return 1
        fi
    fi
}

publish_console() {
    if [ "$console_published" = yes ]; then
        return 0
    fi
    [ "$console_settled" = yes ] || return 1
    [ -n "$console_log" ] && [ -n "$published_console_log" ] || return 1
    discard_console_publish_temporary || return 1
    [ -f "$console_log" ] && [ ! -L "$console_log" ] \
        && [ "$(stat -Lc '%h:%u:%a' "$console_log" 2>/dev/null || true)" \
            = "1:$(id -u):600" ] || return 1
    console_size=$(stat -Lc '%s' "$console_log") || return 1
    [ "$console_size" -le 16777216 ] || return 1
    require_no_private_key_marker "$console_log" || return 1
    [ ! -e "$published_console_log" ] && [ ! -L "$published_console_log" ] \
        || return 1
    console_publish_temporary=$(mktemp "$output_directory/.vm-console.log.XXXXXX") \
        || return 1
    chmod 0600 "$console_publish_temporary" \
        || { discard_console_publish_temporary || true; return 1; }
    cp -- "$console_log" "$console_publish_temporary" \
        || { discard_console_publish_temporary || true; return 1; }
    mv -f -- "$console_publish_temporary" "$published_console_log" \
        || { discard_console_publish_temporary || true; return 1; }
    console_publish_temporary=
    console_published=yes
}

publish_qemu_failure_diagnostics() {
    qemu_failure_phase=$1
    qemu_failure_status=$2
    qemu_failure_qmp=$3
    qemu_failure_stderr=$4
    case $qemu_failure_phase in provisioning|proof) ;; *) return 1 ;; esac
    validate_supervisor_record "$qemu_failure_status" status || return 1
    validate_supervisor_qmp "$qemu_failure_qmp" || return 1
    validate_supervisor_stderr "$qemu_failure_stderr" || return 1
    require_no_private_key_marker "$qemu_failure_stderr" || return 1
    [ -f "$proof_stderr_log" ] && [ ! -L "$proof_stderr_log" ] \
        && [ "$(stat -Lc '%h:%u:%a' "$proof_stderr_log" 2>/dev/null || true)" \
            = "1:$(id -u):600" ] || return 1
    {
        printf 'qemu_phase=%s\n' "$qemu_failure_phase"
        printf 'qemu_supervisor_status='
        jq -S -c . "$qemu_failure_status"
        printf 'qemu_event_record='
        jq -S -c . "$qemu_failure_qmp"
        printf '%s\n' 'qemu_stderr_tail_begin'
        cat "$qemu_failure_stderr"
        printf '\n%s\n' 'qemu_stderr_tail_end'
    } >"$proof_stderr_log" || return 1
    proof_stderr_size=$(stat -Lc '%s' "$proof_stderr_log") || return 1
    [ "$proof_stderr_size" -le 1048576 ] || return 1
    require_no_private_key_marker "$proof_stderr_log" || return 1
}

discard_console_publish_temporary() {
    [ -n "$console_publish_temporary" ] || return 0
    case $console_publish_temporary in
        "$output_directory"/.vm-console.log.??????) ;;
        *) return 1 ;;
    esac
    if [ -e "$console_publish_temporary" ] || [ -L "$console_publish_temporary" ]; then
        [ -f "$console_publish_temporary" ] && [ ! -L "$console_publish_temporary" ] \
            && [ "$(stat -Lc '%h:%u:%a' "$console_publish_temporary" 2>/dev/null || true)" \
                = "1:$(id -u):600" ] || return 1
        rm -f -- "$console_publish_temporary" || return 1
    fi
    console_publish_temporary=
}

scrub_supervisor_diagnostics() {
    supervisor_control_directory=$1
    case $supervisor_control_directory in
        "$run_directory"/qemu-provisioning|"$run_directory"/qemu-proof) ;;
        *) return 1 ;;
    esac
    if [ ! -e "$supervisor_control_directory" ] \
        && [ ! -L "$supervisor_control_directory" ]; then
        return 0
    fi
    [ -d "$supervisor_control_directory" ] \
        && [ ! -L "$supervisor_control_directory" ] \
        && [ "$(stat -c '%u:%a' "$supervisor_control_directory" 2>/dev/null || true)" \
            = "$(id -u):700" ] || return 1

    supervisor_qmp=$supervisor_control_directory/qmp
    if [ -e "$supervisor_qmp" ] || [ -L "$supervisor_qmp" ]; then
        validate_supervisor_qmp "$supervisor_qmp" || return 1
        rm -f -- "$supervisor_qmp" || return 1
    fi

    for supervisor_qmp_temporary in \
        "$supervisor_control_directory"/.qmp.*.tmp
    do
        if [ ! -e "$supervisor_qmp_temporary" ] \
            && [ ! -L "$supervisor_qmp_temporary" ]; then
            continue
        fi
        supervisor_qmp_temporary_name=${supervisor_qmp_temporary##*/}
        printf '%s\n' "$supervisor_qmp_temporary_name" \
            | grep -Eq '^\.qmp\.[0-9]+\.tmp$' || return 1
        [ -f "$supervisor_qmp_temporary" ] \
            && [ ! -L "$supervisor_qmp_temporary" ] \
            && [ "$(stat -c '%h:%u:%a' \
                "$supervisor_qmp_temporary" 2>/dev/null || true)" \
                = "1:$(id -u):600" ] || return 1
        supervisor_qmp_temporary_size=$(stat -c '%s' \
            "$supervisor_qmp_temporary") || return 1
        [ "$supervisor_qmp_temporary_size" -le 65536 ] || return 1
        rm -f -- "$supervisor_qmp_temporary" || return 1
    done

    supervisor_stderr=$supervisor_control_directory/stderr
    if [ -e "$supervisor_stderr" ] || [ -L "$supervisor_stderr" ]; then
        validate_supervisor_stderr "$supervisor_stderr" || return 1
        rm -f -- "$supervisor_stderr" || return 1
    fi

    for supervisor_stderr_temporary in \
        "$supervisor_control_directory"/.stderr.*.tmp
    do
        if [ ! -e "$supervisor_stderr_temporary" ] \
            && [ ! -L "$supervisor_stderr_temporary" ]; then
            continue
        fi
        supervisor_stderr_temporary_name=${supervisor_stderr_temporary##*/}
        printf '%s\n' "$supervisor_stderr_temporary_name" \
            | grep -Eq '^\.stderr\.[0-9]+\.tmp$' || return 1
        [ -f "$supervisor_stderr_temporary" ] \
            && [ ! -L "$supervisor_stderr_temporary" ] \
            && [ "$(stat -c '%h:%u:%a' \
                "$supervisor_stderr_temporary" 2>/dev/null || true)" \
                = "1:$(id -u):600" ] || return 1
        supervisor_stderr_temporary_size=$(stat -c '%s' \
            "$supervisor_stderr_temporary") || return 1
        [ "$supervisor_stderr_temporary_size" -le 917504 ] || return 1
        rm -f -- "$supervisor_stderr_temporary" || return 1
    done
}

scrub_sensitive_run_state() {
    [ -n "$run_directory" ] || return 0
    case $run_directory in
        /tmp/volparossa-helper-boundary-vm.??????) ;;
        *) return 1 ;;
    esac
    if [ -n "$console_publish_temporary" ] \
        && { [ -e "$console_publish_temporary" ] || [ -L "$console_publish_temporary" ]; }; then
        rm -f -- "$console_publish_temporary" || return 1
    fi
    for scrub_name in \
        source.tar.gz overlay.qcow2 seed.img guest-user-key guest-user-key.pub \
        guest-host-key guest-host-key.pub known-hosts user-data meta-data \
        guest-setup.sh guest-proof.sh helper-boundary-evidence-v1.json \
        helper-boundary-proof.stderr.log helper-boundary-evidence-v1.json.sha256 \
        helper-restart-exact-present-evidence-v1.json \
        helper-restart-exact-present-evidence-v1.json.sha256 \
        helper-restart-vm-environment-v1.json restart-validator.stdout \
        restart-validator.stderr restart-environment-validator.stdout \
        restart-environment-validator.stderr \
        helper-restart-may-own-custody-relay-evidence-v1.json \
        helper-restart-may-own-custody-relay-evidence-v1.json.sha256 \
        helper-restart-may-own-custody-relay-vm-environment-v1.json \
        may-own-validator.stdout may-own-validator.stderr \
        may-own-environment-validator.stdout may-own-environment-validator.stderr \
        vm-environment-v1.json \
        validator.stdout validator.stderr \
        environment-validator.stdout environment-validator.stderr vm-console.log \
        console.fifo console.done
    do
        scrub_path=$run_directory/$scrub_name
        if [ -e "$scrub_path" ] || [ -L "$scrub_path" ]; then
            rm -f -- "$scrub_path" || return 1
        fi
    done
    if [ -e "$run_directory/source" ] || [ -L "$run_directory/source" ]; then
        rm -rf --one-file-system -- "$run_directory/source" || return 1
    fi
    scrub_supervisor_diagnostics "$run_directory/qemu-provisioning" || return 1
    scrub_supervisor_diagnostics "$run_directory/qemu-proof" || return 1
    find "$run_directory" -mindepth 1 -maxdepth 1 \
        \( -type f -o -type p -o -type l \) \
        \( -name 'bounded.*' -o -name 'console.*' \) -delete \
        || return 1
}

cleanup() {
    cleanup_status=$?
    trap - EXIT
    trap '' HUP INT TERM
    discard_console_publish_temporary || cleanup_status=1
    if [ -n "$qemu_supervisor_pid" ]; then
        if [ -n "$qemu_control" ] && [ ! -e "$qemu_control/status" ]; then
            atomic_empty_file "$qemu_control/stop" || true
        fi
        reap_qemu no || cleanup_status=1
    fi
    if settle_console; then
        if [ "$safe_to_remove" = yes ] && [ "$proof_mode" = retained-main ]; then
            publish_console || cleanup_status=1
        fi
    else
        cleanup_status=1
    fi
    discard_console_publish_temporary || cleanup_status=1
    if [ "$image_was_used" = yes ]; then
        cleanup_image_hash=$(sha512sum "$image_path" 2>/dev/null | awk '{print $1}' || true)
        if [ "$cleanup_image_hash" != "$image_sha512" ]; then
            printf '%s\n' 'the reviewed base image changed during VM use' >&2
            cleanup_status=1
        fi
    fi
    if [ "$safe_to_remove" = yes ] && [ -n "$run_directory" ]; then
        rm -rf --one-file-system -- "$run_directory"
    elif [ -n "$run_directory" ]; then
        if scrub_sensitive_run_state; then
            printf 'retained only non-secret supervisor state after uncertain cleanup: %s\n' \
                "$run_directory" >&2
        else
            printf 'WARNING: sensitive state may remain in the private run directory: %s\n' \
                "$run_directory" >&2
            cleanup_status=1
        fi
        cleanup_status=1
    fi
    exit "$cleanup_status"
}

run_directory=$(mktemp -d /tmp/volparossa-helper-boundary-vm.XXXXXX)
case $run_directory in
    /tmp/volparossa-helper-boundary-vm.??????) ;;
    *) failed 'mktemp returned an unsafe run directory' ;;
esac
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 0700 "$run_directory"

console_log=$run_directory/vm-console.log
published_console_log=$output_directory/vm-console.log
proof_stderr_log=$output_directory/helper-boundary-proof.stderr.log
environment_report=$output_directory/vm-environment-v1.json
: >"$console_log"
: >"$proof_stderr_log"
chmod 0600 "$console_log" "$proof_stderr_log"
jq -S -c -n \
    --arg commit "$expected_commit" \
    --arg image_sha512 "$image_sha512" \
    '{expected_commit: $commit, image_sha512: $image_sha512,
      report_kind: "volparossa-helper-boundary-vm-environment",
      schema_version: 1, status: "STARTED"}' >"$environment_report"
chmod 0600 "$environment_report"

source_clone=$run_directory/source
if [ "$proof_mode" = retained-main ]; then
    git -c protocol.file.allow=always clone \
        --no-hardlinks --depth 1 --no-tags --single-branch --branch main \
        "file://$repository_directory" "$source_clone" >/dev/null 2>&1 \
        || failed 'the bounded tracked-only main source clone failed'
else
    git -c protocol.file.allow=always clone \
        --no-hardlinks --depth 1 --no-tags --single-branch \
        --branch "$expected_source_branch" \
        "file://$repository_directory" "$source_clone" >/dev/null 2>&1 \
        || failed 'the bounded tracked-only PR source clone failed'
fi
[ "$(git -C "$source_clone" rev-parse HEAD)" = "$expected_commit" ] \
    || failed 'the bounded source clone selected the wrong commit'
[ "$(git -C "$source_clone" symbolic-ref --quiet --short HEAD)" \
    = "$expected_source_branch" ] \
    || failed 'the bounded source clone selected the wrong branch'
[ -z "$(git -C "$source_clone" status --porcelain=v1 --untracked-files=all)" ] \
    || failed 'the bounded source clone is not clean'
[ ! -e "$source_clone/.git/objects/info/alternates" ] \
    || failed 'the bounded source clone unexpectedly uses object alternates'
if find "$source_clone/.git" -type l -print -quit | grep -q .; then
    failed 'the bounded source clone contains a Git metadata symlink'
fi
git -C "$source_clone" remote remove origin \
    || failed 'the local source origin could not be removed'
rm -rf --one-file-system -- "$source_clone/.git/logs"
rm -f -- "$source_clone/.git/FETCH_HEAD"
if grep -F "$repository_directory" "$source_clone/.git/config" >/dev/null 2>&1; then
    failed 'the bounded source clone retained the host workspace path'
fi

source_archive=$run_directory/source.tar.gz
tar -C "$run_directory" -czf "$source_archive" source \
    || failed 'the bounded source archive could not be created'
archive_size=$(stat -Lc '%s' "$source_archive")
if [ "$archive_size" -le 0 ] || [ "$archive_size" -gt 536870912 ]; then
    failed 'the bounded source archive exceeds 512 MiB'
fi
source_archive_sha256=$(sha256sum "$source_archive" | awk '{print $1}') \
    || failed 'the bounded source archive cannot be hashed'

overlay=$run_directory/overlay.qcow2
seed=$run_directory/seed.img
ssh_key=$run_directory/guest-user-key
guest_host_key=$run_directory/guest-host-key
known_hosts=$run_directory/known-hosts
user_data=$run_directory/user-data
meta_data=$run_directory/meta-data
console_fifo=$run_directory/console.fifo
guest_setup=$run_directory/guest-setup.sh
guest_proof=$run_directory/guest-proof.sh
retrieved_report=$run_directory/helper-boundary-evidence-v1.json
retrieved_restart_report=$run_directory/helper-restart-exact-present-evidence-v1.json
retrieved_may_own_report=$run_directory/helper-restart-may-own-custody-relay-evidence-v1.json
retrieved_stderr=$run_directory/helper-boundary-proof.stderr.log

qemu-img create -q -f qcow2 -F qcow2 -b "$image_path" "$overlay" 12G \
    || failed 'the disposable qcow2 overlay could not be created'
ssh-keygen -q -t ed25519 -N '' -C volparossa-helper-boundary-user -f "$ssh_key" \
    || failed 'the ephemeral guest user key could not be created'
ssh-keygen -q -t ed25519 -N '' -C volparossa-helper-boundary-host -f "$guest_host_key" \
    || failed 'the ephemeral guest host key could not be created'
guest_public_key=$(cat "$ssh_key.pub")
guest_host_public_key=$(cat "$guest_host_key.pub")
case $guest_public_key in
    'ssh-ed25519 '*volparossa-helper-boundary-user) ;;
    *) failed 'the generated guest user public key is not canonical' ;;
esac
case $guest_host_public_key in
    'ssh-ed25519 '*volparossa-helper-boundary-host) ;;
    *) failed 'the generated guest host public key is not canonical' ;;
esac
printf '[127.0.0.1]:22222 %s\n' "$guest_host_public_key" >"$known_hosts"
chmod 0600 "$known_hosts"

# Supplying ssh_keys already suppresses host-key generation. The pinned
# cloud-init schema requires ssh_genkeytypes to be non-empty when present.
{
    printf '%s\n' '#cloud-config' \
        'users:' \
        '  - name: volparossa' \
        '    gecos: VOLPAROSSA evidence runner' \
        '    groups: [sudo]' \
        '    sudo: "ALL=(ALL) NOPASSWD:ALL"' \
        '    shell: /bin/bash' \
        '    lock_passwd: true' \
        '    ssh_authorized_keys:'
    printf '      - %s\n' "$guest_public_key"
    printf '%s\n' \
        'ssh_pwauth: false' \
        'disable_root: true' \
        'ssh_deletekeys: true' \
        'ssh_keys:' \
        '  ed25519_private: |'
    sed 's/^/    /' "$guest_host_key"
    printf '  ed25519_public: %s\n' "$guest_host_public_key"
    printf '%s\n' \
        'growpart:' \
        '  mode: auto' \
        '  devices: [/]' \
        'resize_rootfs: true'
} >"$user_data"
printf 'instance-id: volparossa-helper-boundary-%s\nlocal-hostname: volparossa-proof\n' \
    "$(printf '%s' "$expected_commit" | cut -c1-12)" >"$meta_data"
cloud-localds "$seed" "$user_data" "$meta_data" \
    || failed 'the NoCloud seed could not be created'

cat >"$guest_setup" <<'GUEST_SETUP'
#!/bin/sh
set -eu
export LC_ALL=C
umask 077
expected_commit=$1
archive_sha256=$2
case $expected_commit in *[!0-9a-f]*|'') exit 64 ;; esac
case $archive_sha256 in *[!0-9a-f]*|'') exit 64 ;; esac
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install \
    --yes --no-install-recommends \
    build-essential ca-certificates cargo cmake curl dbus gdb git iproute2 iputils-ping jq nftables \
    pkg-config rustc sudo util-linux wireguard-tools
test "$(rustc --version | awk '{print $2}')" = 1.85.0
test "$(cargo --version | awk '{print $2}')" = 1.85.0
# shellcheck disable=SC1091
test "$(. /etc/os-release; printf '%s' "$ID:$VERSION_ID")" = debian:13
test "$(dpkg --print-architecture)" = amd64
test "$(uname -m)" = x86_64
test "$(sed -n '1p' /proc/1/comm)" = systemd
test "$(systemctl show --property=Version --value | sed 's/[^0-9].*$//')" = 257
test "$(systemd-detect-virt)" = kvm
cd /home/volparossa
printf '%s  source.tar.gz\n' "$archive_sha256" | sha256sum --check --strict -
tar -xzf source.tar.gz
cd source
test "$(git rev-parse HEAD)" = "$expected_commit"
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
test -z "$(git remote)"
cargo fetch --locked
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
GUEST_SETUP
chmod 0700 "$guest_setup"

cat >"$guest_proof" <<'GUEST_PROOF'
#!/bin/sh
set -eu
export LC_ALL=C
umask 077
expected_commit=$1
case $expected_commit in *[!0-9a-f]*|'') exit 64 ;; esac
cd /home/volparossa/source
test "$(rustc --version | awk '{print $2}')" = 1.85.0
test "$(cargo --version | awk '{print $2}')" = 1.85.0
# shellcheck disable=SC1091
test "$(. /etc/os-release; printf '%s' "$ID:$VERSION_ID")" = debian:13
test "$(dpkg --print-architecture)" = amd64
test "$(uname -m)" = x86_64
test "$(sed -n '1p' /proc/1/comm)" = systemd
test "$(systemctl show --property=Version --value | sed 's/[^0-9].*$//')" = 257
test "$(systemd-detect-virt)" = kvm
test "$(git rev-parse HEAD)" = "$expected_commit"
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
test -z "$(git remote)"
if curl --fail --silent --show-error --location \
    --connect-timeout 5 --max-time 10 --max-redirs 0 \
    --proto '=https' --proto-redir '=https' \
    https://cloud.debian.org/images/cloud/trixie/ >/dev/null 2>&1; then
    printf '%s\n' 'restricted proof boot unexpectedly reached external HTTPS' >&2
    exit 1
fi
cargo build --locked --offline -p volparossa-helper-entry
cargo build --locked --offline -p volparossa-helper \
    --example volparossa-helper-production-ipc-probe
install -m 0755 target/debug/volparossa-helper \
    target/debug/volparossa-helper.detached
mv -f target/debug/volparossa-helper.detached target/debug/volparossa-helper
install -m 0755 target/debug/examples/volparossa-helper-production-ipc-probe \
    target/debug/examples/volparossa-helper-production-ipc-probe.detached
mv -f target/debug/examples/volparossa-helper-production-ipc-probe.detached \
    target/debug/examples/volparossa-helper-production-ipc-probe
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
set +e
# The unprivileged shell intentionally owns these bounded output files. The
# root proof applies its own 1 MiB ceiling after two separately bounded and
# hash-verified executable staging copies.
# shellcheck disable=SC2024
sudo -n -- ./tests/helper/require-live-worker-identity-proof.sh --execute --yes \
    >/home/volparossa/helper-proof-reports.jsonl \
    2>/home/volparossa/helper-boundary-proof.stderr.log
proof_status=$?
set -e
chmod 0600 /home/volparossa/helper-boundary-proof.stderr.log
test "$(stat -c '%s' /home/volparossa/helper-boundary-proof.stderr.log)" -le 1048576 \
    || exit 1
if test "$proof_status" -ne 0; then
    exit "$proof_status"
fi
test "$(wc -l </home/volparossa/helper-proof-reports.jsonl)" -eq 3
sed -n '1p' /home/volparossa/helper-proof-reports.jsonl \
    >/home/volparossa/helper-boundary-evidence-v1.json
sed -n '2p' /home/volparossa/helper-proof-reports.jsonl \
    >/home/volparossa/helper-restart-exact-present-evidence-v1.json
sed -n '3p' /home/volparossa/helper-proof-reports.jsonl \
    >/home/volparossa/helper-restart-may-own-custody-relay-evidence-v1.json
rm -f -- /home/volparossa/helper-proof-reports.jsonl
chmod 0600 /home/volparossa/helper-boundary-evidence-v1.json \
    /home/volparossa/helper-restart-exact-present-evidence-v1.json \
    /home/volparossa/helper-restart-may-own-custody-relay-evidence-v1.json
test "$(stat -c '%s' /home/volparossa/helper-boundary-evidence-v1.json)" -ge 1
test "$(stat -c '%s' /home/volparossa/helper-boundary-evidence-v1.json)" -le 32768
test "$(stat -c '%s' /home/volparossa/helper-restart-exact-present-evidence-v1.json)" -ge 1
test "$(stat -c '%s' /home/volparossa/helper-restart-exact-present-evidence-v1.json)" -le 32768
test "$(stat -c '%s' /home/volparossa/helper-restart-may-own-custody-relay-evidence-v1.json)" -ge 1
test "$(stat -c '%s' /home/volparossa/helper-restart-may-own-custody-relay-evidence-v1.json)" -le 32768
test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
GUEST_PROOF
chmod 0700 "$guest_proof"

mkfifo -m 0600 "$console_fifo"
exec 9<>"$console_fifo"
console_sentinel_open=yes
console_done=$run_directory/console.done
(
    exec 9>&-
    {
        dd bs=65536 count=256 iflag=fullblock 2>/dev/null
        cat >/dev/null
    } <"$console_fifo" >"$console_log"
    (
        umask 077
        set -C
        : >"$console_done"
    )
) &
console_pid=$!

bounded_counter=0
bounded_run() {
    bounded_name=$1
    bounded_blocks=$2
    shift 2
    bounded_counter=$((bounded_counter + 1))
    bounded_fifo=$run_directory/bounded.$bounded_counter.fifo
    bounded_log=$run_directory/bounded.$bounded_counter.log
    mkfifo -m 0600 "$bounded_fifo"
    {
        dd bs=65536 count="$bounded_blocks" iflag=fullblock 2>/dev/null
        cat >/dev/null
    } <"$bounded_fifo" >"$bounded_log" &
    bounded_capture_pid=$!
    set +e
    "$@" >"$bounded_fifo" 2>&1
    bounded_command_status=$?
    wait "$bounded_capture_pid"
    bounded_capture_status=$?
    set -e
    rm -f -- "$bounded_fifo"
    if [ "$bounded_capture_status" -ne 0 ]; then
        printf 'bounded output collector failed for %s\n' "$bounded_name" >&2
        return 125
    fi
    if [ "$bounded_command_status" -ne 0 ]; then
        printf '%s failed with status %s; bounded tail follows:\n' \
            "$bounded_name" "$bounded_command_status" >&2
        tail -c 65536 "$bounded_log" >&2
    fi
    return "$bounded_command_status"
}

guest_ssh_raw() {
    timeout --signal=TERM --kill-after=10s 1800s ssh \
        -F /dev/null -i "$ssh_key" \
        -o Port=22222 -o BatchMode=yes -o ConnectTimeout=5 \
        -o CanonicalizeHostname=no -o ClearAllForwardings=yes \
        -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
        -o ForwardAgent=no -o PermitLocalCommand=no \
        -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
        -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o KbdInteractiveAuthentication=no -o LogLevel=ERROR \
        -o PasswordAuthentication=no -o ProxyCommand=none -o ProxyJump=none \
        -o RequestTTY=no -o StrictHostKeyChecking=yes -o Tunnel=no \
        -o UserKnownHostsFile="$known_hosts" volparossa@127.0.0.1 "$@"
}

guest_scp_to_raw() {
    timeout --signal=TERM --kill-after=10s 300s scp \
        -F /dev/null -i "$ssh_key" \
        -o Port=22222 -o BatchMode=yes -o ConnectTimeout=5 \
        -o CanonicalizeHostname=no -o ClearAllForwardings=yes \
        -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
        -o ForwardAgent=no -o PermitLocalCommand=no \
        -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
        -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o KbdInteractiveAuthentication=no -o LogLevel=ERROR \
        -o PasswordAuthentication=no -o ProxyCommand=none -o ProxyJump=none \
        -o RequestTTY=no -o StrictHostKeyChecking=yes -o Tunnel=no \
        -o UserKnownHostsFile="$known_hosts" \
        "$1" "volparossa@127.0.0.1:$2"
}

guest_scp_from_raw() {
    timeout --signal=TERM --kill-after=10s 300s scp \
        -F /dev/null -i "$ssh_key" \
        -o Port=22222 -o BatchMode=yes -o ConnectTimeout=5 \
        -o CanonicalizeHostname=no -o ClearAllForwardings=yes \
        -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
        -o ForwardAgent=no -o PermitLocalCommand=no \
        -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
        -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o KbdInteractiveAuthentication=no -o LogLevel=ERROR \
        -o PasswordAuthentication=no -o ProxyCommand=none -o ProxyJump=none \
        -o RequestTTY=no -o StrictHostKeyChecking=yes -o Tunnel=no \
        -o UserKnownHostsFile="$known_hosts" \
        "volparossa@127.0.0.1:$1" "$2"
}

wait_for_ssh() {
    ssh_wait_count=0
    while [ "$ssh_wait_count" -lt 180 ]; do
        if [ -f "$qemu_control/status" ] || [ -L "$qemu_control/status" ]; then
            return 1
        fi
        if timeout --signal=TERM --kill-after=2s 10s ssh \
            -F /dev/null -i "$ssh_key" \
            -o Port=22222 -o BatchMode=yes -o ConnectTimeout=5 \
            -o CanonicalizeHostname=no -o ClearAllForwardings=yes \
            -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
            -o ForwardAgent=no -o PermitLocalCommand=no \
            -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
            -o IdentitiesOnly=yes -o IdentityAgent=none \
            -o KbdInteractiveAuthentication=no -o LogLevel=ERROR \
            -o PasswordAuthentication=no -o ProxyCommand=none -o ProxyJump=none \
            -o RequestTTY=no -o StrictHostKeyChecking=yes -o Tunnel=no \
            -o UserKnownHostsFile="$known_hosts" \
            volparossa@127.0.0.1 true >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ssh_wait_count=$((ssh_wait_count + 1))
    done
    return 1
}

start_vm() {
    vm_phase=$1
    vm_network=$2
    verify_kvm_contract \
        || failed "the KVM authority changed before $vm_phase"
    if ss -H -ltn 2>/dev/null | awk '$4 ~ /:22222$/ { found=1 } END { exit !found }'; then
        failed "the loopback SSH port is occupied before $vm_phase"
    fi
    qemu_control=$run_directory/qemu-$vm_phase
    install -d -m 0700 -- "$qemu_control"
    case $vm_network in
        provisioning) qemu_netdev='user,id=net0,hostfwd=tcp:127.0.0.1:22222-:22' ;;
        restricted) qemu_netdev='user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:22222-:22' ;;
        *) failed 'internal VM network phase is invalid' ;;
    esac
    # Retained main run 33114535362 proved that the pinned legacy-BIOS GRUB
    # requested a guest reset before its first kernel-loading message in a
    # q35 -nodefaults configuration without VGA. That does not prove causality;
    # keep the display headless while testing the smallest remaining hypothesis:
    # one fixed VGA device for the load_video path.
    python3 "$qemu_supervisor" \
        --grace-seconds 5 --term-seconds 5 --kill-seconds 5 \
        --ack-timeout-seconds 30 --qmp-stdio --qmp-timeout-seconds 10 \
        "$qemu_control" -- \
        "$qemu_system" \
        -name "volparossa-helper-boundary-$vm_phase" \
        -no-user-config -nodefaults \
        -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
        -device VGA,id=video0,bus=pcie.0,addr=0x1 \
        -drive "if=virtio,format=qcow2,file=$overlay" \
        -drive "if=virtio,format=raw,readonly=on,file=$seed" \
        -device virtio-rng-pci -device virtio-net-pci,netdev=net0 \
        -netdev "$qemu_netdev" -display none -S -qmp stdio \
        -serial "file:$console_fifo" -no-reboot \
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
        9>&- </dev/null >/dev/null 2>&1 &
    qemu_supervisor_pid=$!
    image_was_used=yes
    set +e
    wait_for_supervisor_ready 15
    supervisor_ready_status=$?
    set -e
    case $supervisor_ready_status in
        0) ;;
        2)
            qemu_failure_status=$qemu_control/status
            qemu_failure_qmp=$qemu_control/qmp
            qemu_failure_stderr=$qemu_control/stderr
            if ! reap_qemu no; then
                printf '%s\n' 'the failed QEMU lifecycle could not be reaped cleanly' >&2
            fi
            if ! publish_qemu_failure_diagnostics \
                "$vm_phase" "$qemu_failure_status" "$qemu_failure_qmp" \
                "$qemu_failure_stderr"; then
                printf '%s\n' 'bounded QEMU failure diagnostics could not be published' >&2
            fi
            failed "the QEMU supervisor failed before ready for $vm_phase"
            ;;
        3)
            validate_supervisor_record "$qemu_control/ready" ready \
                || failed "the QEMU supervisor ready record is invalid for $vm_phase"
            qemu_failure_status=$qemu_control/status
            qemu_failure_qmp=$qemu_control/qmp
            qemu_failure_stderr=$qemu_control/stderr
            if ! reap_qemu no; then
                printf '%s\n' 'the exited QEMU lifecycle could not be reaped cleanly' >&2
            fi
            if ! publish_qemu_failure_diagnostics \
                "$vm_phase" "$qemu_failure_status" "$qemu_failure_qmp" \
                "$qemu_failure_stderr"; then
                printf '%s\n' 'bounded QEMU failure diagnostics could not be published' >&2
            fi
            failed "QEMU exited after supervisor readiness for $vm_phase"
            ;;
        *) failed "the QEMU supervisor did not become ready for $vm_phase" ;;
    esac
    validate_supervisor_record "$qemu_control/ready" ready \
        || failed "the QEMU supervisor ready record is invalid for $vm_phase"
    if ! wait_for_ssh; then
        qemu_failed_before_ssh=no
        if [ -f "$qemu_control/status" ] && [ ! -L "$qemu_control/status" ]; then
            qemu_failed_before_ssh=yes
        fi
        qemu_failure_status=$qemu_control/status
        qemu_failure_qmp=$qemu_control/qmp
        qemu_failure_stderr=$qemu_control/stderr
        if [ "$qemu_failed_before_ssh" = no ]; then
            atomic_empty_file "$qemu_control/stop" \
                || failed "the stalled QEMU stop request failed for $vm_phase"
        fi
        if ! reap_qemu no; then
            printf '%s\n' 'the pre-SSH QEMU lifecycle could not be reaped cleanly' >&2
        fi
        if ! publish_qemu_failure_diagnostics \
            "$vm_phase" "$qemu_failure_status" "$qemu_failure_qmp" \
            "$qemu_failure_stderr"; then
            printf '%s\n' 'bounded QEMU failure diagnostics could not be published' >&2
        fi
        if [ "$qemu_failed_before_ssh" = yes ]; then
            failed "QEMU exited after readiness before pinned guest SSH for $vm_phase"
        fi
        failed "the exact pinned guest did not expose SSH for $vm_phase"
    fi
}

start_vm provisioning provisioning
bounded_run cloud-init 32 guest_ssh_raw sudo -n cloud-init status --wait \
    || failed 'cloud-init did not complete successfully'
bounded_run copy-setup 2 guest_scp_to_raw "$guest_setup" /home/volparossa/guest-setup.sh \
    || failed 'the fixed guest setup script could not be copied'
bounded_run copy-source 2 guest_scp_to_raw "$source_archive" /home/volparossa/source.tar.gz \
    || failed 'the bounded source archive could not be copied'
bounded_run copy-proof 2 guest_scp_to_raw "$guest_proof" /home/volparossa/guest-proof.sh \
    || failed 'the fixed guest proof script could not be copied'
bounded_run guest-permissions 2 guest_ssh_raw chmod 0700 \
    /home/volparossa/guest-setup.sh /home/volparossa/guest-proof.sh \
    || failed 'the fixed guest scripts could not be protected'
bounded_run guest-provisioning 512 guest_ssh_raw \
    /home/volparossa/guest-setup.sh "$expected_commit" "$source_archive_sha256" \
    || failed 'the bounded guest provisioning or locked dependency fetch failed'
guest_ssh_raw sudo -n systemctl poweroff >/dev/null 2>&1 || true
reap_qemu yes || failed 'the provisioning VM did not power off cleanly'
bounded_run kvm-uevent-settle 1 udevadm settle --timeout=10 \
    || failed 'the host KVM change event did not settle after provisioning'

start_vm proof restricted
bounded_run proof-cloud-init 32 guest_ssh_raw sudo -n cloud-init status --wait \
    || failed 'cloud-init did not settle in the restricted proof boot'
wait_for_guest_systemd() {
    guest_system_state=$(guest_ssh_raw sudo -n systemctl is-system-running --wait \
        2>/dev/null || true)
    case $guest_system_state in
        running|degraded) return 0 ;;
        *)
            printf 'restricted proof guest system state is not ready: %s\n' \
                "$guest_system_state" >&2
            return 1
            ;;
    esac
}
bounded_run proof-systemd-ready 2 wait_for_guest_systemd \
    || failed 'systemd did not reach running or degraded in the restricted proof boot'
if bounded_run offline-proof 512 guest_ssh_raw \
    /home/volparossa/guest-proof.sh "$expected_commit"; then
    guest_status=0
else
    guest_status=$?
fi
if ! bounded_run retrieve-proof-diagnostics 32 guest_scp_from_raw \
    /home/volparossa/helper-boundary-proof.stderr.log "$retrieved_stderr"; then
    if [ "$guest_status" -eq 0 ]; then
        failed 'the successful proof did not expose bounded diagnostics'
    fi
    printf 'guest proof command exited before bounded proof diagnostics; status=%s\n' \
        "$guest_status" >"$retrieved_stderr"
fi
[ "$(stat -Lc '%s' "$retrieved_stderr")" -le 1048576 ] \
    || failed 'the retrieved proof diagnostics exceed 1 MiB'
install -m 0600 -- "$retrieved_stderr" "$proof_stderr_log"
if [ "$guest_status" -ne 0 ]; then
    if [ "$proof_mode" = non-retained-pr-smoke ]; then
        if non_retained_blocked_status_is_exact "$guest_status" \
            && report_non_retained_blocked_category "$proof_stderr_log"; then
            :
        elif report_non_retained_boundary_validator_failure_category \
            "$proof_stderr_log"; then
            :
        elif report_non_retained_proof_failure_reason "$proof_stderr_log"; then
            if [ "$non_retained_failure_reason" = worker-launch-status ]; then
                report_non_retained_worker_launch_diagnostic \
                    "$proof_stderr_log" || true
            elif [ "$non_retained_failure_reason" = worker-confinement ]; then
                report_non_retained_worker_confinement_diagnostic \
                    "$proof_stderr_log" || true
            elif [ "$non_retained_failure_reason" = production-launch-status ]; then
                report_non_retained_production_launch_diagnostic \
                    "$proof_stderr_log" || true
            fi
        elif report_non_retained_restart_launch_failure_category \
            "$proof_stderr_log"; then
            if [ "$non_retained_restart_failure_category" = launch-envelope ]; then
                report_non_retained_restart_launch_diagnostic \
                    "$proof_stderr_log" || true
            elif [ "$non_retained_restart_failure_category" = crash-record ]; then
                report_non_retained_restart_crash_record_diagnostic \
                    "$proof_stderr_log" || true
            fi
        elif report_non_retained_may_own_launch_failure_category \
            "$proof_stderr_log"; then
            :
        else
            printf '%s\n' \
                'non-retained helper-boundary PR smoke failure category: unclassified' >&2
            report_non_retained_driver_phase "$proof_stderr_log" || true
            report_non_retained_final_checkpoint "$proof_stderr_log" || true
        fi
    fi
    failed "the guest helper-boundary proof exited with status $guest_status"
fi
bounded_run retrieve-report 2 guest_scp_from_raw \
    /home/volparossa/helper-boundary-evidence-v1.json "$retrieved_report" \
    || failed 'the canonical helper-boundary report could not be retrieved'
bounded_run retrieve-restart-report 2 guest_scp_from_raw \
    /home/volparossa/helper-restart-exact-present-evidence-v1.json \
    "$retrieved_restart_report" \
    || failed 'the canonical restart report could not be retrieved'
bounded_run retrieve-may-own-report 2 guest_scp_from_raw \
    /home/volparossa/helper-restart-may-own-custody-relay-evidence-v1.json \
    "$retrieved_may_own_report" \
    || failed 'the canonical MayOwn Relay report could not be retrieved'

guest_ssh_raw sudo -n systemctl poweroff >/dev/null 2>&1 || true
reap_qemu yes || failed 'the restricted proof VM did not power off cleanly'
bounded_run proof-kvm-uevent-settle 1 udevadm settle --timeout=10 \
    || failed 'the host KVM change event did not settle after the proof'
verify_kvm_contract \
    || failed 'the KVM authority changed after the restricted proof'
settle_console || failed 'the bounded console log did not settle'
if [ "$proof_mode" = retained-main ]; then
    publish_console || failed 'the bounded console log could not be published atomically'
fi

post_image_sha512=$(sha512sum "$image_path" | awk '{print $1}') \
    || failed 'the reviewed base image cannot be rehashed after VM use'
[ "$post_image_sha512" = "$image_sha512" ] \
    || failed 'the reviewed base image changed during VM use'

validator_stdout=$run_directory/validator.stdout
validator_stderr=$run_directory/validator.stderr
set +e
"$report_validator" "$retrieved_report" >"$validator_stdout" 2>"$validator_stderr"
validator_status=$?
set -e
[ "$validator_status" -eq 0 ] || failed 'the retrieved report failed local validation'
if [ -s "$validator_stdout" ] || [ -s "$validator_stderr" ]; then
    failed 'the local report validator was not silent'
fi
jq -e --arg commit "$expected_commit" \
    '.overall == "PASS" and .observed_source.commit_sha == $commit' \
    "$retrieved_report" >/dev/null || failed 'the report is not a PASS for the expected commit'
retrieved_report_size=$(stat -Lc '%s' "$retrieved_report")
if [ "$retrieved_report_size" -lt 1 ] || [ "$retrieved_report_size" -gt 32768 ]; then
    failed 'the retrieved report size is outside the evidence bound'
fi
restart_validator_stdout=$run_directory/restart-validator.stdout
restart_validator_stderr=$run_directory/restart-validator.stderr
set +e
"$restart_report_validator" "$retrieved_restart_report" \
    >"$restart_validator_stdout" 2>"$restart_validator_stderr"
restart_validator_status=$?
set -e
[ "$restart_validator_status" -eq 0 ] \
    || failed 'the retrieved restart report failed local validation'
if [ -s "$restart_validator_stdout" ] || [ -s "$restart_validator_stderr" ]; then
    failed 'the local restart report validator was not silent'
fi
jq -e --arg commit "$expected_commit" \
    '.overall == "PASS" and .observed_source.commit_sha == $commit' \
    "$retrieved_restart_report" >/dev/null \
    || failed 'the restart report is not a PASS for the expected commit'
may_own_validator_stdout=$run_directory/may-own-validator.stdout
may_own_validator_stderr=$run_directory/may-own-validator.stderr
set +e
"$may_own_report_validator" "$retrieved_may_own_report" \
    >"$may_own_validator_stdout" 2>"$may_own_validator_stderr"
may_own_validator_status=$?
set -e
[ "$may_own_validator_status" -eq 0 ] \
    || failed 'the retrieved MayOwn Relay report failed local validation'
if [ -s "$may_own_validator_stdout" ] || [ -s "$may_own_validator_stderr" ]; then
    failed 'the local MayOwn Relay report validator was not silent'
fi
jq -e --arg commit "$expected_commit" \
    '.overall == "PASS" and .observed_source.commit_sha == $commit' \
    "$retrieved_may_own_report" >/dev/null \
    || failed 'the MayOwn Relay report is not a PASS for the expected commit'

late_head=$(git -C "$repository_directory" rev-parse --verify 'HEAD^{commit}') \
    || failed 'the late source HEAD fence failed'
late_branch=$(git -C "$repository_directory" symbolic-ref --quiet --short HEAD) \
    || failed 'the late source branch fence failed'
late_status=$(GIT_OPTIONAL_LOCKS=0 git -C "$repository_directory" \
    status --porcelain=v1 --untracked-files=normal --ignore-submodules=none) \
    || failed 'the late source clean fence failed'
if [ "$late_head" != "$expected_commit" ] \
    || [ "$late_branch" != "$expected_source_branch" ] \
    || [ -n "$late_status" ]; then
    failed 'the source changed while the VM proof ran'
fi

report_hash=$(sha256sum "$retrieved_report" | awk '{print $1}') \
    || failed 'the retained report hash could not be calculated'
report_hash_file=$run_directory/helper-boundary-evidence-v1.json.sha256
printf '%s  helper-boundary-evidence-v1.json\n' "$report_hash" >"$report_hash_file"
restart_report_hash=$(sha256sum "$retrieved_restart_report" | awk '{print $1}') \
    || failed 'the retained restart report hash could not be calculated'
restart_report_hash_file=$run_directory/helper-restart-exact-present-evidence-v1.json.sha256
printf '%s  helper-restart-exact-present-evidence-v1.json\n' \
    "$restart_report_hash" >"$restart_report_hash_file"
may_own_report_hash=$(sha256sum "$retrieved_may_own_report" | awk '{print $1}') \
    || failed 'the retained MayOwn Relay report hash could not be calculated'
may_own_report_hash_file=$run_directory/helper-restart-may-own-custody-relay-evidence-v1.json.sha256
printf '%s  helper-restart-may-own-custody-relay-evidence-v1.json\n' \
    "$may_own_report_hash" >"$may_own_report_hash_file"
successful_environment=$run_directory/vm-environment-v1.json
jq -S -c -n \
    --arg commit "$expected_commit" \
    --arg image_sha512 "$image_sha512" \
    --arg report_sha256 "$report_hash" \
    --arg release_build 20260826-2582 \
    '{expected_commit: $commit,
      guest: {architecture: "amd64", cargo_version: "1.85.0",
        debian_version: "13", rustc_version: "1.85.0", systemd_version: 257,
        virtualization: "kvm"},
      image_release_build: $release_build,
      image_sha512: $image_sha512,
      proof_network: {external_https: "denied", mode: "qemu-user-restrict-on"},
      report_kind: "volparossa-helper-boundary-vm-environment",
      report_sha256: $report_sha256,
      schema_version: 1,
      status: "PASS"}' >"$successful_environment"
successful_restart_environment=$run_directory/helper-restart-vm-environment-v1.json
jq -S -c -n \
    --arg commit "$expected_commit" \
    --arg image_sha512 "$image_sha512" \
    --arg report_sha256 "$restart_report_hash" \
    --arg release_build 20260826-2582 \
    '{expected_commit: $commit,
      guest: {architecture: "amd64", cargo_version: "1.85.0",
        debian_version: "13", rustc_version: "1.85.0", systemd_version: 257,
        virtualization: "kvm"},
      image_release_build: $release_build,
      image_sha512: $image_sha512,
      proof_network: {external_https: "denied", mode: "qemu-user-restrict-on"},
      report_kind: "volparossa-helper-restart-vm-environment",
      report_sha256: $report_sha256,
      schema_version: 1,
      status: "PASS"}' >"$successful_restart_environment"
successful_may_own_environment=$run_directory/helper-restart-may-own-custody-relay-vm-environment-v1.json
jq -S -c -n \
    --arg commit "$expected_commit" \
    --arg image_sha512 "$image_sha512" \
    --arg report_sha256 "$may_own_report_hash" \
    --arg release_build 20260826-2582 \
    '{expected_commit: $commit,
      guest: {architecture: "amd64", cargo_version: "1.85.0",
        debian_version: "13", rustc_version: "1.85.0", systemd_version: 257,
        virtualization: "kvm"},
      image_release_build: $release_build,
      image_sha512: $image_sha512,
      proof_network: {external_https: "denied", mode: "qemu-user-restrict-on"},
      report_kind: "volparossa-helper-restart-may-own-custody-relay-vm-environment",
      report_sha256: $report_sha256,
      schema_version: 1,
      status: "PASS"}' >"$successful_may_own_environment"

environment_validator_stdout=$run_directory/environment-validator.stdout
environment_validator_stderr=$run_directory/environment-validator.stderr
set +e
"$environment_validator" "$successful_environment" "$retrieved_report" \
    "$expected_commit" "$image_sha512" \
    >"$environment_validator_stdout" 2>"$environment_validator_stderr"
environment_validator_status=$?
set -e
[ "$environment_validator_status" -eq 0 ] \
    || failed 'the exact VM-environment record failed local validation'
if [ -s "$environment_validator_stdout" ] || [ -s "$environment_validator_stderr" ]; then
    failed 'the local VM-environment validator was not silent'
fi
restart_environment_validator_stdout=$run_directory/restart-environment-validator.stdout
restart_environment_validator_stderr=$run_directory/restart-environment-validator.stderr
set +e
"$restart_environment_validator" "$successful_restart_environment" \
    "$retrieved_restart_report" "$expected_commit" "$image_sha512" \
    >"$restart_environment_validator_stdout" \
    2>"$restart_environment_validator_stderr"
restart_environment_validator_status=$?
set -e
[ "$restart_environment_validator_status" -eq 0 ] \
    || failed 'the restart VM-environment record failed local validation'
if [ -s "$restart_environment_validator_stdout" ] \
    || [ -s "$restart_environment_validator_stderr" ]; then
    failed 'the restart VM-environment validator was not silent'
fi
may_own_environment_validator_stdout=$run_directory/may-own-environment-validator.stdout
may_own_environment_validator_stderr=$run_directory/may-own-environment-validator.stderr
set +e
"$may_own_environment_validator" "$successful_may_own_environment" \
    "$retrieved_may_own_report" "$expected_commit" "$image_sha512" \
    >"$may_own_environment_validator_stdout" \
    2>"$may_own_environment_validator_stderr"
may_own_environment_validator_status=$?
set -e
[ "$may_own_environment_validator_status" -eq 0 ] \
    || failed 'the MayOwn Relay VM-environment record failed local validation'
if [ -s "$may_own_environment_validator_stdout" ] \
    || [ -s "$may_own_environment_validator_stderr" ]; then
    failed 'the MayOwn Relay VM-environment validator was not silent'
fi

if [ "$proof_mode" = retained-main ]; then
    install -m 0600 -- "$retrieved_report" \
        "$output_directory/helper-boundary-evidence-v1.json"
    install -m 0600 -- "$report_hash_file" \
        "$output_directory/helper-boundary-evidence-v1.json.sha256"
    install -m 0600 -- "$successful_environment" "$environment_report"
    install -m 0600 -- "$retrieved_restart_report" \
        "$output_directory/helper-restart-exact-present-evidence-v1.json"
    install -m 0600 -- "$restart_report_hash_file" \
        "$output_directory/helper-restart-exact-present-evidence-v1.json.sha256"
    install -m 0600 -- "$successful_restart_environment" \
        "$output_directory/helper-restart-vm-environment-v1.json"
    install -m 0600 -- "$retrieved_may_own_report" \
        "$output_directory/helper-restart-may-own-custody-relay-evidence-v1.json"
    install -m 0600 -- "$may_own_report_hash_file" \
        "$output_directory/helper-restart-may-own-custody-relay-evidence-v1.json.sha256"
    install -m 0600 -- "$successful_may_own_environment" \
        "$output_directory/helper-restart-may-own-custody-relay-vm-environment-v1.json"
    printf '%s\n' \
        'PASS: retained canonical helper-boundary evidence from the disposable Debian 13 KVM.' >&2
else
    for non_retained_output in "$proof_stderr_log" "$environment_report"; do
        if [ ! -f "$non_retained_output" ] || [ -L "$non_retained_output" ] \
            || [ "$(stat -Lc '%h:%u:%a' "$non_retained_output" 2>/dev/null || true)" \
                != "1:$(id -u):600" ]; then
            failed 'a non-retained smoke output cannot be discarded safely'
        fi
        rm -f -- "$non_retained_output" \
            || failed 'a non-retained smoke output could not be discarded'
    done
    if find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit \
        | grep -q .; then
        failed 'the non-retained PR smoke output directory is not empty'
    fi
    printf '%s\n' \
        'PASS: non-retained helper-boundary PR smoke completed in the disposable Debian 13 KVM.' >&2
fi
