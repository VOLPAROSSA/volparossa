#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Stage sequential live worker-identity and production IPC proofs in disposable systemd services.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode=preview
approval=no
seen_mode=no
seen_approval=no

usage() {
    printf '%s\n' \
        'usage: tests/helper/require-live-worker-identity-proof.sh [--preview|--execute] [--yes]' \
        '' \
        'Preview is the non-writing default. Execution requires --execute --yes as root' \
        'inside a disposable Debian 13 amd64 virtual machine running systemd.'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA live worker-identity proof plan:' \
        '  require a disposable Debian 13 amd64 VM, root, and the exact systemd v257 manager;' \
        '  bookend one unchanged clean Git revision and exact helper, probe, hook,' \
        '    restart observer/launcher, and debugger artifact hashes;' \
        '  copy the already-built real helper into one validated root-only temporary stage;' \
        '  create synthetic, collision-free agent/worker/group records only inside that stage;' \
        '  bind account files plus the system bus socket read-only in four sequential transient services;' \
        '  let PID 1 resolve only host-present root/root unit credentials before those binds;' \
        '  use exact /usr/bin/setpriv to install the staged primary and singleton agent GID;' \
        '  bind the canonical systemd notify socket read-only inside both private /run trees;' \
        '  pin its D-Bus system address to that verified socket inside the private /run;' \
        '  run with PrivateNetwork=yes, a private temporary /run, and no host account changes;' \
        '  require the host /run/volparossa path absent before and after every private unit run;' \
        '  set NotifyAccess=main, FileDescriptorStoreMax=128, and' \
        '    FileDescriptorStorePreserve=yes on that transient service;' \
        '  start its fixed credential trampoline as blocking Type=exec, then require helper exec;' \
        '  retain diagnostic success with RemainAfterExit=yes and failures with CollectMode=inactive;' \
        '  forbid ignore-failure, aggressive collection, and asynchronous or waiting client modes;' \
        '  grant exactly CAP_KILL, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SETGID, CAP_SETPCAP,' \
        '    CAP_SETUID, and CAP_SYS_ADMIN to the helper parent;' \
        '  bound both large build-artifact staging copies at 128 MiB, then cap' \
        '    the proof process and every transient-unit file write at 1 MiB;' \
        '  cap the diagnostic worker runtime at 45 seconds;' \
        '  cap the production runtime at three minutes;' \
        '  cap the two-crash MayOwn service runtime at six minutes;' \
        '  discard production runtime stdout and stderr through exact systemd null streams;' \
        '  require its kernel supplementary-group vector to contain only the staged agent GID;' \
        '  invoke only --internal-worker-v3-live-proof and require its exact two success records;' \
        '  after main exit require exactly two descriptors in the systemd descriptor store;' \
        '  bind normal retirement to the exact JSON InvocationID returned for that run;' \
        '  recover tentative ownership only from its exact marker and current nonzero manager ID;' \
        '  stop, clean only its fdstore, and collect that exact first invocation;' \
        '  only after the unit is not-found, reuse its random name with a new exact marker and ID;' \
        '  run the argumentless production helper and fixed IPC probe inside the confined unit;' \
        '  use one fixed no-argument launcher and FIFO barriers to hold the ExactPresent successor' \
        '    plus all three MayOwn invocations before same-MainPID helper exec;' \
        '  release each MayOwn launcher only after exact PID, new InvocationID, NRestarts,' \
        '    ControlPID, ControlGroup/ControlGroupId, fdstore, cgroup shape, GDB exec-catch,' \
        '    pending breakpoint, and an outside-cgroup namespace observer are ready;' \
        '  use GDB inferior kill plus quit 0 for exactly three SIGKILL crash boundaries;' \
        '  freeze only each non-empty, exact single-MainPID MayOwn cgroup at its two crash frames,' \
        '    then thaw or observe removal before PID 1 may launch the FIFO-gated successor;' \
        '  require stable Bind identity, bounded malformed-frame and wire-shape rejection,' \
        '    exact peer PID/UID/GID rejection, stable socket inode/token metadata, and zero fdstore;' \
        '  create one fixed dummy underlay only inside the production PrivateNetwork namespace;' \
        '  hold sequential singleton Client and Exit leases, then one simultaneous Relay pair at fixed FIFO READY barriers;' \
        '  externally prove every child PID, executable, identity, distinct netns, and live WireGuard;' \
        '  drive bounded ICMPv6 over both pair legs ::1/::2 and ::3/::4, then require exact Commit;' \
        '  require byte-identical Commit retries, exact fixture cleanup, Destroy, and worker retirement;' \
        '  preserve one MainPID and InvocationID throughout those checks, then require clean' \
        '    SIGTERM, an unchanged journal, one held-then-unlocked lock inode, and removed socket;' \
        '  retire each exact unit, stop all observers/keepers/debuggers, thaw any crash freezer,' \
        '    collect the units, and remove the validated temporary stage;' \
        '  compare privacy-safe before/after host account, resolver, mount, firewall, WireGuard,' \
        '    and network digests;' \
        '  validate exactly three bounded canonical evidence-v1 reports before publishing only those JSON values.' \
        'This stages the helper identity and production IPC boundary. It creates no host account,' \
        'host link, route, firewall rule, WireGuard device, DNS change, sysctl change, or production VPN datapath.' \
        'One dummy underlay and ephemeral Client, Exit, and simultaneous Relay-pair WireGuard leases exist only in private namespaces.' \
        'It is not package-install, general restart recovery, CleanupOwned, production datapath, or A01-A15 evidence.'
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
    if [ "$approval" = yes ]; then
        printf '%s\n' '--yes is valid only with --execute' >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no file, account, service, or network state was changed.'
    exit 0
fi

if [ "$approval" != yes ]; then
    print_plan >&2
    printf '%s\n' 'Execution requires --yes after reviewing the exact plan.' >&2
    exit 64
fi

print_plan >&2

blocked() {
    printf 'BLOCKED: %s\n' "$1" >&2
    exit 77
}

failed() {
    printf 'live worker-identity proof failed: %s\n' "$1" >&2
    exit 1
}

boundary_validator_failure_stage_is_safe() {
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

report_boundary_validator_failure_diagnostic() {
    [ "$#" -eq 4 ] || return 1
    boundary_validator_report=$1
    boundary_validator_status=$2
    boundary_validator_stdout=$3
    boundary_validator_stderr=$4
    boundary_validator_stage=

    if ! vp_capture_file_is_safe "$boundary_validator_report" \
        || ! vp_capture_file_is_safe "$boundary_validator_stdout" \
        || ! vp_capture_file_is_safe "$boundary_validator_stderr"; then
        boundary_validator_stage=capture-unsafe
    else
        case $boundary_validator_status in
            0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
            *) boundary_validator_stage='status-invalid' ;;
        esac
        if [ -z "$boundary_validator_stage" ] \
            && [ -s "$boundary_validator_stdout" ]; then
            boundary_validator_stage=stdout-nonempty
        elif [ -z "$boundary_validator_stage" ] \
            && [ "$boundary_validator_status" -eq 0 ]; then
            boundary_validator_stage='status-zero'
        elif [ -z "$boundary_validator_stage" ] \
            && [ ! -s "$boundary_validator_stderr" ]; then
            boundary_validator_stage=stderr-empty
        fi
    fi

    if [ -z "$boundary_validator_stage" ]; then
        boundary_validator_report_size=$(stat -Lc '%s' \
            "$boundary_validator_report" 2>/dev/null || true)
        case $boundary_validator_report_size in
            ''|*[!0-9]*) boundary_validator_stage=input-size ;;
            *)
                if [ "$boundary_validator_report_size" -eq 0 ] \
                    || [ "$boundary_validator_report_size" -gt 32768 ]; then
                    boundary_validator_stage=input-size
                fi
                ;;
        esac
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e -s 'length == 1' "$boundary_validator_report" \
            >/dev/null 2>&1; then
        boundary_validator_stage=json-value
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -S -c . "$boundary_validator_report" 2>/dev/null \
            | cmp -s - "$boundary_validator_report"; then
        boundary_validator_stage=canonical-encoding
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            type == "object"
            and keys == ([
                "checks", "enumerated_host_state", "environment",
                "finished_at", "generated_at", "invocation_ids",
                "observed_artifact_hashes", "observed_source", "overall",
                "production", "report_kind", "retirement", "schema_version",
                "scope", "started_at", "worker"
            ] | sort)
            and .schema_version == 1
            and .report_kind == "volparossa-helper-boundary-evidence"
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=fixed-contract
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def exact_keys($expected):
                type == "object" and keys == ($expected | sort);
            def valid_sha256:
                type == "string"
                and test("^[0-9a-f]{64}$")
                and (test("^0+$") | not);
            def valid_source_revision:
                type == "string"
                and test("^([0-9a-f]{40}|[0-9a-f]{64})$")
                and (test("^0+$") | not);
            .observed_source
                | exact_keys(["commit_sha", "worktree_clean"])
                and (.commit_sha | valid_source_revision)
                and .worktree_clean == true
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=source-artifacts
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def exact_keys($expected):
                type == "object" and keys == ($expected | sort);
            def valid_sha256:
                type == "string"
                and test("^[0-9a-f]{64}$")
                and (test("^0+$") | not);
            .observed_artifact_hashes
                | exact_keys([
                    "production_ipc_probe_sha256",
                    "production_ipc_unit_hook_sha256",
                    "volparossa_helper_sha256"
                  ])
                and all(.[]; valid_sha256)
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=source-artifacts
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def exact_keys($expected):
                type == "object" and keys == ($expected | sort);
            def valid_kernel_release:
                type == "string"
                and length >= 1
                and length <= 128
                and test("^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$");
            .environment
                | exact_keys([
                    "debian_version", "dpkg_architecture", "kernel_release",
                    "machine", "systemd_version", "virtualization"
                  ])
                and .debian_version == "13"
                and .dpkg_architecture == "amd64"
                and (.kernel_release | valid_kernel_release)
                and .machine == "x86_64"
                and .systemd_version == 257
                and .virtualization == "vm"
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=environment
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def utc_epoch:
                if type == "string"
                    and test("^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
                then . as $timestamp
                    | try (fromdateiso8601 as $epoch
                        | if ($epoch | todateiso8601) == $timestamp
                          then $epoch
                          else null
                          end)
                      catch null
                else null
                end;
            (.started_at | utc_epoch) != null
            and (.finished_at | utc_epoch) != null
            and (.generated_at | utc_epoch) != null
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=clock-format
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def utc_epoch:
                . as $timestamp
                | fromdateiso8601 as $epoch
                | if ($epoch | todateiso8601) == $timestamp
                  then $epoch
                  else null
                  end;
            (.started_at | utc_epoch) as $started
            | (.finished_at | utc_epoch) as $finished
            | (.generated_at | utc_epoch) as $generated
            | $started <= $finished and $finished <= $generated
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=clock-order
    fi
    if [ -z "$boundary_validator_stage" ]; then
        if ! jq -e '
            def valid_invocation_id:
                type == "string"
                and test("^[0-9a-f]{32}$")
                and (test("^0+$") | not);
            .invocation_ids
                | type == "array"
                and length == 2
                and all(.[]; valid_invocation_id)
                and .[0] != .[1]
        ' "$boundary_validator_report" >/dev/null 2>&1; then
            boundary_validator_stage=invocations
        fi
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def exact_keys($expected):
                type == "object" and keys == ($expected | sort);
            (.worker
                | exact_keys([
                    "fdstore_before_retirement",
                    "unit_load_state_after_retirement"
                  ])
                and .fdstore_before_retirement == 2
                and .unit_load_state_after_retirement == "not-found")
            and (.production
                | exact_keys([
                    "argumentless", "fdstore_active_cycle_counts",
                    "fdstore_exact_identity_bound", "fdstore_idle_observation",
                    "fdstore_settled_cycle_counts",
                    "unit_load_state_after_retirement"
                  ])
                and .argumentless == true
                and .fdstore_active_cycle_counts == [2, 2, 2]
                and .fdstore_exact_identity_bound == true
                and .fdstore_idle_observation == 0
                and .fdstore_settled_cycle_counts == [0, 0, 0]
                and .unit_load_state_after_retirement == "not-found")
            and (.retirement
                | exact_keys([
                    "journal_settled_absent", "lock_released", "socket_absent"
                  ])
                and .journal_settled_absent == true
                and .lock_released == true
                and .socket_absent == true)
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=lifecycle
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def exact_keys($expected):
                type == "object" and keys == ($expected | sort);
            def valid_sha256:
                type == "string"
                and test("^[0-9a-f]{64}$")
                and (test("^0+$") | not);
            def expected_host_state_records:
                [
                  "production_runtime_path", "accounts", "namespaces",
                  "mounts", "resolver", "sysctls", "links", "addresses",
                  "routes", "rules", "nexthops", "qdiscs", "nftables",
                  "wireguard", "legacy_ipv4_firewall",
                  "legacy_ipv6_firewall"
                ];
            .enumerated_host_state
                | exact_keys([
                    "after_sha256", "before_sha256", "equal_at_fences",
                    "records"
                  ])
                and (.after_sha256 | valid_sha256)
                and (.before_sha256 | valid_sha256)
                and .after_sha256 == .before_sha256
                and .equal_at_fences == true
                and .records == expected_host_state_records
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=host-state
    fi
    if [ -z "$boundary_validator_stage" ] \
        && ! jq -e '
            def exact_keys($expected):
                type == "object" and keys == ($expected | sort);
            def expected_check_ids:
                [
                  "OBSERVED_SOURCE_TREE_CLEAN", "OBSERVED_ARTIFACT_HASHES",
                  "DEBIAN_13_AMD64_X86_64_SYSTEMD_257_VM",
                  "WORKER_INVOCATION_BOUND", "WORKER_LIVE_IDENTITY",
                  "WORKER_FDSTORE_TWO_BEFORE_RETIREMENT",
                  "WORKER_RETIRED_UNIT_NOT_FOUND",
                  "PRODUCTION_DISTINCT_INVOCATION_BOUND",
                  "PRODUCTION_ARGUMENTLESS", "PRODUCTION_IPC_BOUNDARY",
                  "PRODUCTION_FDSTORE_ZERO_AT_IDLE_OBSERVATION",
                  "PRODUCTION_FDSTORE_EXACT_CUSTODY_DURING_ACTIVE_CYCLES",
                  "PRODUCTION_FDSTORE_ZERO_AFTER_SETTLED_CYCLES",
                  "PRODUCTION_RETIRED_UNIT_NOT_FOUND",
                  "RETIREMENT_JOURNAL_SETTLED_ABSENT",
                  "RETIREMENT_LOCK_RELEASED", "RETIREMENT_SOCKET_ABSENT",
                  "ENUMERATED_HOST_STATE_EQUAL_AT_FENCES"
                ];
            (.scope
                | exact_keys([
                    "acceptance_a01_a15", "cleanup_owned", "datapath",
                    "helper_boundary_only", "installed_package",
                    "restart_recovery"
                  ])
                and .acceptance_a01_a15 == false
                and .cleanup_owned == false
                and .datapath == false
                and .helper_boundary_only == true
                and .installed_package == false
                and .restart_recovery == false)
            and (.checks
                | type == "array"
                and length == 18
                and [.[].id] == expected_check_ids
                and all(.[];
                    exact_keys(["id", "result"])
                    and .result == "PASS"))
            and .overall == "PASS"
        ' "$boundary_validator_report" >/dev/null 2>&1; then
        boundary_validator_stage=fixed-contract
    fi
    if [ -z "$boundary_validator_stage" ]; then
        boundary_validator_stage=fixed-contract
    fi
    boundary_validator_failure_stage_is_safe "$boundary_validator_stage" \
        || return 1
    printf 'VOLPAROSSA_HELPER_LIVE_BOUNDARY_VALIDATOR_DIAGNOSTIC_V1=%s\n' \
        "$boundary_validator_stage" >&2
}

proof_failure_reason_is_safe() {
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

record_proof_failure() {
    [ "$#" -eq 1 ] || failed 'internal proof failure recorder invocation is invalid'
    proof_failure_reason_is_safe "$1" \
        || failed 'internal proof failure reason is invalid'
    if [ -z "${proof_failure_reason:-}" ]; then
        proof_failure_reason=$1
    fi
    proof_ok=no
    case $1 in
        production-*)
            production_ok=no
            ;;
    esac
}

worker_confinement_failure_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        bounding|ambient|private-network|control-group) return 0 ;;
        *) return 1 ;;
    esac
}

record_worker_confinement_failure() {
    [ "$#" -eq 1 ] || failed 'internal worker confinement recorder invocation is invalid'
    worker_confinement_failure_is_safe "$1" \
        || failed 'internal worker confinement reason is invalid'
    if [ -z "${worker_confinement_failure:-}" ]; then
        worker_confinement_failure=$1
    fi
    record_proof_failure 'worker-confinement'
}

record_helper_live_proof_failure_stage() {
    [ "$#" -eq 1 ] || return 1
    vp_capture_file_is_safe "$1" || return 1
    if printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=parent-contract' \
        | cmp -s - "$1"; then
        record_proof_failure 'worker-helper-parent-contract'
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=runtime-preparation' \
        | cmp -s - "$1"; then
        record_proof_failure 'worker-helper-runtime-preparation'
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=worker-spawn' \
        | cmp -s - "$1"; then
        record_proof_failure 'worker-helper-worker-spawn'
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
        | cmp -s - "$1"; then
        record_proof_failure 'worker-helper-publication'
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=retirement-cleanup' \
        | cmp -s - "$1"; then
        record_proof_failure 'worker-helper-retirement-cleanup'
    else
        return 1
    fi
}

classify_worker_live_proof_terminal() {
    [ "$#" -eq 1 ] || return 1
    if [ "$worker_manager_binding_ok" = yes ] \
        && unit_invocation_is_current \
        && unit_description_matches_marker \
        && [ "$active_state:$sub_state:$result:$exec_code:$exec_status" \
            = failed:failed:exit-code:1:1 ]; then
        record_helper_live_proof_failure_stage "$1" || true
    fi
    record_worker_launch_failure
    if [ "$active_state" != active ] || [ "$sub_state" != exited ] \
        || [ "$result" != success ] || [ "$exec_code" != 1 ] \
        || [ "$exec_status" != 0 ]; then
        record_proof_failure 'worker-terminal-state'
    fi
}

record_worker_launch_failure() {
    if [ "$run_status" -ne 0 ]; then
        record_proof_failure 'worker-launch-status'
    fi
    if [ "$worker_launch_captures_ok" != yes ] \
        || [ "$worker_launch_json_ok" != yes ] \
        || [ "$worker_launch_stderr_empty" != yes ]; then
        record_proof_failure 'worker-launch-envelope'
    elif [ "$worker_manager_binding_ok" != yes ]; then
        record_proof_failure 'worker-manager-binding'
    fi
}

report_proof_failure() {
    [ "$#" -eq 1 ] || failed 'internal proof failure reporter invocation is invalid'
    proof_failure_reason_is_safe "$1" \
        || failed 'internal proof failure reason was not recorded'
    if [ "${proof_failure_reason:-}" != "$1" ] || [ "${proof_ok:-}" != no ]; then
        failed 'internal proof failure reason was not recorded'
    fi
    case $1 in
        worker-*)
            [ "${production_ok+x}" != x ] \
                || failed 'internal proof failure state is inconsistent'
            ;;
        production-*)
            [ "${production_ok:-}" = no ] \
                || failed 'internal proof failure state is inconsistent'
            ;;
    esac
    printf 'live worker-identity proof failed: predicate rejected: %s\n' "$1" >&2
    structured_failure_reported=yes
    exit 1
}

report_worker_launch_diagnostic() {
    [ "${proof_failure_reason:-}" = worker-launch-status ] || return 1

    case ${run_status:-} in
        0) worker_diagnostic_run=zero ;;
        ''|*[!0-9]*) worker_diagnostic_run=invalid ;;
        *) worker_diagnostic_run=nonzero ;;
    esac
    case ${worker_launch_captures_ok:-} in
        yes|no) worker_diagnostic_captures=$worker_launch_captures_ok ;;
        *) worker_diagnostic_captures=invalid ;;
    esac
    case ${worker_launch_json_ok:-} in
        yes|no) worker_diagnostic_json=$worker_launch_json_ok ;;
        *) worker_diagnostic_json=invalid ;;
    esac
    case ${worker_manager_binding_ok:-} in
        yes|no) worker_diagnostic_manager=$worker_manager_binding_ok ;;
        *) worker_diagnostic_manager=invalid ;;
    esac

    if vp_capture_file_is_safe "$temporary_stage/systemd-run.stderr"; then
        if [ -s "$temporary_stage/systemd-run.stderr" ]; then
            worker_diagnostic_client_stderr=nonempty
        else
            worker_diagnostic_client_stderr=empty
        fi
    else
        worker_diagnostic_client_stderr=unsafe
    fi

    case ${active_state:-}:${sub_state:-}:${result:-}:${exec_code:-}:${exec_status:-} in
        active:exited:success:1:0) worker_diagnostic_terminal=success ;;
        failed:failed:exit-code:1:1) worker_diagnostic_terminal=failed-exit-one ;;
        failed:failed:exit-code:1:*)
            case ${exec_status:-} in
                0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9])
                    if [ "$exec_status" -le 255 ]; then
                        worker_diagnostic_terminal=failed-exit-status-$exec_status
                    else
                        worker_diagnostic_terminal=other
                    fi
                    ;;
                *) worker_diagnostic_terminal=other ;;
            esac
            ;;
        *) worker_diagnostic_terminal=other ;;
    esac

    worker_diagnostic_stage_file=$temporary_stage/proof.stderr
    if ! vp_capture_file_is_safe "$worker_diagnostic_stage_file"; then
        worker_diagnostic_stage=unsafe
    elif [ ! -s "$worker_diagnostic_stage_file" ]; then
        worker_diagnostic_stage=empty
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=parent-contract' \
        | cmp -s - "$worker_diagnostic_stage_file"; then
        worker_diagnostic_stage=parent-contract
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=runtime-preparation' \
        | cmp -s - "$worker_diagnostic_stage_file"; then
        worker_diagnostic_stage=runtime-preparation
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=worker-spawn' \
        | cmp -s - "$worker_diagnostic_stage_file"; then
        worker_diagnostic_stage=worker-spawn
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
        | cmp -s - "$worker_diagnostic_stage_file"; then
        worker_diagnostic_stage=publication
    elif printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=retirement-cleanup' \
        | cmp -s - "$worker_diagnostic_stage_file"; then
        worker_diagnostic_stage=retirement-cleanup
    else
        worker_diagnostic_stage=other
    fi

    printf '%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n' \
        'VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=run-' \
        "$worker_diagnostic_run" \
        ',captures-' "$worker_diagnostic_captures" \
        ',json-' "$worker_diagnostic_json" \
        ',manager-' "$worker_diagnostic_manager" \
        ',client-stderr-' "$worker_diagnostic_client_stderr" \
        ',terminal-' "$worker_diagnostic_terminal" \
        ',stage-' "$worker_diagnostic_stage" >&2
}

report_worker_confinement_diagnostic() {
    [ "${proof_failure_reason:-}" = worker-confinement ] || return 1
    worker_confinement_failure_is_safe "${worker_confinement_failure:-}" || return 1
    printf 'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=%s\n' \
        "$worker_confinement_failure" >&2
}

report_restart_crash_record_diagnostic() {
    [ "$#" -eq 2 ] || return 1
    restart_crash_diagnostic_record=$1
    restart_crash_diagnostic_stderr=$2
    if [ ! -e "$restart_crash_diagnostic_record" ] \
        && [ ! -L "$restart_crash_diagnostic_record" ]; then
        restart_crash_diagnostic_record_state=absent
    elif vp_capture_file_is_safe "$restart_crash_diagnostic_record"; then
        return 1
    else
        restart_crash_diagnostic_record_state=unsafe
    fi

    if ! vp_capture_file_is_safe "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=stderr-unsafe
    elif grep -Fqx \
        'production IPC unit hook failed: restart exact descriptor custody is unavailable' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=fdstore-read
    elif grep -Fqx \
        'production IPC unit hook failed: restart descriptor count changed during observation' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=fdstore-count
    elif grep -Fqx \
        'production IPC unit hook failed: restart exact descriptor custody changed' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=fdstore-name
    elif grep -Fqx \
        'production IPC unit hook failed: restart CleanupConfirmed journal is unavailable' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=journal-read
    elif grep -Fqx \
        'production IPC unit hook failed: restart CleanupConfirmed journal proof is invalid' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=journal-value
    elif grep -Fqx \
        'production IPC unit hook failed: precrash hook ControlPID changed' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=control-binding
    elif grep -Eq \
        '^production IPC unit hook failed: precrash worker (namespace|process) pin is unavailable$' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=pin-open
    elif grep -Eq \
        '^production IPC unit hook failed: precrash worker (namespace|process) pin changed$' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=pin-change
    elif grep -Fqx \
        'production IPC unit hook failed: precrash worker process is not retired' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=process-live
    elif grep -Fqx \
        'production IPC unit hook failed: precrash worker WireGuard state remains' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=wireguard-live
    elif grep -Eq \
        '^production IPC unit hook failed: (cleanup-confirmed time is unavailable|crash record is unavailable|crash record could not be published)$' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=publication
    elif grep -Fqx \
        'production IPC unit hook failed: restart MainPID is not manager-bound' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=manager-binding
    elif grep -Eq \
        '^production IPC unit hook failed: restart (precrash identity|initial [A-Za-z ]+|worker [A-Za-z ]+|pidfd descriptor identity|namespace descriptor identity|custody name|peer fixture) is (unavailable|invalid)$' \
        "$restart_crash_diagnostic_stderr"; then
        restart_crash_diagnostic_observer=precrash
    elif [ ! -s "$restart_crash_diagnostic_stderr" ]; then
        restart_crash_diagnostic_observer=stderr-empty
    else
        restart_crash_diagnostic_observer=stderr-other
    fi
    printf 'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-%s,observer-%s\n' \
        "$restart_crash_diagnostic_record_state" \
        "$restart_crash_diagnostic_observer" >&2
}

restart_successor_debugger_failure_category_is_safe() {
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

restart_successor_debugger_failure_category() {
    [ "$#" -eq 3 ] || return 1
    restart_successor_debugger_status=$1
    restart_successor_debugger_stdout=$2
    restart_successor_debugger_stderr=$3
    case $restart_successor_debugger_status in
        ''|0|*[!0-9]*) return 1 ;;
    esac
    for restart_successor_debugger_log in \
        "$restart_successor_debugger_stdout" \
        "$restart_successor_debugger_stderr"; do
        vp_capture_file_is_safe "$restart_successor_debugger_log" || return 1
        [ "$(stat -Lc '%s' "$restart_successor_debugger_log")" -le 1048576 ] \
            || return 1
    done
    restart_successor_exec_marker=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=exec-caught
    restart_successor_breakpoint_marker=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-installed
    restart_successor_hit_marker=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-hit
    restart_successor_observer_ok_marker=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-ok
    restart_successor_observer_failed_marker=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-failed
    restart_successor_marker_prefix=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=
    restart_successor_marker_sequence=$(grep -F \
        "$restart_successor_marker_prefix" \
        "$restart_successor_debugger_stdout" || true)
    restart_successor_exec_breakpoint=$(printf '%s\n%s' \
        "$restart_successor_exec_marker" \
        "$restart_successor_breakpoint_marker") || return 1
    restart_successor_through_hit=$(printf '%s\n%s' \
        "$restart_successor_exec_breakpoint" \
        "$restart_successor_hit_marker") || return 1
    restart_successor_through_observer_ok=$(printf '%s\n%s' \
        "$restart_successor_through_hit" \
        "$restart_successor_observer_ok_marker") || return 1
    restart_successor_through_observer_failed=$(printf '%s\n%s' \
        "$restart_successor_through_hit" \
        "$restart_successor_observer_failed_marker") || return 1
    restart_successor_debugger_category=
    restart_successor_observer_failed=no
    case $restart_successor_marker_sequence in
        '') restart_successor_debugger_category=exec-not-caught ;;
        "$restart_successor_exec_marker")
            restart_successor_debugger_category=breakpoint-not-installed ;;
        "$restart_successor_exec_breakpoint")
            restart_successor_debugger_category=breakpoint-not-reached ;;
        "$restart_successor_through_hit")
            case $restart_successor_debugger_status in
                137|143) restart_successor_debugger_category=observer-timeout ;;
                *) restart_successor_debugger_category=observer-other ;;
            esac
            ;;
        "$restart_successor_through_observer_ok")
            restart_successor_debugger_category=post-observer ;;
        "$restart_successor_through_observer_failed")
            restart_successor_observer_failed=yes ;;
        *) restart_successor_debugger_category=marker-invalid ;;
    esac
    if [ "$restart_successor_observer_failed" = yes ]; then
        restart_successor_hook_prefix='production IPC unit hook failed: '
        restart_successor_hook_count=$(grep -c \
            "^$restart_successor_hook_prefix" \
            "$restart_successor_debugger_stderr" || true)
        if [ "$restart_successor_hook_count" != 1 ]; then
            restart_successor_debugger_category=observer-other
        else
            restart_successor_hook_line=$(grep \
                "^$restart_successor_hook_prefix" \
                "$restart_successor_debugger_stderr") || return 1
            case $restart_successor_hook_line in
                'production IPC unit hook failed: restart MainPID is not manager-bound')
                    restart_successor_debugger_category=observer-manager-binding ;;
                'production IPC unit hook failed: restart precrash identity is unavailable'|\
                'production IPC unit hook failed: restart initial invocation is unavailable'|\
                'production IPC unit hook failed: restart initial invocation is invalid'|\
                'production IPC unit hook failed: restart initial PID is unavailable'|\
                'production IPC unit hook failed: restart initial PID is invalid'|\
                'production IPC unit hook failed: restart initial starttime is unavailable'|\
                'production IPC unit hook failed: restart initial starttime is invalid'|\
                'production IPC unit hook failed: restart initial socket is unavailable'|\
                'production IPC unit hook failed: restart hook PID is unavailable'|\
                'production IPC unit hook failed: restart worker PID is unavailable'|\
                'production IPC unit hook failed: restart worker starttime is unavailable'|\
                'production IPC unit hook failed: restart worker namespace is unavailable'|\
                'production IPC unit hook failed: restart worker process identity is unavailable'|\
                'production IPC unit hook failed: restart pidfd descriptor identity is unavailable'|\
                'production IPC unit hook failed: restart namespace descriptor identity is unavailable'|\
                'production IPC unit hook failed: restart custody name is unavailable'|\
                'production IPC unit hook failed: restart custody name is invalid'|\
                'production IPC unit hook failed: restart peer fixture is unavailable')
                    restart_successor_debugger_category=observer-precrash-record ;;
                'production IPC unit hook failed: restart exact descriptor custody is unavailable')
                    restart_successor_debugger_category=observer-fdstore-read ;;
                'production IPC unit hook failed: restart descriptor count changed during observation')
                    restart_successor_debugger_category=observer-fdstore-count ;;
                'production IPC unit hook failed: restart exact descriptor custody changed')
                    restart_successor_debugger_category=observer-fdstore-name ;;
                'production IPC unit hook failed: restart CleanupConfirmed journal is unavailable')
                    restart_successor_debugger_category=observer-journal-read ;;
                'production IPC unit hook failed: restart CleanupConfirmed journal proof is invalid')
                    restart_successor_debugger_category=observer-journal-value ;;
                'production IPC unit hook failed: restart successor invocation is unavailable')
                    restart_successor_debugger_category=observer-invocation-read ;;
                'production IPC unit hook failed: restart successor reused the invocation')
                    restart_successor_debugger_category=observer-invocation-reuse ;;
                'production IPC unit hook failed: restart successor reused the MainPID')
                    restart_successor_debugger_category=observer-mainpid-reuse ;;
                'production IPC unit hook failed: restart count is not exactly one')
                    restart_successor_debugger_category=observer-restart-count ;;
                'production IPC unit hook failed: a new socket appeared before settlement')
                    restart_successor_debugger_category=observer-socket-change ;;
                'production IPC unit hook failed: restart boundary time is unavailable')
                    restart_successor_debugger_category=observer-time ;;
                'production IPC unit hook failed: restart successor starttime is unavailable')
                    restart_successor_debugger_category=observer-starttime ;;
                'production IPC unit hook failed: restart boundary record is unavailable')
                    restart_successor_debugger_category=observer-record-build ;;
                'production IPC unit hook failed: restart boundary record could not be published')
                    restart_successor_debugger_category=observer-record-publication ;;
                *) restart_successor_debugger_category=observer-other ;;
            esac
        fi
    fi
    restart_successor_debugger_failure_category_is_safe \
        "$restart_successor_debugger_category" || return 1
    printf '%s\n' "$restart_successor_debugger_category"
}

production_start_failure_stage_is_safe() {
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

restart_successor_start_failure_category() {
    [ "$#" -eq 1 ] || return 1
    restart_start_failure_file=$1
    vp_capture_file_is_safe "$restart_start_failure_file" || return 1
    [ ! -e "$restart_start_failure_file.next" ] \
        && [ ! -L "$restart_start_failure_file.next" ] || return 1
    restart_start_failure_size=$(stat -Lc '%s' \
        "$restart_start_failure_file" 2>/dev/null) || return 1
    [ "$restart_start_failure_size" -ge 1 ] \
        && [ "$restart_start_failure_size" -le 128 ] || return 1
    restart_start_failure_record=$(cat "$restart_start_failure_file") \
        || return 1
    restart_start_failure_prefix=VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=
    case $restart_start_failure_record in
        "$restart_start_failure_prefix"*)
            restart_start_failure_stage=${restart_start_failure_record#"$restart_start_failure_prefix"}
            ;;
        *) return 1 ;;
    esac
    printf '%s%s\n' "$restart_start_failure_prefix" \
        "$restart_start_failure_stage" \
        | cmp -s - "$restart_start_failure_file" || return 1
    case $restart_start_failure_stage in
        preflight-runtime) printf '%s\n' preflight ;;
        restart-recovery-wait) printf '%s\n' recovery-wait ;;
        restart-lineage) printf '%s\n' lineage ;;
        restart-descriptor-settlement) printf '%s\n' descriptor-settlement ;;
        restart-journal-settlement) printf '%s\n' journal-settlement ;;
        restart-socket-validation) printf '%s\n' socket-validation ;;
        restart-publication) printf '%s\n' publication ;;
        *) return 1 ;;
    esac
}

restart_readiness_failure_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        preflight|clock-read|clock-backwards|lineage-pid|lineage-invocation|\
        socket-capture|\
        initial-journal-value|stage-transition|final-journal-read|\
        final-journal-value|bind-runtime-read|bind-runtime-value|journal-next|\
        journal-state-before|journal-state-after|journal-state-change|\
        socket-stability|final-lineage-pid|final-lineage-invocation|timeout)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_restart_readiness_failure_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    restart_readiness_diagnostic_file=$1
    vp_capture_file_is_safe "$restart_readiness_diagnostic_file" || return 1
    [ ! -e "$restart_readiness_diagnostic_file.next" ] \
        && [ ! -L "$restart_readiness_diagnostic_file.next" ] || return 1
    restart_readiness_diagnostic_size=$(stat -Lc '%s' \
        "$restart_readiness_diagnostic_file" 2>/dev/null) || return 1
    [ "$restart_readiness_diagnostic_size" -ge 1 ] \
        && [ "$restart_readiness_diagnostic_size" -le 128 ] || return 1
    restart_readiness_diagnostic_record=$(cat \
        "$restart_readiness_diagnostic_file") || return 1
    restart_readiness_diagnostic_prefix=VOLPAROSSA_HELPER_V3_RESTART_READINESS_FAILURE_V1=
    case $restart_readiness_diagnostic_record in
        "$restart_readiness_diagnostic_prefix"*)
            restart_readiness_diagnostic_stage=${restart_readiness_diagnostic_record#"$restart_readiness_diagnostic_prefix"}
            ;;
        *) return 1 ;;
    esac
    restart_readiness_failure_stage_is_safe \
        "$restart_readiness_diagnostic_stage" || return 1
    printf '%s%s\n' "$restart_readiness_diagnostic_prefix" \
        "$restart_readiness_diagnostic_stage" \
        | cmp -s - "$restart_readiness_diagnostic_file" || return 1
    printf 'VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=%s\n' \
        "$restart_readiness_diagnostic_stage" >&2
}

restart_initial_driver_failure_stage_is_safe() {
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

set_restart_initial_driver_failure_stage() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_driver_failure_stage_is_safe "$1" || return 1
    restart_initial_driver_failure_stage=$1
}

restart_initial_hook_failure_stage_is_safe() {
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

read_restart_initial_hook_failure_stage() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_hook_failure_file=$1
    vp_capture_file_is_safe "$restart_initial_hook_failure_file" || return 1
    [ ! -e "$restart_initial_hook_failure_file.next" ] \
        && [ ! -L "$restart_initial_hook_failure_file.next" ] || return 1
    restart_initial_hook_failure_size=$(stat -Lc '%s' \
        "$restart_initial_hook_failure_file" 2>/dev/null) || return 1
    [ "$restart_initial_hook_failure_size" -ge 1 ] \
        && [ "$restart_initial_hook_failure_size" -le 128 ] || return 1
    restart_initial_hook_failure_record=$(cat \
        "$restart_initial_hook_failure_file") || return 1
    restart_initial_hook_failure_prefix=VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_FAILURE_V1=
    case $restart_initial_hook_failure_record in
        "$restart_initial_hook_failure_prefix"*)
            restart_initial_hook_failure_stage=${restart_initial_hook_failure_record#"$restart_initial_hook_failure_prefix"}
            ;;
        *) return 1 ;;
    esac
    restart_initial_hook_failure_stage_is_safe \
        "$restart_initial_hook_failure_stage" || return 1
    printf '%s%s\n' "$restart_initial_hook_failure_prefix" \
        "$restart_initial_hook_failure_stage" \
        | cmp -s - "$restart_initial_hook_failure_file" || return 1
    printf '%s\n' "$restart_initial_hook_failure_stage"
}

inspect_restart_initial_hook_failure_record() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_hook_failure_file=$1
    restart_initial_hook_failure_state=absent
    restart_initial_hook_failure_stage=
    if [ -e "$restart_initial_hook_failure_file" ] \
        || [ -L "$restart_initial_hook_failure_file" ]; then
        if [ -e "$restart_initial_hook_failure_file.next" ] \
            || [ -L "$restart_initial_hook_failure_file.next" ]; then
            restart_initial_hook_failure_state=unsafe
            return 0
        fi
        if ! vp_capture_file_is_safe "$restart_initial_hook_failure_file"; then
            restart_initial_hook_failure_state=unsafe
            return 0
        fi
        if restart_initial_hook_failure_stage=$( \
            read_restart_initial_hook_failure_stage \
                "$restart_initial_hook_failure_file"
        ); then
            restart_initial_hook_failure_state=present
        else
            restart_initial_hook_failure_state=invalid
        fi
        return 0
    fi
    if [ -e "$restart_initial_hook_failure_file.next" ] \
        || [ -L "$restart_initial_hook_failure_file.next" ]; then
        if vp_capture_file_is_safe \
            "$restart_initial_hook_failure_file.next"; then
            restart_initial_hook_failure_state=pending
        else
            restart_initial_hook_failure_state=unsafe
        fi
    fi
}

restart_initial_terminal_record_is_exact() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_terminal_file=$1
    vp_capture_file_is_safe "$restart_initial_terminal_file" || return 1
    [ ! -e "$restart_initial_terminal_file.next" ] \
        && [ ! -L "$restart_initial_terminal_file.next" ] || return 1
    restart_initial_terminal_size=$(stat -Lc '%s' \
        "$restart_initial_terminal_file" 2>/dev/null) || return 1
    [ "$restart_initial_terminal_size" -ge 1 ] \
        && [ "$restart_initial_terminal_size" -le 128 ] || return 1
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_TERMINAL_V1=success' \
        | cmp -s - "$restart_initial_terminal_file"
}

inspect_restart_initial_terminal_record() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_terminal_file=$1
    restart_initial_terminal_state=absent
    if [ -e "$restart_initial_terminal_file" ] \
        || [ -L "$restart_initial_terminal_file" ]; then
        if [ -e "$restart_initial_terminal_file.next" ] \
            || [ -L "$restart_initial_terminal_file.next" ]; then
            restart_initial_terminal_state=unsafe
        elif ! vp_capture_file_is_safe "$restart_initial_terminal_file"; then
            restart_initial_terminal_state=unsafe
        elif restart_initial_terminal_record_is_exact \
            "$restart_initial_terminal_file"; then
            restart_initial_terminal_state=present
        else
            restart_initial_terminal_state=invalid
        fi
        return 0
    fi
    if [ -e "$restart_initial_terminal_file.next" ] \
        || [ -L "$restart_initial_terminal_file.next" ]; then
        if vp_capture_file_is_safe "$restart_initial_terminal_file.next"; then
            restart_initial_terminal_state=pending
        else
            restart_initial_terminal_state=unsafe
        fi
    fi
}

classify_restart_initial_hook_failure_record() {
    [ "$#" -eq 1 ] || return 1
    inspect_restart_initial_hook_failure_record "$1" || return 1
    case $restart_initial_hook_failure_state in
        absent) return 1 ;;
        pending) return 2 ;;
        present)
            restart_initial_hook_failure_stage_is_safe \
                "$restart_initial_hook_failure_stage" || return 1
            return 0
            ;;
        unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path \
                || return 1
            return 3
            ;;
        invalid)
            set_restart_initial_driver_failure_stage hook-payload \
                || return 1
            return 3
            ;;
        *) return 3 ;;
    esac
}

consume_expected_restart_initial_start_failure() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_start_failure_file=$1
    restart_initial_hook_failure_file=$temporary_stage/restart-output/restart.initial-start.failure-stage
    restart_initial_driver_failure_stage=
    restart_initial_hook_failure_stage=
    restart_initial_terminal_identity=
    restart_initial_after_crash_observed=no
    set_restart_initial_driver_failure_stage appearance || return 1
    restart_initial_start_failure_wait=0
    while :; do
        inspect_restart_initial_hook_failure_record \
            "$restart_initial_hook_failure_file" || return 1
        case $restart_initial_hook_failure_state in
            present) return 1 ;;
            invalid)
                set_restart_initial_driver_failure_stage hook-payload \
                    || return 1
                return 1
                ;;
            unsafe)
                set_restart_initial_driver_failure_stage unsafe-pending-path \
                    || return 1
                return 1
                ;;
            absent)
                if vp_capture_file_is_safe \
                    "$restart_initial_start_failure_file"; then
                    break
                fi
                ;;
            pending) ;;
            *) return 1 ;;
        esac
        if ! vp_capture_file_is_safe "$restart_initial_start_failure_file" \
            && { [ -e "$restart_initial_start_failure_file" ] \
                || [ -L "$restart_initial_start_failure_file" ]; }; then
            set_restart_initial_driver_failure_stage unsafe-pending-path \
                || return 1
            return 1
        fi
        if [ -e "$restart_initial_start_failure_file.next" ] \
            || [ -L "$restart_initial_start_failure_file.next" ]; then
            vp_capture_file_is_safe "$restart_initial_start_failure_file.next" \
                || {
                    set_restart_initial_driver_failure_stage unsafe-pending-path \
                        || return 1
                    return 1
                }
        fi
        set_restart_initial_driver_failure_stage main-pid || return 1
        [ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ] \
            || return 1
        set_restart_initial_driver_failure_stage restart-count || return 1
        [ "$(systemctl show --property=NRestarts --value "$unit_name")" = 0 ] \
            || return 1
        set_restart_initial_driver_failure_stage control-pid || return 1
        [ "$(systemctl show --property=ControlPID --value "$unit_name")" = \
            "$restart_initial_hook_pid" ] || return 1
        set_restart_initial_driver_failure_stage invocation || return 1
        [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
            "$restart_initial_invocation_id" ] || return 1
        set_restart_initial_driver_failure_stage marker || return 1
        unit_description_matches_marker || return 1
        set_restart_initial_driver_failure_stage appearance || return 1
        restart_initial_start_failure_wait=$((
            restart_initial_start_failure_wait + 1
        ))
        [ "$restart_initial_start_failure_wait" -lt 150 ] || return 1
        sleep 0.05
    done
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_hook_failure_file" || return 1
    case $restart_initial_hook_failure_state in
        present) return 1 ;;
        invalid)
            set_restart_initial_driver_failure_stage hook-payload || return 1
            return 1
            ;;
        pending|unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
            return 1
            ;;
        absent) ;;
        *) return 1 ;;
    esac
    set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
    [ ! -e "$restart_initial_start_failure_file.next" ] \
        && [ ! -L "$restart_initial_start_failure_file.next" ] || return 1
    set_restart_initial_driver_failure_stage start-payload || return 1
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-client-release' \
        | cmp -s - "$restart_initial_start_failure_file" || return 1
    restart_initial_functional_stdout_file=$temporary_stage/restart-output/functional-client-lease.stdout
    restart_initial_functional_stderr_file=$temporary_stage/restart-output/functional-client-lease.stderr
    restart_initial_functional_failure_file=$temporary_stage/restart-output/functional-client-lease.failure
    vp_capture_file_is_safe "$restart_initial_functional_failure_file" || return 1
    [ ! -e "$restart_initial_functional_failure_file.next" ] \
        && [ ! -L "$restart_initial_functional_failure_file.next" ] || return 1
    vp_capture_file_is_safe "$restart_initial_functional_stdout_file" || return 1
    vp_capture_file_is_safe "$restart_initial_functional_stderr_file" || return 1
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
        | cmp -s - "$restart_initial_functional_stdout_file" || return 1
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=destroy,protocol' \
        | cmp -s - "$restart_initial_functional_failure_file" || return 1
    cmp -s "$restart_initial_functional_failure_file" \
        "$restart_initial_functional_stderr_file" || return 1
    restart_initial_functional_failure_identity=$(stat -Lc \
        '%d:%i:%f:%u:%g:%a:%h:%s' \
        "$restart_initial_functional_failure_file" 2>/dev/null) || return 1
    set_restart_initial_driver_failure_stage main-pid || return 1
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ] \
        || return 1
    set_restart_initial_driver_failure_stage restart-count || return 1
    [ "$(systemctl show --property=NRestarts --value "$unit_name")" = 0 ] \
        || return 1
    set_restart_initial_driver_failure_stage control-pid || return 1
    [ "$(systemctl show --property=ControlPID --value "$unit_name")" = \
        "$restart_initial_hook_pid" ] || return 1
    set_restart_initial_driver_failure_stage invocation || return 1
    [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
        "$restart_initial_invocation_id" ] || return 1
    set_restart_initial_driver_failure_stage marker || return 1
    unit_description_matches_marker || return 1
    set_restart_initial_driver_failure_stage stable-inode || return 1
    [ "$restart_initial_functional_failure_identity" = \
        "$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
            "$restart_initial_functional_failure_file" 2>/dev/null)" ] || return 1
    rm -- "$restart_initial_functional_failure_file" || return 1
    [ ! -e "$restart_initial_functional_failure_file" ] \
        && [ ! -L "$restart_initial_functional_failure_file" ] \
        && [ ! -e "$restart_initial_functional_failure_file.next" ] \
        && [ ! -L "$restart_initial_functional_failure_file.next" ] || return 1
    restart_initial_start_failure_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
        "$restart_initial_start_failure_file" 2>/dev/null) || return 1
    [ "$restart_initial_start_failure_identity" = \
        "$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
            "$restart_initial_start_failure_file" 2>/dev/null)" ] || return 1
    # Every old-invocation fence is complete before this unlink. The still-live
    # ExecStartPost treats absence as the acknowledgement and only then returns
    # its intentional failure, so no racy manager read belongs after unlink.
    set_restart_initial_driver_failure_stage unlink || return 1
    rm -- "$restart_initial_start_failure_file" || return 1
    set_restart_initial_driver_failure_stage absence || return 1
    [ ! -e "$restart_initial_start_failure_file" ] \
        && [ ! -L "$restart_initial_start_failure_file" ] \
        && [ ! -e "$restart_initial_start_failure_file.next" ] \
        && [ ! -L "$restart_initial_start_failure_file.next" ] || return 1
    # The unlink is only the hook's input ACK. Do not accept the handshake
    # until that same hook has completed its post-lineage and post-pin fences
    # and published the separate canonical terminal-success record. No old
    # systemd InvocationID read is valid or needed after the unlink.
    restart_initial_terminal_file=$temporary_stage/restart-output/restart.initial-start.terminal
    set_restart_initial_driver_failure_stage appearance || return 1
    restart_initial_terminal_wait=0
    while :; do
        inspect_restart_initial_hook_failure_record \
            "$restart_initial_hook_failure_file" || return 1
        case $restart_initial_hook_failure_state in
            present) return 1 ;;
            invalid)
                set_restart_initial_driver_failure_stage hook-payload \
                    || return 1
                return 1
                ;;
            unsafe)
                set_restart_initial_driver_failure_stage unsafe-pending-path \
                    || return 1
                return 1
                ;;
            absent|pending) ;;
            *) return 1 ;;
        esac
        inspect_restart_initial_terminal_record \
            "$restart_initial_terminal_file" || return 1
        case $restart_initial_terminal_state in
            present)
                if [ "$restart_initial_hook_failure_state" = pending ]; then
                    set_restart_initial_driver_failure_stage unsafe-pending-path \
                        || return 1
                    return 1
                fi
                break
                ;;
            invalid)
                set_restart_initial_driver_failure_stage terminal-payload \
                    || return 1
                return 1
                ;;
            unsafe)
                set_restart_initial_driver_failure_stage unsafe-pending-path \
                    || return 1
                return 1
                ;;
            absent|pending) ;;
            *) return 1 ;;
        esac
        set_restart_initial_driver_failure_stage absence || return 1
        [ ! -e "$restart_initial_start_failure_file" ] \
            && [ ! -L "$restart_initial_start_failure_file" ] \
            && [ ! -e "$restart_initial_start_failure_file.next" ] \
            && [ ! -L "$restart_initial_start_failure_file.next" ] || return 1
        set_restart_initial_driver_failure_stage appearance || return 1
        restart_initial_terminal_wait=$((restart_initial_terminal_wait + 1))
        [ "$restart_initial_terminal_wait" -lt 300 ] || return 1
        sleep 0.05
    done
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_hook_failure_file" || return 1
    case $restart_initial_hook_failure_state in
        absent) ;;
        present) return 1 ;;
        invalid)
            set_restart_initial_driver_failure_stage hook-payload || return 1
            return 1
            ;;
        pending|unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
            return 1
            ;;
        *) return 1 ;;
    esac
    set_restart_initial_driver_failure_stage terminal-payload || return 1
    restart_initial_terminal_record_is_exact \
        "$restart_initial_terminal_file" || return 1
    set_restart_initial_driver_failure_stage stable-inode || return 1
    restart_initial_terminal_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
        "$restart_initial_terminal_file" 2>/dev/null) || return 1
    [ "$restart_initial_terminal_identity" = \
        "$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
            "$restart_initial_terminal_file" 2>/dev/null)" ] || return 1
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_hook_failure_file" || return 1
    [ "$restart_initial_hook_failure_state" = absent ] || {
        case $restart_initial_hook_failure_state in
            invalid)
                set_restart_initial_driver_failure_stage hook-payload \
                    || return 1
                ;;
            *)
                set_restart_initial_driver_failure_stage unsafe-pending-path \
                    || return 1
                ;;
        esac
        return 1
    }
    set_restart_initial_driver_failure_stage absence || return 1
    [ -e "$restart_initial_terminal_file" ] \
        && [ ! -L "$restart_initial_terminal_file" ] || return 1
    [ ! -e "$restart_initial_terminal_file.next" ] \
        && [ ! -L "$restart_initial_terminal_file.next" ] \
        && [ ! -e "$restart_initial_hook_failure_file" ] \
        && [ ! -L "$restart_initial_hook_failure_file" ] \
        && [ ! -e "$restart_initial_hook_failure_file.next" ] \
        && [ ! -L "$restart_initial_hook_failure_file.next" ] || return 1
    # Terminal success proves post-cleanup readiness, but it is intentionally
    # retained. The root driver must observe after-crash custody while this old
    # ExecStartPost is still ControlPID, then release this exact inode once.
    restart_initial_driver_failure_stage=
    return 0
}

release_expected_restart_initial_terminal() {
    [ "$#" -eq 2 ] || return 1
    restart_initial_release_terminal_file=$1
    restart_initial_release_failure_file=$2
    [ "$restart_initial_release_terminal_file" = \
        "$temporary_stage/restart-output/restart.initial-start.terminal" ] \
        || return 1
    [ "$restart_initial_release_failure_file" = \
        "$temporary_stage/restart-output/restart.initial-start.failure-stage" ] \
        || return 1
    set_restart_initial_driver_failure_stage hook-identity || return 1
    [ "$restart_initial_after_crash_observed" = yes ] || return 1
    case $restart_initial_hook_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    if [ "${#restart_initial_hook_pid}" -gt 10 ] \
        || [ "$restart_initial_hook_pid" -gt 4294967294 ]; then
        return 1
    fi
    case $restart_initial_hook_starttime in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#restart_initial_hook_starttime}" -le 20 ] || return 1
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_release_failure_file" || return 1
    case $restart_initial_hook_failure_state in
        absent) ;;
        present) return 1 ;;
        invalid)
            set_restart_initial_driver_failure_stage hook-payload || return 1
            return 1
            ;;
        pending|unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
            return 1
            ;;
        *) return 1 ;;
    esac
    inspect_restart_initial_terminal_record \
        "$restart_initial_release_terminal_file" || return 1
    case $restart_initial_terminal_state in
        present) ;;
        absent|pending)
            set_restart_initial_driver_failure_stage appearance || return 1
            return 1
            ;;
        invalid)
            set_restart_initial_driver_failure_stage terminal-payload || return 1
            return 1
            ;;
        unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
            return 1
            ;;
        *) return 1 ;;
    esac
    set_restart_initial_driver_failure_stage main-pid || return 1
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ] \
        || return 1
    set_restart_initial_driver_failure_stage restart-count || return 1
    [ "$(systemctl show --property=NRestarts --value "$unit_name")" = 0 ] \
        || return 1
    set_restart_initial_driver_failure_stage invocation || return 1
    [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
        "$restart_initial_invocation_id" ] || return 1
    set_restart_initial_driver_failure_stage marker || return 1
    unit_description_matches_marker || return 1
    set_restart_initial_driver_failure_stage control-pid || return 1
    [ "$(systemctl show --property=ControlPID --value "$unit_name")" = \
        "$restart_initial_hook_pid" ] || return 1
    set_restart_initial_driver_failure_stage hook-identity || return 1
    [ "$(capture_process_starttime "$restart_initial_hook_pid" \
        2>/dev/null || true)" = "$restart_initial_hook_starttime" ] || return 1
    set_restart_initial_driver_failure_stage terminal-payload || return 1
    restart_initial_terminal_record_is_exact \
        "$restart_initial_release_terminal_file" || return 1
    set_restart_initial_driver_failure_stage stable-inode || return 1
    restart_initial_release_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
        "$restart_initial_release_terminal_file" 2>/dev/null) || return 1
    [ "$restart_initial_release_identity" = \
        "$restart_initial_terminal_identity" ] || return 1
    [ "$restart_initial_release_identity" = \
        "$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
            "$restart_initial_release_terminal_file" 2>/dev/null)" ] || return 1
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_release_failure_file" || return 1
    [ "$restart_initial_hook_failure_state" = absent ] || {
        case $restart_initial_hook_failure_state in
            invalid)
                set_restart_initial_driver_failure_stage hook-payload \
                    || return 1
                ;;
            *)
                set_restart_initial_driver_failure_stage unsafe-pending-path \
                    || return 1
                ;;
        esac
        return 1
    }
    set_restart_initial_driver_failure_stage main-pid || return 1
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ] \
        || return 1
    set_restart_initial_driver_failure_stage restart-count || return 1
    [ "$(systemctl show --property=NRestarts --value "$unit_name")" = 0 ] \
        || return 1
    set_restart_initial_driver_failure_stage invocation || return 1
    [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
        "$restart_initial_invocation_id" ] || return 1
    set_restart_initial_driver_failure_stage marker || return 1
    unit_description_matches_marker || return 1
    set_restart_initial_driver_failure_stage control-pid || return 1
    [ "$(systemctl show --property=ControlPID --value "$unit_name")" = \
        "$restart_initial_hook_pid" ] || return 1
    set_restart_initial_driver_failure_stage hook-identity || return 1
    [ "$(capture_process_starttime "$restart_initial_hook_pid" \
        2>/dev/null || true)" = "$restart_initial_hook_starttime" ] || return 1
    set_restart_initial_driver_failure_stage stable-inode || return 1
    [ "$(stat -Lc '%d:%i:%f:%u:%g:%a:%h:%s' \
        "$restart_initial_release_terminal_file" 2>/dev/null)" = \
        "$restart_initial_release_identity" ] || return 1
    set_restart_initial_driver_failure_stage unlink || return 1
    rm -- "$restart_initial_release_terminal_file" || return 1
    set_restart_initial_driver_failure_stage absence || return 1
    [ ! -e "$restart_initial_release_terminal_file" ] \
        && [ ! -L "$restart_initial_release_terminal_file" ] \
        && [ ! -e "$restart_initial_release_terminal_file.next" ] \
        && [ ! -L "$restart_initial_release_terminal_file.next" ] || return 1
    set_restart_initial_driver_failure_stage hook-quiescence || return 1
    restart_initial_hook_quiescence_wait=0
    while [ "$(capture_process_starttime "$restart_initial_hook_pid" \
        2>/dev/null || true)" = "$restart_initial_hook_starttime" ]; do
        inspect_restart_initial_hook_failure_record \
            "$restart_initial_release_failure_file" || return 1
        case $restart_initial_hook_failure_state in
            absent|pending) ;;
            present) return 1 ;;
            invalid)
                set_restart_initial_driver_failure_stage hook-payload \
                    || return 1
                return 1
                ;;
            unsafe)
                set_restart_initial_driver_failure_stage unsafe-pending-path \
                    || return 1
                return 1
                ;;
            *) return 1 ;;
        esac
        [ ! -e "$restart_initial_release_terminal_file" ] \
            && [ ! -L "$restart_initial_release_terminal_file" ] \
            && [ ! -e "$restart_initial_release_terminal_file.next" ] \
            && [ ! -L "$restart_initial_release_terminal_file.next" ] || return 1
        restart_initial_hook_quiescence_wait=$((
            restart_initial_hook_quiescence_wait + 1
        ))
        [ "$restart_initial_hook_quiescence_wait" -lt 300 ] || return 1
        sleep 0.05
    done
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_release_failure_file" || return 1
    case $restart_initial_hook_failure_state in
        absent) ;;
        present) return 1 ;;
        invalid)
            set_restart_initial_driver_failure_stage hook-payload || return 1
            return 1
            ;;
        pending|unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
            return 1
            ;;
        *) return 1 ;;
    esac
    set_restart_initial_driver_failure_stage absence || return 1
    [ ! -e "$restart_initial_release_terminal_file" ] \
        && [ ! -L "$restart_initial_release_terminal_file" ] \
        && [ ! -e "$restart_initial_release_terminal_file.next" ] \
        && [ ! -L "$restart_initial_release_terminal_file.next" ] || return 1
    restart_initial_after_crash_observed=no
    restart_initial_driver_failure_stage=
    return 0
}

report_restart_initial_start_failure_diagnostic() {
    [ "$#" -eq 1 ] || return 1
    restart_initial_hook_failure_file=$1
    inspect_restart_initial_hook_failure_record \
        "$restart_initial_hook_failure_file" || return 1
    case $restart_initial_hook_failure_state in
        present)
            restart_initial_hook_failure_stage_is_safe \
                "$restart_initial_hook_failure_stage" || return 1
            printf 'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_HOOK_V1=%s\n' \
                "$restart_initial_hook_failure_stage" >&2
            return 0
            ;;
        invalid)
            set_restart_initial_driver_failure_stage hook-payload || return 1
            ;;
        pending|unsafe)
            set_restart_initial_driver_failure_stage unsafe-pending-path || return 1
            ;;
        absent) ;;
        *) return 1 ;;
    esac
    restart_initial_driver_failure_stage_is_safe \
        "$restart_initial_driver_failure_stage" || return 1
    if [ "$restart_initial_driver_failure_stage" = start-payload ]; then
        restart_initial_start_diagnostic_file=$temporary_stage/restart-output/start.failure
        if vp_capture_file_is_safe "$restart_initial_start_diagnostic_file" \
            && [ ! -e "$restart_initial_start_diagnostic_file.next" ] \
            && [ ! -L "$restart_initial_start_diagnostic_file.next" ]; then
            restart_initial_start_diagnostic_record=$(cat \
                "$restart_initial_start_diagnostic_file") || return 1
            restart_initial_start_diagnostic_prefix=VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=
            case $restart_initial_start_diagnostic_record in
                "$restart_initial_start_diagnostic_prefix"*)
                    restart_initial_start_diagnostic_stage=${restart_initial_start_diagnostic_record#"$restart_initial_start_diagnostic_prefix"}
                    ;;
                *) restart_initial_start_diagnostic_stage= ;;
            esac
            if production_start_failure_stage_is_safe \
                "$restart_initial_start_diagnostic_stage" \
                && printf '%s%s\n' \
                    "$restart_initial_start_diagnostic_prefix" \
                    "$restart_initial_start_diagnostic_stage" \
                    | cmp -s - "$restart_initial_start_diagnostic_file"; then
                printf 'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_START_V1=%s\n' \
                    "$restart_initial_start_diagnostic_stage" >&2
            fi
        fi
    fi
    printf 'VOLPAROSSA_HELPER_LIVE_RESTART_INITIAL_FAILURE_DRIVER_V1=%s\n' \
        "$restart_initial_driver_failure_stage" >&2
}

production_functional_probe_failure_value_is_safe() {
    [ "$#" -eq 1 ] || return 1
    production_functional_failure_value=$1
    production_functional_failure_phase=${production_functional_failure_value%%,*}
    production_functional_failure_class=${production_functional_failure_value#*,}
    [ "$production_functional_failure_value" = \
        "$production_functional_failure_phase,$production_functional_failure_class" ] \
        || return 1
    case $production_functional_failure_phase in
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
    case $production_functional_failure_class in
        random|protocol|io|timeout|untrusted|correlation|unexpected-response)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_production_launch_diagnostic() {
    [ "${proof_failure_reason:-}" = production-launch-status ] || return 1
    production_start_failure_file=$temporary_stage/production-output/start.failure
    vp_capture_file_is_safe "$production_start_failure_file" || return 1
    [ ! -e "$temporary_stage/production-output/start.pass" ] \
        && [ ! -L "$temporary_stage/production-output/start.pass" ] || return 1
    production_start_failure_record=$(cat "$production_start_failure_file") \
        || return 1
    production_start_failure_prefix=VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=
    case $production_start_failure_record in
        "$production_start_failure_prefix"*)
            production_start_failure_stage=${production_start_failure_record#"$production_start_failure_prefix"}
            ;;
        *) return 1 ;;
    esac
    production_start_failure_stage_is_safe "$production_start_failure_stage" \
        || return 1
    printf '%s%s\n' "$production_start_failure_prefix" \
        "$production_start_failure_stage" \
        | cmp -s - "$production_start_failure_file" || return 1
    production_functional_failure_file=$temporary_stage/production-output/functional-client-lease.failure
    [ ! -e "$production_functional_failure_file.next" ] \
        && [ ! -L "$production_functional_failure_file.next" ] || return 1
    production_functional_failure_value=
    if [ -e "$production_functional_failure_file" ] \
        || [ -L "$production_functional_failure_file" ]; then
        case $production_start_failure_stage in
            functional-probe-wait|functional-client-release|functional-exit-release|\
            functional-probe-finish) ;;
            *) return 1 ;;
        esac
        vp_capture_file_is_safe "$production_functional_failure_file" || return 1
        production_functional_failure_size=$(stat -Lc '%s' \
            "$production_functional_failure_file" 2>/dev/null) || return 1
        [ "$production_functional_failure_size" -ge 1 ] \
            && [ "$production_functional_failure_size" -le 128 ] || return 1
        production_functional_failure_record=$(cat \
            "$production_functional_failure_file") || return 1
        production_functional_failure_prefix=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=
        case $production_functional_failure_record in
            "$production_functional_failure_prefix"*)
                production_functional_failure_value=${production_functional_failure_record#"$production_functional_failure_prefix"}
                ;;
            *) return 1 ;;
        esac
        production_functional_probe_failure_value_is_safe \
            "$production_functional_failure_value" || return 1
        production_functional_failure_expected=$production_functional_failure_prefix$production_functional_failure_value
        [ "$production_functional_failure_record" = \
            "$production_functional_failure_expected" ] || return 1
        production_functional_failure_expected_size=$((
            ${#production_functional_failure_expected} + 1
        ))
        [ "$production_functional_failure_size" -eq \
            "$production_functional_failure_expected_size" ] || return 1
    fi
    printf 'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=%s\n' \
        "$production_start_failure_stage" >&2
    if [ -n "$production_functional_failure_value" ]; then
        printf 'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=%s\n' \
            "$production_functional_failure_value" >&2
    fi
}

driver_phase_is_safe() {
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

report_unexpected_driver_phase() {
    [ "$#" -eq 1 ] || return 1
    driver_phase_is_safe "$1" || return 1
    printf 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=%s\n' "$1" >&2
}

final_checkpoint_is_safe() {
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

report_unexpected_final_checkpoint() {
    [ "$#" -eq 1 ] || return 1
    final_checkpoint_is_safe "$1" || return 1
    printf 'VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=%s\n' "$1" >&2
}

if [ "$(id -u)" -ne 0 ]; then
    blocked 'execution requires root inside the disposable VM'
fi
if [ ! -r /etc/os-release ]; then
    blocked 'operating-system identity is unavailable'
fi
os_id=$(sed -n 's/^ID=//p' /etc/os-release)
os_version_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release)
if [ "$os_id" != debian ] \
    || { [ "$os_version_id" != 13 ] && [ "$os_version_id" != '"13"' ]; }; then
    blocked 'execution requires Debian 13'
fi
if ! command -v dpkg >/dev/null 2>&1 \
    || [ "$(dpkg --print-architecture)" != amd64 ] \
    || [ "$(uname -m)" != x86_64 ]; then
    blocked 'execution requires Debian 13 amd64 on x86_64'
fi
if [ ! -d /run/systemd/system ] || [ ! -r /proc/1/comm ] \
    || [ "$(sed -n '1p' /proc/1/comm)" != systemd ]; then
    blocked 'PID 1 is not the system systemd manager'
fi
if systemd-detect-virt --container --quiet; then
    blocked 'containers cannot provide the required disposable-host evidence'
fi
if ! systemd-detect-virt --vm --quiet; then
    blocked 'execution is restricted to a recognised disposable virtual machine'
fi

for command_name in \
    awk base64 busctl cat chmod chown cmp cp date dd dpkg find flock gdb getent git id install ip jq mkfifo mktemp mv nft nm \
    nsenter paste ping prlimit readlink rm sed setpriv sha256sum sleep sort stat systemctl \
    systemd-detect-virt systemd-run tc timeout tr uname wc wg
do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        blocked "required Debian tool is unavailable: $command_name"
    fi
done
busctl_path=/usr/bin/busctl
if [ "$(command -v busctl)" != "$busctl_path" ] \
    || [ ! -f "$busctl_path" ] || [ ! -x "$busctl_path" ] \
    || [ -L "$busctl_path" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$busctl_path" 2>/dev/null || true)" \
        != 'regular file:0:0:755:1' ]; then
    blocked 'the fixed root-owned systemd bus client is unavailable'
fi
setpriv_path=/usr/bin/setpriv
if [ "$(command -v setpriv)" != "$setpriv_path" ] \
    || [ ! -f "$setpriv_path" ] || [ ! -x "$setpriv_path" ] \
    || [ -L "$setpriv_path" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$setpriv_path" 2>/dev/null || true)" \
        != 'regular file:0:0:755:1' ]; then
    blocked 'the fixed root-owned setpriv credential trampoline is unavailable'
fi
systemd_version_output=$(systemctl show --property=Version --value 2>/dev/null) \
    || blocked 'the systemd manager version is unavailable'
systemd_version=$(printf '%s\n' "$systemd_version_output" \
    | sed -n '1{s/^\([0-9][0-9]*\).*$/\1/p;q;}')
if [ "$systemd_version" != 257 ]; then
    blocked 'execution requires exact systemd v257'
fi
manager_state=$(systemctl is-system-running 2>/dev/null || true)
case $manager_state in
    running|degraded) ;;
    *) blocked 'the system systemd manager is not operational' ;;
esac
resolver_runtime_uid=$(id -u systemd-resolve 2>/dev/null) \
    || blocked 'the systemd-resolved service UID is unavailable'
resolver_runtime_gid=$(id -g systemd-resolve 2>/dev/null) \
    || blocked 'the systemd-resolved service GID is unavailable'
case $resolver_runtime_uid in
    ''|0|0*|*[!0-9]*) blocked 'the systemd-resolved service UID is non-canonical' ;;
esac
case $resolver_runtime_gid in
    ''|0|0*|*[!0-9]*) blocked 'the systemd-resolved service GID is non-canonical' ;;
esac
system_bus_socket=/run/dbus/system_bus_socket
if [ ! -S "$system_bus_socket" ] || [ -L "$system_bus_socket" ] \
    || [ "$(stat -Lc '%F:%u:%g' "$system_bus_socket" 2>/dev/null || true)" \
        != 'socket:0:0' ]; then
    blocked 'the canonical root-owned system bus socket is unavailable'
fi
notify_socket=/run/systemd/notify
if [ ! -S "$notify_socket" ] || [ -L "$notify_socket" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$notify_socket" 2>/dev/null || true)" \
        != 'socket:0:0:777:1' ]; then
    blocked 'the canonical root-owned systemd notify socket is unavailable'
fi
host_runtime_directory=/run/volparossa
if [ -e "$host_runtime_directory" ] || [ -L "$host_runtime_directory" ]; then
    blocked 'the disposable host /run/volparossa path must initially be absent'
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
evidence_validator=$script_directory/validate-helper-boundary-evidence-v1.sh
if [ ! -f "$evidence_validator" ] || [ ! -x "$evidence_validator" ] \
    || [ -L "$evidence_validator" ] \
    || [ "$(stat -Lc '%F:%h' "$evidence_validator" 2>/dev/null || true)" != 'regular file:1' ]; then
    blocked 'the helper-boundary evidence validator is not one executable regular file'
fi
restart_evidence_validator=$script_directory/validate-helper-restart-exact-present-evidence-v1.sh
if [ ! -f "$restart_evidence_validator" ] || [ ! -x "$restart_evidence_validator" ] \
    || [ -L "$restart_evidence_validator" ] \
    || [ "$(stat -Lc '%F:%h' "$restart_evidence_validator" 2>/dev/null || true)" \
        != 'regular file:1' ]; then
    blocked 'the restart evidence validator is not one executable regular file'
fi
may_own_evidence_validator=$script_directory/validate-helper-restart-may-own-custody-relay-evidence-v1.sh
if [ ! -f "$may_own_evidence_validator" ] || [ ! -x "$may_own_evidence_validator" ] \
    || [ -L "$may_own_evidence_validator" ] \
    || [ "$(stat -Lc '%F:%h' "$may_own_evidence_validator" 2>/dev/null || true)" \
        != 'regular file:1' ]; then
    blocked 'the MayOwn Relay evidence validator is not one executable regular file'
fi
debugger_path=/usr/bin/gdb
if [ "$(command -v gdb)" != "$debugger_path" ] \
    || [ ! -f "$debugger_path" ] || [ ! -x "$debugger_path" ] \
    || [ -L "$debugger_path" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$debugger_path" 2>/dev/null || true)" \
        != 'regular file:0:0:755:1' ]; then
    blocked 'the fixed root-owned debugger is unavailable'
fi
debugger_digest=
repository_root=$(git -c safe.directory="$repository_directory" -C "$repository_directory" \
    rev-parse --show-toplevel 2>/dev/null) \
    || blocked 'the repository root cannot be established'
if [ "$repository_root" != "$repository_directory" ]; then
    blocked 'the live proof is not running from the exact repository root'
fi
source_commit=$(git -c safe.directory="$repository_directory" -C "$repository_directory" \
    rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
    || blocked 'the source commit cannot be established'
case ${#source_commit} in
    40|64) ;;
    *) blocked 'the source commit is not a canonical Git revision' ;;
esac
case $source_commit in
    *[!0-9a-f]*|0000000000000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000)
        blocked 'the source commit is not a canonical Git revision'
        ;;
esac
source_status=$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$repository_directory" \
    -C "$repository_directory" status --porcelain=v1 --untracked-files=normal \
    --ignore-submodules=none 2>/dev/null) \
    || blocked 'the source worktree state cannot be established'
if [ -n "$source_status" ]; then
    blocked 'the source worktree must be clean before live evidence execution'
fi
kernel_release=$(uname -r) || blocked 'the kernel release cannot be established'
virtualization=vm
case $kernel_release in
    ''|*[!A-Za-z0-9._+~-]*) blocked 'the kernel release is not bounded ASCII metadata' ;;
esac
case $kernel_release in
    [A-Za-z0-9]*) ;;
    *) blocked 'the kernel release is not bounded ASCII metadata' ;;
esac
if [ "${#kernel_release}" -gt 128 ] || [ "${#virtualization}" -gt 64 ]; then
    blocked 'the execution environment metadata exceeds its fixed bound'
fi
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
    || blocked 'the execution start time cannot be established'
VP_CAPTURE_OWNER_UID=0
VP_CAPTURE_OWNER_GID=0
VP_CAPTURE_RESOLVER_DIAGNOSTICS=yes
export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID VP_CAPTURE_RESOLVER_DIAGNOSTICS
# shellcheck source=tests/helper/lib/live-worker-proof-capture.sh
. "$script_directory/lib/live-worker-proof-capture.sh"
debugger_digest=$(vp_capture_sha256_file "$debugger_path") \
    || blocked 'the fixed debugger could not be hashed'

resolver_authority_record() {
    [ "$#" -eq 0 ] || return 1
    resolver_uid_before=$(id -u systemd-resolve 2>/dev/null) || return 1
    resolver_gid_before=$(id -g systemd-resolve 2>/dev/null) || return 1
    [ "$resolver_uid_before:$resolver_gid_before" = \
        "$resolver_runtime_uid:$resolver_runtime_gid" ] || return 1

    resolver_unit_raw=$(systemctl show systemd-resolved.service --no-pager \
        --property=LoadState --property=ActiveState --property=SubState \
        --property=User --property=Group --property=DynamicUser \
        --property=RuntimeDirectory --property=RuntimeDirectoryMode \
        --property=MainPID --property=InvocationID 2>/dev/null) || return 1
    [ "${#resolver_unit_raw}" -le 4096 ] || return 1
    resolver_unit_record=$(printf '%s\n' "$resolver_unit_raw" | awk -F= \
        -v expected_uid="$resolver_runtime_uid" \
        -v expected_gid="$resolver_runtime_gid" '
        function reject() { failed = 1; exit }
        {
            separator = index($0, "=")
            if (separator == 0) reject()
            key = substr($0, 1, separator - 1)
            value = substr($0, separator + 1)
            if (seen[key]++) reject()
            if (key == "LoadState") {
                if (value != "loaded") reject()
            } else if (key == "ActiveState") {
                if (value != "active") reject()
            } else if (key == "SubState") {
                if (value != "running") reject()
            } else if (key == "User") {
                if (value != "systemd-resolve") reject()
            } else if (key == "Group") {
                if (value != "") reject()
            } else if (key == "DynamicUser") {
                if (value != "no") reject()
            } else if (key == "RuntimeDirectory") {
                if (value != "systemd/resolve") reject()
            } else if (key == "RuntimeDirectoryMode") {
                if (value != "0755") reject()
            } else if (key == "MainPID") {
                if (value !~ /^[1-9][0-9]*$/) reject()
            } else if (key == "InvocationID") {
                if (length(value) != 32 || value !~ /^[0-9a-f]+$/ \
                    || value == "00000000000000000000000000000000") reject()
            } else {
                reject()
            }
            values[key] = value
            count++
        }
        END {
            if (failed || count != 10 \
                || values["LoadState"] != "loaded" \
                || values["ActiveState"] != "active" \
                || values["SubState"] != "running" \
                || values["User"] != "systemd-resolve" \
                || values["Group"] != "" \
                || values["DynamicUser"] != "no" \
                || values["RuntimeDirectory"] != "systemd/resolve" \
                || values["RuntimeDirectoryMode"] != "0755") exit 1
            print "LoadState=" values["LoadState"]
            print "ActiveState=" values["ActiveState"]
            print "SubState=" values["SubState"]
            print "User=" values["User"]
            print "Group=" values["Group"]
            print "DynamicUser=" values["DynamicUser"]
            print "RuntimeDirectory=" values["RuntimeDirectory"]
            print "RuntimeDirectoryMode=" values["RuntimeDirectoryMode"]
            print "MainPID=" values["MainPID"]
            print "InvocationID=" values["InvocationID"]
            print "RuntimeUID=" expected_uid
            print "RuntimeGID=" expected_gid
        }
    ') || return 1
    resolver_main_pid=$(printf '%s\n' "$resolver_unit_record" \
        | sed -n 's/^MainPID=//p') || return 1
    case $resolver_main_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    resolver_process_uids=$(awk '
        $1 == "Uid:" && NF == 5 { print $2 ":" $3 ":" $4 ":" $5 }
    ' "/proc/$resolver_main_pid/status" 2>/dev/null) || return 1
    resolver_process_gids=$(awk '
        $1 == "Gid:" && NF == 5 { print $2 ":" $3 ":" $4 ":" $5 }
    ' "/proc/$resolver_main_pid/status" 2>/dev/null) || return 1
    [ "$resolver_process_uids" = \
        "$resolver_runtime_uid:$resolver_runtime_uid:$resolver_runtime_uid:$resolver_runtime_uid" ] \
        || return 1
    [ "$resolver_process_gids" = \
        "$resolver_runtime_gid:$resolver_runtime_gid:$resolver_runtime_gid:$resolver_runtime_gid" ] \
        || return 1
    [ "$(cat "/proc/$resolver_main_pid/comm" 2>/dev/null)" = systemd-resolve ] \
        || return 1
    resolver_uid_after=$(id -u systemd-resolve 2>/dev/null) || return 1
    resolver_gid_after=$(id -g systemd-resolve 2>/dev/null) || return 1
    [ "$resolver_uid_before:$resolver_gid_before" = \
        "$resolver_uid_after:$resolver_gid_after" ] || return 1
    printf '%s\n' "$resolver_unit_record"
}

resolver_object_contract_is_exact() {
    [ "$(stat -c '%F:%u:%g:%a:%h' /etc/resolv.conf 2>/dev/null)" = \
        'symbolic link:0:0:777:1' ] \
        && [ "$(readlink -- /etc/resolv.conf 2>/dev/null)" = \
            '../run/systemd/resolve/stub-resolv.conf' ] \
        && [ "$(readlink -f -- /etc/resolv.conf 2>/dev/null)" = \
            '/run/systemd/resolve/stub-resolv.conf' ]
}

resolver_state_producer() {
    [ "$#" -eq 2 ] || return 1
    vp_capture_file_is_safe "$1" && vp_capture_file_is_safe "$2" || return 1
    cat "$1" "$2"
}

quiet_jq() {
    [ "$#" -ge 1 ] || return 1
    jq "$@" 2>/dev/null
}

link_state_producer() {
    [ "$#" -eq 0 ] || return 1
    quiet_jq -S -c -s '
        if (length == 1 and (.[0] | type) == "array") then .[0]
        else error("link input must contain exactly one array") end
        | if all(.[]; type == "object") then .
          else error("link array entries must be objects") end
        | map(del(.operstate,.link_netnsid,.promiscuity,.allmulti,.stats,.stats64)
            | if has("flags") then
                if ((.flags | type) == "array"
                    and all(.flags[]; type == "string")) then
                    .flags |= (map(select(. != "LOWER_UP" and . != "RUNNING"
                        and . != "DORMANT" and . != "NO-CARRIER")) | sort)
                else error("link flags must be a string array") end
              else .flags = [] end
            | if has("altnames") then
                if ((.altnames | type) == "array"
                    and all(.altnames[]; type == "string")) then
                    .altnames |= sort
                else error("link altnames must be a string array") end
              else . end)
        | sort_by(.ifindex,.ifname)
    '
}

address_state_producer() {
    [ "$#" -eq 0 ] || return 1
    quiet_jq -S -c -s '
        if (length == 1 and (.[0] | type) == "array") then .[0]
        else error("address input must contain exactly one array") end
        | if all(.[]; type == "object") then .
          else error("address array entries must be objects") end
        | map(if has("addr_info") then
                if ((.addr_info | type) == "array"
                    and all(.addr_info[]; type == "object")) then .
                else error("addr_info must be an object array") end
              else .addr_info = [] end
            | {ifindex,ifname,addr_info:(.addr_info
                | map(del(.valid_life_time,.preferred_life_time,.valid_lft,
                    .preferred_lft,.tstamp,.cstamp,.tentative,.dadfailed,.deprecated,
                    .optimistic))
                | sort_by(.family,.local,(.peer // ""),.prefixlen,.scope,(.label // "")))})
        | sort_by(.ifindex,.ifname)
    '
}

route_state_producer() {
    [ "$#" -eq 2 ] || return 1
    # The jq program, not the shell, expands its slurpfile variables.
    # shellcheck disable=SC2016
    quiet_jq -S -c -n --slurpfile v4 "$1" --slurpfile v6 "$2" '
        def tag_family($records; $expected):
            if all($records[];
                if type != "object" then false
                elif has("family") then .family == $expected
                else true end)
            then ($records | map(.family = $expected))
            else error("route entries have invalid address-family provenance") end;
        if (($v4 | length) == 1 and ($v4[0] | type) == "array"
            and ($v6 | length) == 1 and ($v6[0] | type) == "array") then
            tag_family($v4[0]; "inet") + tag_family($v6[0]; "inet6")
        else error("route inputs must each contain exactly one array") end
        | walk(if type == "object" then
            del(.expires,.used,.age,.lastuse,.users,.cache,.statistics)
            | if has("flags") then
                if (.flags | type) != "array" then
                    error("route flags must be a string array")
                elif all(.flags[]; type == "string") then
                    .flags |= (map(select(. != "linkdown" and . != "dead" and . != "offload"
                        and . != "trap" and . != "unresolved")) | sort)
                else error("route flags must be a string array") end
              else . end
          else . end)
        | sort_by((.family // ""),(.table // ""|tostring),(.dst // ""),(.src // ""),
            (.metric // 0),(.protocol // ""),(.dev // ""),(.gateway // ""))
    '
}

rule_state_producer() {
    [ "$#" -eq 2 ] || return 1
    # The jq program, not the shell, expands its slurpfile variables.
    # shellcheck disable=SC2016
    quiet_jq -S -c -n --slurpfile v4 "$1" --slurpfile v6 "$2" '
        def tag_family($records; $expected):
            if all($records[];
                if type != "object" then false
                elif has("family") then .family == $expected
                else true end)
            then ($records | map(.family = $expected))
            else error("rule entries have invalid address-family provenance") end;
        if (($v4 | length) == 1 and ($v4[0] | type) == "array"
            and ($v6 | length) == 1 and ($v6[0] | type) == "array") then
            tag_family($v4[0]; "inet") + tag_family($v6[0]; "inet6")
        else error("rule inputs must each contain exactly one array") end
        | sort_by(.family,.priority,(.table // ""|tostring),
            (.src // ""),(.dst // ""))
    '
}

nexthop_state_producer() {
    [ "$#" -eq 0 ] || return 1
    quiet_jq -S -c -s '
        if (length == 1 and (.[0] | type) == "array") then .[0]
        else error("nexthop input must contain exactly one array") end
        | if all(.[]; type == "object") then .
          else error("nexthop array entries must be objects") end
        | walk(if type == "object" then del(.used,.age,.lastuse,.statistics)
            | if has("flags") then
                if (.flags | type) != "array" then
                    error("nexthop flags must be a string array")
                elif all(.flags[]; type == "string") then
                    .flags |= (map(select(. != "offload" and . != "trap")) | sort)
                else error("nexthop flags must be a string array") end
              else . end else . end)
        | sort_by(.id,(.dev // ""),(.via // ""|tostring))
    '
}

qdisc_state_producer() {
    [ "$#" -eq 0 ] || return 1
    quiet_jq -S -c -s '
        if (length == 1 and (.[0] | type) == "array") then .[0]
        else error("qdisc input must contain exactly one array") end
        | if all(.[]; type == "object") then .
          else error("qdisc array entries must be objects") end
        | walk(if type == "object" then
            del(.refcnt,.bytes,.packets,.drops,.overlimits,.requeues,.backlog,.qlen,
                .direct_packets_stat,.xstats) else . end)
        | sort_by(.dev,(.parent // ""),(.handle // ""),.kind)
    '
}

nftables_state_producer() {
    [ "$#" -eq 0 ] || return 1
    quiet_jq -S -c -s '
        if (length == 1 and (.[0] | type) == "object"
            and (.[0] | has("nftables")) and (.[0].nftables | type) == "array"
            and all(.[0].nftables[]; type == "object")) then .[0]
        else error("nftables input must contain one object-entry array") end
        | walk(if type == "object" then
            if has("counter") then .counter |= del(.packets,.bytes) else . end
            | del(.expires,.last,.used) else . end)
    '
}

# Capture the kernel-owned registration inventory for one legacy xtables
# address family.  An absent proc record, an initialized family with no
# tables, and a non-empty table inventory are deliberately distinct states.
# The path and expected metadata are parameters so the unprivileged contract
# test can exercise this parser without consulting the host network namespace.
legacy_firewall_inventory_producer() {
    [ "$#" -eq 4 ] || return 1
    legacy_inventory_path=$1
    legacy_inventory_uid=$2
    legacy_inventory_gid=$3
    legacy_inventory_mode=$4
    case $legacy_inventory_path in
        /*) ;;
        *) return 1 ;;
    esac
    case $legacy_inventory_uid in
        ''|*[!0-9]*|0[0-9]*) return 1 ;;
    esac
    case $legacy_inventory_gid in
        ''|*[!0-9]*|0[0-9]*) return 1 ;;
    esac
    case $legacy_inventory_mode in
        [0-7][0-7][0-7]) ;;
        *) return 1 ;;
    esac

    if [ ! -e "$legacy_inventory_path" ] && [ ! -L "$legacy_inventory_path" ]; then
        [ ! -e "$legacy_inventory_path" ] && [ ! -L "$legacy_inventory_path" ] \
            || return 1
        printf '%s\n' PROC_ABSENT
        return 0
    fi
    [ -f "$legacy_inventory_path" ] && [ ! -L "$legacy_inventory_path" ] \
        && [ -r "$legacy_inventory_path" ] || return 1
    legacy_inventory_metadata_before=$(stat -Lc '%F:%u:%g:%a:%h:%d:%i' \
        "$legacy_inventory_path" 2>/dev/null) || return 1
    case $legacy_inventory_metadata_before in
        "regular file:$legacy_inventory_uid:$legacy_inventory_gid:$legacy_inventory_mode:1:"*|\
        "regular empty file:$legacy_inventory_uid:$legacy_inventory_gid:$legacy_inventory_mode:1:"*)
            ;;
        *) return 1 ;;
    esac
    legacy_inventory_records=$(awk 'END { print NR }' \
        "$legacy_inventory_path" 2>/dev/null) || return 1
    legacy_inventory_newlines=$(wc -l <"$legacy_inventory_path" 2>/dev/null) \
        || return 1
    case $legacy_inventory_records:$legacy_inventory_newlines in
        *[!0-9:]*|:|*:|*:*:*) return 1 ;;
    esac
    [ "$legacy_inventory_records" = "$legacy_inventory_newlines" ] || return 1

    awk '
        BEGIN { count = 0; bytes = 0; bad = 0 }
        {
            if (length($0) < 1 || length($0) > 31 ||
                $0 !~ /^[-A-Za-z0-9_.+]+$/ || seen[$0]++) {
                bad = 1
                exit
            }
            count++
            bytes += length($0) + 1
            if (count > 64 || bytes > 4096) {
                bad = 1
                exit
            }
            table[count] = $0
        }
        END {
            if (bad) exit 1
            if (count == 0) {
                print "NO_TABLES"
            } else {
                print "PRESENT"
                for (position = 1; position <= count; position++)
                    print table[position]
            }
        }
    ' "$legacy_inventory_path" 2>/dev/null || return 1

    legacy_inventory_metadata_after=$(stat -Lc '%F:%u:%g:%a:%h:%d:%i' \
        "$legacy_inventory_path" 2>/dev/null) || return 1
    [ "$legacy_inventory_metadata_before" = "$legacy_inventory_metadata_after" ]
}

# The caller supplies a code-pinned absolute legacy binary.  Keeping the
# producer generic permits a fixture executable in the contract test; the two
# production call sites below are statically pinned to Debian's explicit
# legacy binaries.  Suppress all tool diagnostics so only fixed gate labels
# can escape into the evidence log.
legacy_firewall_save_producer() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        /*) ;;
        *) return 1 ;;
    esac
    legacy_save_tool=$1
    legacy_save_owner_uid=$(id -u 2>/dev/null) || return 1
    legacy_save_owner_gid=$(id -g 2>/dev/null) || return 1
    legacy_save_link_before=$(stat -c '%F:%u:%g:%a:%h:%d:%i' \
        "$legacy_save_tool" 2>/dev/null) || return 1
    case $legacy_save_link_before in
        "regular file:$legacy_save_owner_uid:$legacy_save_owner_gid:"*|\
        "symbolic link:$legacy_save_owner_uid:$legacy_save_owner_gid:"*) ;;
        *) return 1 ;;
    esac
    legacy_save_target_before=$(readlink -f -- "$legacy_save_tool" 2>/dev/null) \
        || return 1
    case $legacy_save_target_before in /*) ;; *) return 1 ;; esac
    case $legacy_save_tool in
        /usr/sbin/iptables-legacy-save|/usr/sbin/ip6tables-legacy-save)
            case $legacy_save_link_before in
                "symbolic link:0:0:777:1:"*) ;;
                *) return 1 ;;
            esac
            [ "$(stat -Lc '%F:%u:%g:%a' /usr/sbin 2>/dev/null)" = \
                'directory:0:0:755' ] || return 1
            [ "$(readlink -- "$legacy_save_tool" 2>/dev/null)" = xtables-legacy-multi ] \
                || return 1
            [ "$legacy_save_target_before" = /usr/sbin/xtables-legacy-multi ] \
                || return 1
            ;;
    esac
    legacy_save_target_metadata_before=$(stat -Lc '%F:%u:%g:%a:%h:%d:%i' \
        "$legacy_save_tool" 2>/dev/null) || return 1
    legacy_save_target_digest_before=$(vp_capture_sha256_file \
        "$legacy_save_target_before" 2>/dev/null) || return 1
    legacy_save_target_mode=$(stat -Lc '%a' "$legacy_save_tool" 2>/dev/null) \
        || return 1
    case $legacy_save_target_metadata_before in
        "regular file:$legacy_save_owner_uid:$legacy_save_owner_gid:$legacy_save_target_mode:1:"*) ;;
        *) return 1 ;;
    esac
    vp_capture_mode_is_not_group_or_world_writable "$legacy_save_target_mode" \
        && [ -x "$legacy_save_tool" ] || return 1

    if "$legacy_save_tool" -M /bin/false 2>/dev/null; then
        legacy_save_status=0
    else
        legacy_save_status=$?
    fi
    legacy_save_link_after=$(stat -c '%F:%u:%g:%a:%h:%d:%i' \
        "$legacy_save_tool" 2>/dev/null) || return 1
    legacy_save_target_after=$(readlink -f -- "$legacy_save_tool" 2>/dev/null) \
        || return 1
    legacy_save_target_metadata_after=$(stat -Lc '%F:%u:%g:%a:%h:%d:%i' \
        "$legacy_save_tool" 2>/dev/null) || return 1
    legacy_save_target_digest_after=$(vp_capture_sha256_file \
        "$legacy_save_target_after" 2>/dev/null) || return 1
    [ "$legacy_save_status" -eq 0 ] \
        && [ "$legacy_save_link_before" = "$legacy_save_link_after" ] \
        && [ "$legacy_save_target_before" = "$legacy_save_target_after" ] \
        && [ "$legacy_save_target_metadata_before" = \
            "$legacy_save_target_metadata_after" ] \
        && [ "$legacy_save_target_digest_before" = \
            "$legacy_save_target_digest_after" ]
}

# Remove only producer-owned timestamps and policy-chain counters.  In
# particular, bracketed text in a rule or comment remains semantic input.
legacy_firewall_save_normalizer() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ipv4) legacy_save_program=iptables-save ;;
        ipv6) legacy_save_program=ip6tables-save ;;
        *) return 1 ;;
    esac
    awk -v program="$legacy_save_program" '
        BEGIN {
            generated = 0
            completed = 0
            tables = 0
            commits = 0
            in_table = 0
            table_seen = 0
            commit_seen = 0
            bad = 0
            ctime = "(Sun|Mon|Tue|Wed|Thu|Fri|Sat) " \
                "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) " \
                "( [1-9]|[12][0-9]|3[01]) " \
                "([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] " \
                "[0-9][0-9][0-9][0-9]"
        }
        index($0, "# Generated by ") == 1 {
            # Debian iptables-save.c formats PACKAGE_VERSION here; unlike the
            # multi-call binary --version output, this header has no backend
            # suffix.  Exact legacy authority is established by the tool pin.
            pattern = "^# Generated by " program \
                " v[0-9][0-9A-Za-z.+:~_-]* on " ctime "$"
            if (in_table || $0 !~ pattern) {
                bad = 1
                exit
            }
            generated++
            in_table = 1
            table_seen = 0
            commit_seen = 0
            next
        }
        index($0, "# Completed on ") == 1 {
            if (!in_table || !table_seen || !commit_seen ||
                $0 !~ ("^# Completed on " ctime "$")) {
                bad = 1
                exit
            }
            completed++
            in_table = 0
            next
        }
        /^#/ {
            bad = 1
            exit
        }
        /^\*/ {
            if (!in_table || table_seen || commit_seen ||
                $0 !~ /^\*[-A-Za-z0-9_.+]+$/ || length($0) > 32) {
                bad = 1
                exit
            }
            table_seen = 1
            tables++
            print
            next
        }
        /^:/ {
            if (!in_table || !table_seen || commit_seen ||
                $0 !~ / \[[0-9]+:[0-9]+\]$/) {
                bad = 1
                exit
            }
            sub(/ \[[0-9]+:[0-9]+\]$/, " [COUNTERS]")
            print
            next
        }
        $0 == "COMMIT" {
            if (!in_table || !table_seen || commit_seen) {
                bad = 1
                exit
            }
            commit_seen = 1
            commits++
            print
            next
        }
        {
            if (!in_table || !table_seen || commit_seen || length($0) == 0) {
                bad = 1
                exit
            }
            print
        }
        END {
            if (bad || in_table || generated == 0 ||
                generated != completed || generated != tables ||
                generated != commits) exit 1
        }
    ' 2>/dev/null
}

# Join a canonical inventory with its stable normalized dump.  Only this
# joined private capture is hashed into the published host-state record.
legacy_firewall_join_producer() {
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || return 1
    legacy_join_inventory=$1
    vp_capture_file_is_safe "$legacy_join_inventory" || return 1
    awk '
        NR == 1 {
            marker = $0
            if (marker != "PROC_ABSENT" && marker != "NO_TABLES" &&
                marker != "PRESENT") exit 1
            next
        }
        {
            if (marker != "PRESENT" || length($0) < 1 || length($0) > 31 ||
                $0 !~ /^[-A-Za-z0-9_.+]+$/ || seen[$0]++) exit 1
            names++
        }
        END {
            if (NR < 1 || (marker == "PRESENT" && names < 1) ||
                (marker != "PRESENT" && NR != 1)) exit 1
        }
    ' "$legacy_join_inventory" 2>/dev/null || return 1
    legacy_join_marker=$(sed -n '1p' "$legacy_join_inventory") || return 1
    if [ "$legacy_join_marker" = PRESENT ]; then
        [ "$#" -eq 2 ] || return 1
        vp_capture_file_is_safe "$2" && [ -s "$2" ] || return 1
        awk '
            FNR == NR {
                if (FNR == 1) {
                    if ($0 != "PRESENT") bad = 1
                    next
                }
                if (inventory[$0]++) bad = 1
                inventory_count++
                next
            }
            /^\*/ {
                name = substr($0, 2)
                if (dump[name]++) bad = 1
                dump_count++
            }
            END {
                if (bad || inventory_count < 1 ||
                    inventory_count != dump_count) exit 1
                for (name in inventory)
                    if (!(name in dump)) exit 1
                for (name in dump)
                    if (!(name in inventory)) exit 1
            }
        ' "$legacy_join_inventory" "$2" 2>/dev/null || return 1
    else
        [ "$#" -eq 1 ] || return 1
    fi
    cat "$legacy_join_inventory" 2>/dev/null || return 1
    if [ "$legacy_join_marker" = PRESENT ]; then
        cat "$2" 2>/dev/null || return 1
    fi
}

# Obtain two identical inventory observations and, when legacy tables exist,
# two identical normalized all-table dumps.  A subshell-local EXIT trap removes
# every intermediate and any failed stable output on all error paths.
capture_stable_legacy_firewall_state() (
    [ "$#" -eq 8 ] || return 1
    legacy_stable_family=$1
    legacy_stable_inventory_path=$2
    legacy_stable_uid=$3
    legacy_stable_gid=$4
    legacy_stable_mode=$5
    legacy_stable_tool=$6
    legacy_stable_prefix=$7
    legacy_stable_output=$8
    case $legacy_stable_family in ipv4|ipv6) ;; *) return 1 ;; esac
    for legacy_stable_path in "$legacy_stable_inventory_path" \
        "$legacy_stable_tool" "$legacy_stable_prefix" "$legacy_stable_output"
    do
        case $legacy_stable_path in
            /*) ;;
            *) return 1 ;;
        esac
        case $legacy_stable_path in
            /|*/../*|*/..|*/./*|*/.) return 1 ;;
        esac
    done

    legacy_inventory_a=$legacy_stable_prefix.inventory-a
    legacy_inventory_b=$legacy_stable_prefix.inventory-b
    legacy_raw_a=$legacy_stable_prefix.raw-a
    legacy_raw_b=$legacy_stable_prefix.raw-b
    legacy_normalized_a=$legacy_stable_prefix.normalized-a
    legacy_normalized_b=$legacy_stable_prefix.normalized-b
    for legacy_stable_path in "$legacy_inventory_a" "$legacy_inventory_b" \
        "$legacy_raw_a" "$legacy_raw_b" "$legacy_normalized_a" \
        "$legacy_normalized_b" "$legacy_stable_output"
    do
        [ ! -e "$legacy_stable_path" ] && [ ! -L "$legacy_stable_path" ] \
            || return 1
    done

    legacy_stable_success=no
    # Invoked indirectly by the EXIT trap below.
    # shellcheck disable=SC2317
    legacy_stable_cleanup() {
        rm -f -- "$legacy_inventory_a" "$legacy_inventory_b" \
            "$legacy_raw_a" "$legacy_raw_b" "$legacy_normalized_a" \
            "$legacy_normalized_b"
        if [ "$legacy_stable_success" != yes ]; then
            rm -f -- "$legacy_stable_output"
        fi
    }
    trap 'legacy_stable_cleanup' 0
    trap 'exit 1' HUP INT TERM

    vp_capture_run "$legacy_inventory_a" legacy_firewall_inventory_producer \
        "$legacy_stable_inventory_path" "$legacy_stable_uid" \
        "$legacy_stable_gid" "$legacy_stable_mode" || return 1
    legacy_stable_marker=$(sed -n '1p' "$legacy_inventory_a") || return 1
    case $legacy_stable_marker in
        PROC_ABSENT|NO_TABLES)
            ;;
        PRESENT)
            vp_capture_run "$legacy_raw_a" legacy_firewall_save_producer \
                "$legacy_stable_tool" || return 1
            vp_capture_normalize "$legacy_raw_a" "$legacy_normalized_a" \
                legacy_firewall_save_normalizer "$legacy_stable_family" || return 1
            vp_capture_run "$legacy_raw_b" legacy_firewall_save_producer \
                "$legacy_stable_tool" || return 1
            vp_capture_normalize "$legacy_raw_b" "$legacy_normalized_b" \
                legacy_firewall_save_normalizer "$legacy_stable_family" || return 1
            ;;
        *) return 1 ;;
    esac
    vp_capture_run "$legacy_inventory_b" legacy_firewall_inventory_producer \
        "$legacy_stable_inventory_path" "$legacy_stable_uid" \
        "$legacy_stable_gid" "$legacy_stable_mode" || return 1
    cmp -s "$legacy_inventory_a" "$legacy_inventory_b" || return 1

    if [ "$legacy_stable_marker" = PRESENT ]; then
        cmp -s "$legacy_normalized_a" "$legacy_normalized_b" || return 1
        vp_capture_run "$legacy_stable_output" legacy_firewall_join_producer \
            "$legacy_inventory_a" "$legacy_normalized_a" || return 1
    else
        vp_capture_run "$legacy_stable_output" legacy_firewall_join_producer \
            "$legacy_inventory_a" || return 1
    fi
    legacy_stable_success=yes
)

helper_source=$repository_directory/target/debug/volparossa-helper
ipc_probe_source=$repository_directory/target/debug/examples/volparossa-helper-production-ipc-probe
ipc_hook_source=$script_directory/lib/production-ipc-unit-hook.sh
restart_observer_source=$script_directory/lib/restart-exact-present-observer.sh
restart_launcher_source=$script_directory/lib/restart-exact-present-launcher.sh
may_own_observer_source=$script_directory/lib/restart-may-own-relay-observer.sh
staged_executable_max_bytes=134217728
proof_file_max_bytes=1048576
repository_owner_uid=$(stat -Lc '%u' "$repository_directory" 2>/dev/null) \
    || blocked 'the repository owner UID is unavailable'
repository_owner_gid=$(stat -Lc '%g' "$repository_directory" 2>/dev/null) \
    || blocked 'the repository owner GID is unavailable'
case $repository_owner_uid in
    ''|0|0*|*[!0-9]*)
        blocked 'the repository must be owned by one canonical unprivileged identity'
        ;;
esac
case $repository_owner_gid in
    ''|0|0*|*[!0-9]*)
        blocked 'the repository must be owned by one canonical unprivileged identity'
        ;;
esac

source_snapshot_is_exact() {
    [ "$#" -eq 3 ] || return 1
    source_snapshot_value=$1
    source_snapshot_mode=$2
    source_snapshot_max_bytes=$3
    saved_source_snapshot_ifs=$IFS
    IFS=:
    # The fixed stat serialization contains no glob metacharacters.
    # shellcheck disable=SC2086
    set -- $source_snapshot_value
    IFS=$saved_source_snapshot_ifs
    [ "$#" -eq 10 ] || return 1
    [ "$1" = 'regular file' ] \
        && [ "$4" = "$repository_owner_uid" ] \
        && [ "$5" = "$repository_owner_gid" ] \
        && [ "$6" = "$source_snapshot_mode" ] \
        && [ "$7" = 1 ] \
        || return 1
    case $8 in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#8}" -le 9 ] || return 1
    [ "$8" -le "$source_snapshot_max_bytes" ]
}

install_proof_file_limit() {
    [ "$#" -eq 1 ] && [ "$1" = "$proof_file_max_bytes" ] || return 1
    prlimit --pid "$$" --fsize="$1:$1" \
        || return 1
    observed_proof_fsize=$(
        prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD \
            | awk 'NF == 2 { print $1 ":" $2 }'
    ) || return 1
    [ "$observed_proof_fsize" = "$1:$1" ]
}

if [ ! -f "$helper_source" ] || [ ! -x "$helper_source" ] || [ -L "$helper_source" ]; then
    blocked 'build target/debug/volparossa-helper as an unprivileged workspace user first'
fi
helper_initial_snapshot=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$helper_source" 2>/dev/null || true)
if ! source_snapshot_is_exact \
    "$helper_initial_snapshot" 755 "$staged_executable_max_bytes"; then
    blocked 'the helper source must be one bounded workspace-owned 0755 regular file'
fi
if [ ! -f "$ipc_probe_source" ] || [ ! -x "$ipc_probe_source" ] \
    || [ -L "$ipc_probe_source" ]; then
    blocked 'build the production IPC probe as an unprivileged workspace user first'
fi
ipc_probe_initial_snapshot=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$ipc_probe_source" 2>/dev/null || true)
if ! source_snapshot_is_exact \
    "$ipc_probe_initial_snapshot" 755 "$staged_executable_max_bytes"; then
    blocked 'the production IPC probe must be one bounded workspace-owned 0755 regular file'
fi
if [ ! -f "$ipc_hook_source" ] || [ ! -x "$ipc_hook_source" ] \
    || [ -L "$ipc_hook_source" ]; then
    blocked 'the production IPC unit hook must be one executable regular file with one hard link'
fi
ipc_hook_initial_snapshot=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$ipc_hook_source" 2>/dev/null || true)
if ! source_snapshot_is_exact "$ipc_hook_initial_snapshot" 700 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$ipc_hook_initial_snapshot" 750 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$ipc_hook_initial_snapshot" 755 "$proof_file_max_bytes"; then
    blocked 'the production IPC unit hook has unsafe workspace metadata'
fi
if [ ! -f "$restart_observer_source" ] || [ ! -x "$restart_observer_source" ] \
    || [ -L "$restart_observer_source" ]; then
    blocked 'the restart observer must be one executable regular file with one hard link'
fi
restart_observer_initial_snapshot=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_observer_source" 2>/dev/null || true)
if ! source_snapshot_is_exact \
    "$restart_observer_initial_snapshot" 700 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$restart_observer_initial_snapshot" 750 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$restart_observer_initial_snapshot" 755 "$proof_file_max_bytes"; then
    blocked 'the restart observer has unsafe workspace metadata'
fi
if [ ! -f "$restart_launcher_source" ] || [ ! -x "$restart_launcher_source" ] \
    || [ -L "$restart_launcher_source" ]; then
    blocked 'the restart launcher must be one executable regular file with one hard link'
fi
restart_launcher_initial_snapshot=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_launcher_source" 2>/dev/null || true)
if ! source_snapshot_is_exact \
    "$restart_launcher_initial_snapshot" 700 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$restart_launcher_initial_snapshot" 750 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$restart_launcher_initial_snapshot" 755 "$proof_file_max_bytes"; then
    blocked 'the restart launcher has unsafe workspace metadata'
fi
if [ ! -f "$may_own_observer_source" ] || [ ! -x "$may_own_observer_source" ] \
    || [ -L "$may_own_observer_source" ]; then
    blocked 'the MayOwn Relay observer must be one executable regular file with one hard link'
fi
may_own_observer_initial_snapshot=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$may_own_observer_source" 2>/dev/null || true)
if ! source_snapshot_is_exact \
    "$may_own_observer_initial_snapshot" 700 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$may_own_observer_initial_snapshot" 750 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact \
        "$may_own_observer_initial_snapshot" 755 "$proof_file_max_bytes"; then
    blocked 'the MayOwn Relay observer has unsafe workspace metadata'
fi

if [ "$(stat -c '%F:%u:%g:%a' /var/tmp)" != 'directory:0:0:1777' ]; then
    blocked '/var/tmp is not the canonical root-owned sticky staging parent'
fi

temporary_stage=
temporary_stage_identity=
unit_name=
unit_owned=no
unit_may_own=no
unit_invocation_id=
unit_ownership_marker=
cleanup_error=no
worker_fdstore_before_retirement=
worker_retired_load_state=
production_fdstore_during_run=
production_fdstore_active_counts=
production_fdstore_settled_counts=
production_fdstore_identity_bound=
production_journal_settled_absent=
production_retired_load_state=
restart_initial_invocation_id=
restart_initial_driver_failure_stage=
restart_initial_hook_failure_stage=
restart_initial_terminal_identity=
restart_initial_after_crash_observed=no
restart_initial_hook_pid=
restart_initial_hook_starttime=
restart_successor_invocation_id=
restart_retired_load_state=
restart_evidence_validated=false
restart_mount_keeper_pid=
restart_mount_keeper_starttime=
restart_successor_debugger_pid=
restart_successor_debugger_starttime=
may_own_invocation_one=
may_own_invocation_two=
may_own_invocation_three=
may_own_retired_load_state=
may_own_evidence_validated=false
may_own_mount_keeper_pid=
may_own_mount_keeper_starttime=
may_own_debugger_pid=
may_own_debugger_starttime=
may_own_cgroup=
may_own_cgroup_frozen=no
driver_phase=staging
structured_failure_reported=no
final_checkpoint=

unit_name_is_safe() {
    case $unit_name in
        volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service)
            return 0
            ;;
        *) return 1 ;;
    esac
}

unit_invocation_id_is_safe() {
    [ "$#" -eq 1 ] || return 1
    candidate_invocation_id=$1
    [ "${#candidate_invocation_id}" -eq 32 ] || return 1
    case $candidate_invocation_id in
        *[!0-9a-f]*) return 1 ;;
        00000000000000000000000000000000) return 1 ;;
        *) return 0 ;;
    esac
}

unit_ownership_marker_is_safe() {
    [ "$#" -eq 1 ] || return 1
    candidate_ownership_marker=$1
    ownership_marker_prefix=volparossa-helper-live-proof-owner-v1-
    case $candidate_ownership_marker in
        "$ownership_marker_prefix"*) ;;
        *) return 1 ;;
    esac
    ownership_marker_digest=${candidate_ownership_marker#"$ownership_marker_prefix"}
    [ "${#ownership_marker_digest}" -eq 64 ] || return 1
    case $ownership_marker_digest in
        *[!0-9a-f]*|0000000000000000000000000000000000000000000000000000000000000000)
            return 1
            ;;
        *) return 0 ;;
    esac
}

unit_description_matches_marker() {
    unit_name_is_safe || return 1
    unit_ownership_marker_is_safe "$unit_ownership_marker" || return 1
    observed_unit_description=$(systemctl show --property=Description --value \
        "$unit_name" 2>/dev/null) || return 1
    [ "$observed_unit_description" = "$unit_ownership_marker" ]
}

unit_current_invocation_id() {
    unit_name_is_safe || return 1
    observed_unit_invocation_id=$(systemctl show --property=InvocationID --value \
        "$unit_name" 2>/dev/null) || return 1
    unit_invocation_id_is_safe "$observed_unit_invocation_id" || return 1
    printf '%s\n' "$observed_unit_invocation_id"
}

unit_invocation_is_current() {
    [ "$unit_owned" = yes ] || return 1
    unit_invocation_id_is_safe "$unit_invocation_id" || return 1
    observed_unit_invocation_id=$(unit_current_invocation_id) || return 1
    [ "$observed_unit_invocation_id" = "$unit_invocation_id" ]
}

forget_unit_ownership() {
    unit_owned=no unit_may_own=no unit_invocation_id='' \
        unit_ownership_marker='' unit_name=''
}

prepare_restart_unit_identity() {
    [ "$production_retirement_confirmed" = yes ] || return 1
    [ -z "$unit_name" ] || return 1
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = no ] || return 1
    [ -z "$unit_invocation_id" ] || return 1
    [ -z "$unit_ownership_marker" ] || return 1
    case $stage_suffix in
        [A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
        *) return 1 ;;
    esac
    case $production_unit_name in
        volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service) ;;
        *) return 1 ;;
    esac
    case $stage_suffix in
        A*) restart_identity_suffix=B${stage_suffix#?} ;;
        *) restart_identity_suffix=A${stage_suffix#?} ;;
    esac
    restart_identity_name=volparossa-helper-live-proof-$restart_identity_suffix.service
    [ "$restart_identity_name" != "$production_unit_name" ] || return 1
    unit_name=$restart_identity_name
}

restart_journal_metadata_is_exact() {
    [ "$#" -eq 2 ] || return 1
    restart_journal_metadata=$1
    restart_journal_metadata_gid=$2
    case $restart_journal_metadata_gid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#restart_journal_metadata_gid}" -le 10 ] \
        && [ "$restart_journal_metadata_gid" -le 4294967294 ] || return 1
    [ "${#restart_journal_metadata}" -le 256 ] || return 1
    printf '%s\n' "$restart_journal_metadata" | /usr/bin/awk \
        -F: -v expected_gid="$restart_journal_metadata_gid" '
        function canonical_u64(value) {
            if (value == "0") return 1
            if (value !~ /^[1-9][0-9]*$/ || length(value) > 20) return 0
            if (length(value) < 20) return 1
            return ("x" value) <= "x18446744073709551615"
        }
        function canonical_positive(value) {
            if (value !~ /^[1-9][0-9]*$/ || length(value) > 20) return 0
            if (length(value) < 20) return 1
            return ("x" value) <= "x18446744073709551615"
        }
        function canonical_size(value) {
            return (value == "0" || value ~ /^[1-9][0-9]*$/) \
                && length(value) <= 7 && value <= 1048576
        }
        function date_hour(value) {
            return value ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]$/
        }
        function seconds_zone(value) {
            return value ~ /^[0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] [+-][0-9][0-9][0-9][0-9]$/
        }
        NR != 1 { invalid = 1; next }
        {
            if (NF != 14 || !canonical_u64($1) \
                || !canonical_positive($2) || $3 != "8180" \
                || $4 != "0" || $5 != expected_gid || $6 != "600" \
                || $7 != "1" || !canonical_size($8) \
                || !date_hour($9) || $10 !~ /^[0-9][0-9]$/ \
                || !seconds_zone($11) || !date_hour($12) \
                || $13 !~ /^[0-9][0-9]$/ || !seconds_zone($14)) {
                invalid = 1
            }
        }
        END { if (invalid || NR != 1) exit 1 }
    '
}

restart_journal_digest_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "${#1}" -eq 64 ] || return 1
    case $1 in
        ''|*[!0-9a-f]*) return 1 ;;
        *) return 0 ;;
    esac
}

capture_restart_journal_state() {
    [ "$#" -eq 2 ] || return 1
    restart_journal_path=$1
    restart_journal_gid=$2
    [ "$restart_journal_path" = \
        "$temporary_stage/production-runtime/helper.ownership-v3" ] || return 1
    case $restart_journal_gid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ -f "$restart_journal_path" ] && [ ! -L "$restart_journal_path" ] \
        || return 1
    restart_journal_state_before=$(stat -c '%d:%i:%f:%u:%g:%a:%h:%s:%y:%z' \
        "$restart_journal_path" 2>/dev/null) || return 1
    restart_journal_metadata_is_exact \
        "$restart_journal_state_before" "$restart_journal_gid" || return 1
    restart_journal_digest=$(vp_capture_sha256_file \
        "$restart_journal_path") || return 1
    restart_journal_digest_is_exact "$restart_journal_digest" || return 1
    restart_journal_state_after=$(stat -c '%d:%i:%f:%u:%g:%a:%h:%s:%y:%z' \
        "$restart_journal_path" 2>/dev/null) || return 1
    [ "$restart_journal_state_after" = "$restart_journal_state_before" ] \
        || return 1
    printf 'PRESENT\n%s\n%s\n' \
        "$restart_journal_state_before" "$restart_journal_digest"
}

capture_restart_journal_state_record() {
    [ "$#" -eq 2 ] || return 1
    restart_journal_record_path=$1
    restart_journal_record_gid=$2
    [ "$restart_journal_record_path" = \
        "$temporary_stage/restart-output/restart.journal.settled.state" ] \
        || return 1
    vp_capture_file_is_safe "$restart_journal_record_path" || return 1
    [ ! -e "$restart_journal_record_path.next" ] \
        && [ ! -L "$restart_journal_record_path.next" ] || return 1
    restart_journal_record_size=$(stat -Lc '%s' \
        "$restart_journal_record_path" 2>/dev/null) || return 1
    case $restart_journal_record_size in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#restart_journal_record_size}" -le 3 ] \
        && [ "$restart_journal_record_size" -le 512 ] || return 1
    restart_journal_record_marker=$(sed -n '1p' \
        "$restart_journal_record_path") || return 1
    restart_journal_record_metadata=$(sed -n '2p' \
        "$restart_journal_record_path") || return 1
    restart_journal_record_digest=$(sed -n '3p' \
        "$restart_journal_record_path") || return 1
    [ "$restart_journal_record_marker" = PRESENT ] || return 1
    restart_journal_metadata_is_exact \
        "$restart_journal_record_metadata" "$restart_journal_record_gid" \
        || return 1
    restart_journal_digest_is_exact "$restart_journal_record_digest" || return 1
    printf 'PRESENT\n%s\n%s\n' \
        "$restart_journal_record_metadata" "$restart_journal_record_digest" \
        | cmp -s - "$restart_journal_record_path" || return 1
    printf 'PRESENT\n%s\n%s\n' \
        "$restart_journal_record_metadata" "$restart_journal_record_digest"
}

prepare_may_own_unit_identity() {
    [ "$restart_evidence_validated" = true ] || return 1
    [ -z "$unit_name" ] || return 1
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = no ] || return 1
    [ -z "$unit_invocation_id" ] || return 1
    [ -z "$unit_ownership_marker" ] || return 1
    case $stage_suffix in
        [A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
        *) return 1 ;;
    esac
    may_own_identity_suffix=C${stage_suffix#?}
    may_own_identity_name=volparossa-helper-live-proof-$may_own_identity_suffix.service
    [ "$may_own_identity_name" != "$production_unit_name" ] \
        && [ "$may_own_identity_name" != "$restart_unit_name" ] || return 1
    unit_name=$may_own_identity_name
}

unit_load_state() {
    unit_name_is_safe || return 1
    unit_load_state_value=$(systemctl show --property=LoadState --value "$unit_name" 2>/dev/null) \
        || return 1
    case $unit_load_state_value in
        loaded|not-found) printf '%s\n' "$unit_load_state_value" ;;
        *) return 1 ;;
    esac
}

unit_active_state() {
    unit_name_is_safe || return 1
    unit_active_state_value=$(systemctl show --property=ActiveState --value "$unit_name" 2>/dev/null) \
        || return 1
    case $unit_active_state_value in
        active|activating|deactivating|failed|inactive|reloading)
            printf '%s\n' "$unit_active_state_value"
            ;;
        *) return 1 ;;
    esac
}

# Capture every manager property used to decide retirement from one D-Bus
# GetAll transaction. A CollectMode=inactive transient unit may disappear as
# soon as its stop job and cgroup settle; separate `systemctl show` processes
# would otherwise turn successful collection between two reads into a false
# lineage failure.
observe_unit_retirement_snapshot() {
    unit_name_is_safe || return 1
    unit_retirement_properties=$(systemctl show --no-pager \
        --property=LoadState \
        --property=InvocationID \
        --property=ActiveState \
        --property=Job \
        --property=NFileDescriptorStore \
        "$unit_name" 2>/dev/null) || return 1
    unit_retirement_tuple=$(printf '%s\n' "$unit_retirement_properties" | /usr/bin/awk '
        {
            separator = index($0, "=")
            if (separator == 0) {
                invalid = 1
                next
            }
            key = substr($0, 1, separator - 1)
            value = substr($0, separator + 1)
            if (key == "LoadState") {
                if (++load_seen != 1) invalid = 1
                load = value
            } else if (key == "InvocationID") {
                if (++invocation_seen != 1) invalid = 1
                invocation = value
            } else if (key == "ActiveState") {
                if (++active_seen != 1) invalid = 1
                active = value
            } else if (key == "Job") {
                if (++job_seen != 1) invalid = 1
                job = value
            } else if (key == "NFileDescriptorStore") {
                if (++fdstore_seen != 1) invalid = 1
                fdstore = value
            } else {
                invalid = 1
            }
        }
        END {
            if (invalid || NR != 5 || load_seen != 1 || invocation_seen != 1 \
                    || active_seen != 1 || job_seen != 1 || fdstore_seen != 1) {
                exit 1
            }
            printf "%s:%s:%s:%s:%s\n", load, \
                invocation == "" ? "absent" : invocation, active, \
                job == "" ? "absent" : "present", fdstore
        }
    ') || return 1

    retire_load_state=${unit_retirement_tuple%%:*}
    unit_retirement_remainder=${unit_retirement_tuple#*:}
    [ "$unit_retirement_remainder" != "$unit_retirement_tuple" ] || return 1
    retire_invocation_id=${unit_retirement_remainder%%:*}
    unit_retirement_remainder=${unit_retirement_remainder#*:}
    retire_active_state=${unit_retirement_remainder%%:*}
    unit_retirement_remainder=${unit_retirement_remainder#*:}
    retire_job_state=${unit_retirement_remainder%%:*}
    retire_fdstore_count=${unit_retirement_remainder#*:}
    case $retire_fdstore_count in
        *:*) return 1 ;;
    esac

    case $retire_load_state in
        not-found)
            [ "$retire_invocation_id:$retire_active_state:$retire_job_state:$retire_fdstore_count" \
                = absent:inactive:absent:0 ]
            ;;
        loaded)
            unit_invocation_id_is_safe "$retire_invocation_id" || return 1
            case $retire_active_state in
                active|activating|deactivating|failed|inactive|reloading) ;;
                *) return 1 ;;
            esac
            case $retire_job_state in
                absent|present) ;;
                *) return 1 ;;
            esac
            case $retire_fdstore_count in
                0|[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

systemd_launch_record_is_safe() {
    [ "$#" -eq 3 ] || return 1
    retired_launch_record=$1
    retired_launch_pid=$2
    retired_launch_gid=$3
    case $retired_launch_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    case $retired_launch_gid in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "$retired_launch_record" | /usr/bin/awk \
        -v expected_pid="$retired_launch_pid" \
        -v expected_gid="$retired_launch_gid" '
        function positive_u53(value) {
            return value ~ /^[1-9][0-9]*$/ \
                && length(value) <= 16 \
                && value + 0 <= 9007199254740991
        }
        NR != 1 { invalid = 1; next }
        {
            prefix = "systemd-launch-v1=pid:" expected_pid \
                ";gid:" expected_gid ";start-realtime:"
            if (index($0, prefix) != 1) {
                invalid = 1
                next
            }
            remainder = substr($0, length(prefix) + 1)
            if (split(remainder, value, ";start-monotonic:") != 2 \
                || !positive_u53(value[1]) \
                || !positive_u53(value[2])) {
                invalid = 1
                next
            }
            accepted++
        }
        END {
            if (invalid || NR != 1 || accepted != 1) exit 1
        }
    '
}

launch_image_record_is_safe() {
    [ "$#" -eq 2 ] || return 1
    retired_image_record=$1
    retired_image_digest=$2
    [ "${#retired_image_digest}" -eq 64 ] || return 1
    case $retired_image_digest in
        *[!0-9a-f]*) return 1 ;;
    esac
    printf '%s\n' "$retired_image_record" | /usr/bin/awk -F '[:;]' \
        -v expected_digest="$retired_image_digest" '
        function canonical_positive(value) {
            return value ~ /^[1-9][0-9]*$/ && length(value) <= 20
        }
        NR != 1 { invalid = 1; next }
        {
            if (NF != 8 || $1 != "launch-image-v1=device" \
                || !canonical_positive($2) || $3 != "inode" \
                || !canonical_positive($4) || $5 != "size" \
                || !canonical_positive($6) || length($6) > 9 \
                || $6 > 134217728 || $7 != "sha256" \
                || $8 != expected_digest) {
                invalid = 1
                next
            }
            accepted++
        }
        END {
            if (invalid || NR != 1 || accepted != 1) exit 1
        }
    '
}

process_starttime_from_stat() {
    [ "$#" -eq 2 ] || return 1
    retired_starttime_line=$1
    retired_starttime_pid=$2
    case $retired_starttime_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#retired_starttime_pid}" -le 10 ] \
        && [ "$retired_starttime_pid" -le 4194304 ] || return 1
    [ "${#retired_starttime_line}" -le 4096 ] || return 1
    printf '%s\n' "$retired_starttime_line" | /usr/bin/awk \
        -v expected_pid="$retired_starttime_pid" '
        NR != 1 { invalid = 1; next }
        {
            prefix = expected_pid " ("
            if (index($0, prefix) != 1) {
                invalid = 1
                next
            }
            close_offset = 0
            for (offset = length($0) - 1; offset >= length(prefix); offset--) {
                if (substr($0, offset, 2) == ") ") {
                    close_offset = offset
                    break
                }
            }
            if (close_offset == 0) {
                invalid = 1
                next
            }
            remainder = substr($0, close_offset + 2)
            if (remainder == "" || substr(remainder, 1, 1) == " " \
                || substr(remainder, length(remainder), 1) == " " \
                || index(remainder, "  ") != 0 \
                || remainder ~ /[\t\r\n]/) {
                invalid = 1
                next
            }
            fields = split(remainder, value, " ")
            starttime = value[20]
            if (fields < 20 || value[1] !~ /^(R|S|D)$/ \
                || starttime !~ /^[1-9][0-9]*$/ \
                || length(starttime) > 20) {
                invalid = 1
                next
            }
            accepted++
        }
        END {
            if (invalid || NR != 1 || accepted != 1) exit 1
            print starttime
        }
    '
}

capture_process_starttime() {
    [ "$#" -eq 1 ] || return 1
    retired_starttime_pid=$1
    case $retired_starttime_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#retired_starttime_pid}" -le 10 ] \
        && [ "$retired_starttime_pid" -le 4194304 ] || return 1
    retired_starttime_path=/proc/$retired_starttime_pid/stat
    [ -f "$retired_starttime_path" ] && [ ! -L "$retired_starttime_path" ] \
        || return 1
    retired_starttime_line=$(cat "$retired_starttime_path") || return 1
    process_starttime_from_stat "$retired_starttime_line" "$retired_starttime_pid"
}

retired_runtime_is_absent() {
    [ "$#" -eq 4 ] || return 1
    retired_unit_name=$1
    retired_control_group=$2
    retired_main_pid=$3
    retired_process_starttime=$4
    case $retired_unit_name in
        volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service) ;;
        *) return 1 ;;
    esac
    [ "$retired_control_group" = "/system.slice/$retired_unit_name" ] || return 1
    case $retired_main_pid in
        0) [ -z "$retired_process_starttime" ] || return 1 ;;
        ''|0*|*[!0-9]*) return 1 ;;
        *) [ "${#retired_main_pid}" -le 7 ] \
                && [ "$retired_main_pid" -le 4194304 ] || return 1
            case $retired_process_starttime in
                ''|0|0*|*[!0-9]*) return 1 ;;
            esac
            [ "${#retired_process_starttime}" -le 20 ] || return 1
            ;;
    esac
    retired_cgroup_path=/sys/fs/cgroup$retired_control_group
    retired_attempt=0
    while :; do
        retired_cgroup_present=no
        if [ -e "$retired_cgroup_path" ] || [ -L "$retired_cgroup_path" ]; then
            retired_cgroup_present=yes
        fi
        retired_process_present=no
        if [ "$retired_main_pid" -ne 0 ] && [ -d "/proc/$retired_main_pid" ]; then
            if retired_observed_starttime=$(capture_process_starttime \
                "$retired_main_pid"); then
                if [ "$retired_observed_starttime" = \
                    "$retired_process_starttime" ]; then
                    retired_process_present=yes
                fi
            elif [ -d "/proc/$retired_main_pid" ]; then
                # An existing process whose birth token cannot be observed is
                # never treated as safely retired. A disappearing proc entry
                # is handled as absent on this or the next bounded attempt.
                retired_process_present=yes
            fi
        fi
        if [ "$retired_cgroup_present:$retired_process_present" = no:no ]; then
            return 0
        fi
        retired_attempt=$((retired_attempt + 1))
        [ "$retired_attempt" -lt 1200 ] || return 1
        sleep 0.05
    done
}

adopt_tentative_unit() {
    [ "$#" -le 1 ] || return 1
    adopt_not_found_disposition=${1:-forget}
    case $adopt_not_found_disposition in
        forget|retain) ;;
        *) return 1 ;;
    esac
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = yes ] || return 1
    unit_name_is_safe || return 1
    unit_ownership_marker_is_safe "$unit_ownership_marker" || return 1

    adopt_attempt=0
    while :; do
        adopt_load_state=$(unit_load_state) || return 1
        if [ "$adopt_load_state" = not-found ]; then
            if [ "$adopt_not_found_disposition" = forget ]; then
                forget_unit_ownership
            fi
            return 0
        fi
        unit_description_matches_marker || return 1
        adopted_invocation_id=$(unit_current_invocation_id 2>/dev/null) \
            || adopted_invocation_id=
        if unit_invocation_id_is_safe "$adopted_invocation_id"; then
            unit_description_matches_marker || return 1
            unit_invocation_id=$adopted_invocation_id unit_owned=yes \
                unit_may_own=no
            return 0
        fi
        adopt_active_state=$(unit_active_state) || return 1
        case $adopt_active_state in
            active|activating|deactivating|failed|inactive|reloading) ;;
            *) return 1 ;;
        esac
        adopt_attempt=$((adopt_attempt + 1))
        [ "$adopt_attempt" -lt 1000 ] || return 1
        sleep 0.05
    done
}

adopt_launched_tentative_unit() {
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = yes ] || return 1
    unit_name_is_safe || return 1
    unit_ownership_marker_is_safe "$unit_ownership_marker" || return 1
    launched_unit_name=$unit_name
    launched_ownership_marker=$unit_ownership_marker
    launched_adopt_attempt=0
    while :; do
        if ! adopt_tentative_unit retain; then
            return 1
        fi
        if [ "$unit_owned" = yes ] && [ "$unit_may_own" = no ]; then
            return 0
        fi
        [ "$unit_name" = "$launched_unit_name" ] && [ "$unit_owned" = no ] \
            && [ "$unit_may_own" = yes ] && [ -z "$unit_invocation_id" ] \
            && [ "$unit_ownership_marker" = "$launched_ownership_marker" ] \
            || return 1
        launched_adopt_attempt=$((launched_adopt_attempt + 1))
        if [ "$launched_adopt_attempt" -ge 1000 ]; then
            return 1
        fi
        sleep 0.05
    done
}

recover_failed_worker_manager_binding() {
    [ "$run_status" -ne 0 ] || return 1
    [ "$worker_launch_captures_ok" = yes ] || return 1
    vp_capture_file_is_safe "$temporary_stage/systemd-run.stdout" || return 1
    [ ! -s "$temporary_stage/systemd-run.stdout" ] || return 1
    [ "$worker_launch_json_ok" = no ] || return 1
    [ "$worker_manager_binding_ok" = no ] || return 1
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = yes ] || return 1
    adopt_tentative_unit || return 1
    [ "$unit_owned" = yes ] || return 1
    [ "$unit_may_own" = no ] || return 1
    unit_invocation_is_current || return 1
    unit_description_matches_marker || return 1
    worker_manager_binding_ok=yes
}

recover_successful_restart_manager_binding() {
    [ "$restart_run_status" -eq 0 ] || return 1
    [ "$restart_launch_captures_ok" = yes ] || return 1
    [ "$restart_launch_json_ok" = no ] || return 1
    [ "$restart_launch_fresh" = no ] || return 1
    [ "$restart_launch_stderr" = empty ] || return 1
    vp_capture_file_is_safe "$temporary_stage/systemd-run-restart.stdout" || return 1
    vp_capture_file_is_safe "$temporary_stage/systemd-run-restart.stderr" || return 1
    [ "$(stat -Lc '%s' "$temporary_stage/systemd-run-restart.stderr")" = 0 ] \
        || return 1
    case $restart_launch_stdout in
        empty)
            [ "$(stat -Lc '%s' \
                "$temporary_stage/systemd-run-restart.stdout")" = 0 ] \
                || return 1
            ;;
        unit-only)
            jq -ers -e --arg expected_unit "$unit_name" '
                length == 1
                    and (.[0] | type) == "object"
                    and (.[0] | keys) == ["unit"]
                    and .[0].unit == $expected_unit
            ' "$temporary_stage/systemd-run-restart.stdout" \
                >/dev/null 2>&1 || return 1
            ;;
        *) return 1 ;;
    esac
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = yes ] || return 1
    adopt_launched_tentative_unit || return 1
    [ "$unit_owned" = yes ] || return 1
    [ "$unit_may_own" = no ] || return 1
    if ! unit_invocation_id_is_safe "$unit_invocation_id" \
        || ! unit_invocation_is_current \
        || ! unit_description_matches_marker \
        || [ "$unit_invocation_id" = "$production_invocation_id" ]; then
        unit_may_own=yes unit_owned=no unit_invocation_id=
        return 1
    fi
    restart_initial_invocation_id=$unit_invocation_id
}

recover_successful_may_own_manager_binding() {
    [ "$may_own_run_status" -eq 0 ] || return 1
    [ "$may_own_launch_captures_ok" = yes ] || return 1
    [ "$may_own_launch_json_ok" = no ] || return 1
    [ "$may_own_launch_fresh" = no ] || return 1
    [ "$may_own_launch_stderr" = empty ] || return 1
    vp_capture_file_is_safe "$temporary_stage/systemd-run-may-own.stdout" || return 1
    vp_capture_file_is_safe "$temporary_stage/systemd-run-may-own.stderr" || return 1
    [ "$(stat -Lc '%s' "$temporary_stage/systemd-run-may-own.stderr")" = 0 ] \
        || return 1
    case $may_own_launch_stdout in
        empty)
            [ "$(stat -Lc '%s' \
                "$temporary_stage/systemd-run-may-own.stdout")" = 0 ] \
                || return 1
            ;;
        unit-only)
            jq -ers -e --arg expected_unit "$unit_name" '
                length == 1
                    and (.[0] | type) == "object"
                    and (.[0] | keys) == ["unit"]
                    and .[0].unit == $expected_unit
            ' "$temporary_stage/systemd-run-may-own.stdout" \
                >/dev/null 2>&1 || return 1
            ;;
        *) return 1 ;;
    esac
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = yes ] || return 1
    adopt_launched_tentative_unit || return 1
    [ "$unit_owned" = yes ] || return 1
    [ "$unit_may_own" = no ] || return 1
    if ! unit_invocation_id_is_safe "$unit_invocation_id" \
        || ! unit_invocation_is_current \
        || ! unit_description_matches_marker \
        || [ "$unit_invocation_id" = "$worker_invocation_id" ] \
        || [ "$unit_invocation_id" = "$production_invocation_id" ] \
        || [ "$unit_invocation_id" = "$restart_initial_invocation_id" ] \
        || [ "$unit_invocation_id" = "$restart_successor_invocation_id" ]; then
        unit_may_own=yes unit_owned=no unit_invocation_id=
        return 1
    fi
    may_own_invocation_one=$unit_invocation_id
}

may_own_preexec_barrier_failure_stage_is_safe() {
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
        shape-cgroup-members|\
        shape-cgroup-type|\
        shape-cgroup-stat|\
        record-size|\
        expectation-create|\
        expectation-write|\
        record-content|\
        launcher-executable|\
        freezer)
            return 0
            ;;
        *) return 1 ;;
    esac
}

report_may_own_preexec_barrier_failure_stage() {
    may_own_preexec_barrier_failure_stage_is_safe \
        "$may_own_preexec_barrier_failure_stage" || return 1
    printf 'VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1=%s\n' \
        "$may_own_preexec_barrier_failure_stage" >&2
}

may_own_service_shape_is_exact() {
    may_own_preexec_barrier_failure_stage=arguments
    [ "$#" -eq 4 ] || return 1
    may_own_shape_main_pid=$1
    may_own_shape_invocation=$2
    may_own_shape_restarts=$3
    may_own_shape_fdstore=$4
    may_own_preexec_barrier_failure_stage=shape-mainpid-argument
    case $may_own_shape_main_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    may_own_preexec_barrier_failure_stage=shape-invocation-argument
    unit_invocation_id_is_safe "$may_own_shape_invocation" || return 1
    may_own_preexec_barrier_failure_stage=shape-count-arguments
    case $may_own_shape_restarts:$may_own_shape_fdstore in
        *[!0-9:]*|:*|*:) return 1 ;;
    esac
    may_own_preexec_barrier_failure_stage=shape-type
    [ "$(systemctl show --property=Type --value "$unit_name")" = simple ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-restart-usec
    [ "$(systemctl show --property=RestartUSec --value "$unit_name")" = 3s ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-control-pid
    [ "$(systemctl show --property=ControlPID --value "$unit_name")" = 0 ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-main-pid
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = \
        "$may_own_shape_main_pid" ] || return 1
    may_own_preexec_barrier_failure_stage=shape-invocation
    [ "$(unit_current_invocation_id)" = "$may_own_shape_invocation" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-restarts
    [ "$(systemctl show --property=NRestarts --value "$unit_name")" = \
        "$may_own_shape_restarts" ] || return 1
    may_own_preexec_barrier_failure_stage=shape-fdstore-count
    [ "$(systemctl show --property=NFileDescriptorStore --value "$unit_name")" = \
        "$may_own_shape_fdstore" ] || return 1
    may_own_preexec_barrier_failure_stage=shape-fdstore-max
    [ "$(systemctl show --property=FileDescriptorStoreMax --value "$unit_name")" = 128 ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-fdstore-preserve
    [ "$(systemctl show --property=FileDescriptorStorePreserve --value "$unit_name")" = yes ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-exec-start-post
    [ -z "$(systemctl show --property=ExecStartPost --value "$unit_name")" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-control-group
    may_own_shape_control_group=$(systemctl show --property=ControlGroup \
        --value "$unit_name") || return 1
    [ "$may_own_shape_control_group" = "/system.slice/$unit_name" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-control-group-id
    may_own_shape_control_group_id=$(systemctl show --property=ControlGroupId \
        --value "$unit_name") || return 1
    case $may_own_shape_control_group_id in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    may_own_preexec_barrier_failure_stage=shape-cgroup-path
    may_own_shape_cgroup=/sys/fs/cgroup/system.slice/$unit_name
    [ -d "$may_own_shape_cgroup" ] && [ ! -L "$may_own_shape_cgroup" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-cgroup-procs
    may_own_shape_procs=$may_own_shape_cgroup/cgroup.procs
    [ -f "$may_own_shape_procs" ] && [ ! -L "$may_own_shape_procs" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=shape-cgroup-members
    /usr/bin/awk -v expected_pid="$may_own_shape_main_pid" '
        NR > 32 || $0 != expected_pid { invalid = 1 }
        END { if (invalid || NR < 1) exit 1 }
    ' "$may_own_shape_procs" || return 1
    may_own_preexec_barrier_failure_stage=shape-cgroup-type
    [ "$(cat "$may_own_shape_cgroup/cgroup.type")" = domain ] || return 1
    may_own_preexec_barrier_failure_stage=shape-cgroup-stat
    /usr/bin/awk '
        NR > 256 { invalid = 1 }
        $1 == "nr_descendants" {
            if (seen_descendants || NF != 2 || $2 != 0) invalid = 1
            seen_descendants = 1
        }
        $1 == "nr_dying_descendants" {
            if (seen_dying || NF != 2 || $2 != 0) invalid = 1
            seen_dying = 1
        }
        END {
            if (invalid || !seen_descendants || !seen_dying) exit 1
        }
    ' "$may_own_shape_cgroup/cgroup.stat" || return 1
    may_own_preexec_barrier_failure_stage=
}

may_own_preexec_barrier_is_exact() {
    may_own_preexec_barrier_failure_stage=arguments
    [ "$#" -eq 4 ] || return 1
    may_own_barrier_main_pid=$1
    may_own_barrier_invocation=$2
    may_own_barrier_restarts=$3
    may_own_barrier_fdstore=$4
    may_own_barrier_record=$temporary_stage/may-own-output/may-own.pre-exec.$may_own_barrier_invocation
    may_own_preexec_barrier_failure_stage=starttime
    may_own_barrier_starttime=$(capture_process_starttime \
        "$may_own_barrier_main_pid") || return 1
    may_own_barrier_wait=0
    while ! vp_capture_file_is_safe "$may_own_barrier_record"; do
        if [ -e "$may_own_barrier_record" ] \
            || [ -L "$may_own_barrier_record" ]; then
            may_own_preexec_barrier_failure_stage=publication-unsafe
            vp_capture_file_is_safe "$may_own_barrier_record" || return 1
            break
        fi
        may_own_preexec_barrier_failure_stage=lineage-mainpid
        [ "$(systemctl show --property=MainPID --value "$unit_name" \
            2>/dev/null || true)" = "$may_own_barrier_main_pid" ] \
            || return 1
        may_own_preexec_barrier_failure_stage=lineage-invocation
        [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
            "$may_own_barrier_invocation" ] || return 1
        may_own_preexec_barrier_failure_stage=lineage-starttime
        [ "$(capture_process_starttime "$may_own_barrier_main_pid" \
            2>/dev/null || true)" = "$may_own_barrier_starttime" ] \
            || return 1
        may_own_preexec_barrier_failure_stage=lineage-marker
        unit_description_matches_marker || return 1
        may_own_barrier_wait=$((may_own_barrier_wait + 1))
        may_own_preexec_barrier_failure_stage=publication-timeout
        [ "$may_own_barrier_wait" -lt 600 ] || return 1
        sleep 0.05
    done
    may_own_preexec_barrier_failure_stage=lineage-mainpid
    [ "$(systemctl show --property=MainPID --value "$unit_name" \
        2>/dev/null || true)" = "$may_own_barrier_main_pid" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=lineage-invocation
    [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
        "$may_own_barrier_invocation" ] || return 1
    may_own_preexec_barrier_failure_stage=lineage-starttime
    [ "$(capture_process_starttime "$may_own_barrier_main_pid" \
        2>/dev/null || true)" = "$may_own_barrier_starttime" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=lineage-marker
    unit_description_matches_marker || return 1
    while ! may_own_service_shape_is_exact "$may_own_barrier_main_pid" \
        "$may_own_barrier_invocation" "$may_own_barrier_restarts" \
        "$may_own_barrier_fdstore"
    do
        [ "$may_own_preexec_barrier_failure_stage" = shape-cgroup-members ] \
            || return 1
        may_own_preexec_barrier_failure_stage=lineage-mainpid
        [ "$(systemctl show --property=MainPID --value "$unit_name" \
            2>/dev/null || true)" = "$may_own_barrier_main_pid" ] \
            || return 1
        may_own_preexec_barrier_failure_stage=lineage-invocation
        [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
            "$may_own_barrier_invocation" ] || return 1
        may_own_preexec_barrier_failure_stage=lineage-starttime
        [ "$(capture_process_starttime "$may_own_barrier_main_pid" \
            2>/dev/null || true)" = "$may_own_barrier_starttime" ] \
            || return 1
        may_own_preexec_barrier_failure_stage=lineage-marker
        unit_description_matches_marker || return 1
        may_own_barrier_wait=$((may_own_barrier_wait + 1))
        may_own_preexec_barrier_failure_stage=shape-cgroup-members
        [ "$may_own_barrier_wait" -lt 600 ] || return 1
        sleep 0.05
    done
    # shellcheck disable=SC2100
    may_own_preexec_barrier_failure_stage=record-size
    [ "$(stat -Lc '%s' "$may_own_barrier_record")" -le 256 ] || return 1
    may_own_barrier_expected=$temporary_stage/may-own-pre-exec.$may_own_barrier_invocation.expected
    may_own_preexec_barrier_failure_stage=expectation-create
    install -o root -g root -m 0600 /dev/null "$may_own_barrier_expected" \
        || return 1
    may_own_preexec_barrier_failure_stage=expectation-write
    printf '%s\n%s\n%s\n' \
        'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_BARRIER_V1=ready' \
        "$may_own_barrier_invocation" "$may_own_barrier_main_pid" \
        >"$may_own_barrier_expected" || return 1
    # shellcheck disable=SC2100
    may_own_preexec_barrier_failure_stage=record-content
    cmp -s "$may_own_barrier_expected" "$may_own_barrier_record" || return 1
    may_own_preexec_barrier_failure_stage=launcher-executable
    [ "$(stat -Lc '%d:%i' "/proc/$may_own_barrier_main_pid/exe")" = \
        "$(stat -Lc '%d:%i' "$temporary_stage/restart-launcher")" ] \
        || return 1
    may_own_preexec_barrier_failure_stage=freezer
    [ "$(cat "/sys/fs/cgroup/system.slice/$unit_name/cgroup.freeze")" = 0 ] \
        || return 1
    may_own_preexec_barrier_failure_stage=
}

release_may_own_preexec_barrier() {
    [ "$#" -eq 2 ] || return 1
    may_own_release_main_pid=$1
    may_own_release_invocation=$2
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = \
        "$may_own_release_main_pid" ] || return 1
    [ "$(unit_current_invocation_id)" = "$may_own_release_invocation" ] \
        || return 1
    [ "$(stat -Lc '%F:%u:%g:%a:%h' "$may_own_preexec_release_fifo" \
        2>/dev/null || true)" = 'fifo:0:0:600:1' ] || return 1
    # The newline lets the fixed launcher's shell-builtin read hold MainPID at
    # the barrier without adding a second process to the service cgroup.
    # shellcheck disable=SC2016
    timeout --preserve-status --signal=TERM --kill-after=1s 5s \
        /bin/sh -c 'printf "%s\n" G >"$1"' sh \
        "$may_own_preexec_release_fifo" \
        || return 1
    [ "$(stat -Lc '%F:%u:%g:%a:%h' "$may_own_preexec_release_fifo" \
        2>/dev/null || true)" = 'fifo:0:0:600:1' ]
}

start_may_own_preexec_observer() {
    [ "$#" -eq 3 ] || return 1
    may_own_preexec_observer_label=$1
    may_own_preexec_observer_main_pid=$2
    may_own_preexec_observer_invocation=$3
    case $may_own_preexec_observer_label in one|two|three) ;; *) return 1 ;; esac
    case $may_own_preexec_observer_main_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    unit_invocation_id_is_safe "$may_own_preexec_observer_invocation" || return 1
    [ -z "${may_own_preexec_observer_pid:-}" ] \
        && [ -z "${may_own_preexec_observer_starttime:-}" ] || return 1
    may_own_preexec_observer_stdout=$temporary_stage/may-own-preexec-observer-$may_own_preexec_observer_label.stdout
    may_own_preexec_observer_stderr=$temporary_stage/may-own-preexec-observer-$may_own_preexec_observer_label.stderr
    for may_own_preexec_observer_log in \
        "$may_own_preexec_observer_stdout" "$may_own_preexec_observer_stderr"; do
        [ ! -e "$may_own_preexec_observer_log" ] \
            && [ ! -L "$may_own_preexec_observer_log" ] || return 1
    done
    timeout --preserve-status --signal=TERM --kill-after=5s 90s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        /usr/bin/nsenter --mount="/proc/$may_own_preexec_observer_main_pid/ns/mnt" \
            --net="/proc/$may_own_preexec_observer_main_pid/ns/net" -- \
        /run/volparossa-helper-may-own-observer \
            "pre-exec-$may_own_preexec_observer_label" "$unit_name" \
            "$agent_gid" "$may_own_preexec_observer_main_pid" \
            "$may_own_preexec_observer_invocation" \
        >"$may_own_preexec_observer_stdout" \
        2>"$may_own_preexec_observer_stderr" &
    may_own_preexec_observer_pid=$!
    may_own_preexec_observer_starttime=$(capture_process_starttime \
        "$may_own_preexec_observer_pid") || {
            kill "$may_own_preexec_observer_pid" 2>/dev/null || :
            wait "$may_own_preexec_observer_pid" 2>/dev/null || :
            may_own_preexec_observer_pid=
            return 1
        }
    may_own_preexec_observer_ready=$temporary_stage/may-own-output/may-own.pre-exec-observer-ready.$may_own_preexec_observer_label
    may_own_preexec_wait=0
    while ! vp_capture_file_is_safe "$may_own_preexec_observer_ready"; do
        kill -0 "$may_own_preexec_observer_pid" 2>/dev/null || return 1
        may_own_preexec_wait=$((may_own_preexec_wait + 1))
        [ "$may_own_preexec_wait" -lt 600 ] || return 1
        sleep 0.05
    done
    may_own_preexec_observer_record_pid=$(sed -n '4p' \
        "$may_own_preexec_observer_ready") || return 1
    case $may_own_preexec_observer_record_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    may_own_preexec_observer_record_starttime=$(capture_process_starttime \
        "$may_own_preexec_observer_record_pid") || return 1
    [ "$(sed -n '1p' "$may_own_preexec_observer_ready")" = \
        'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_OBSERVER_V1=ready' ] \
        && [ "$(sed -n '2p' "$may_own_preexec_observer_ready")" = \
            "$may_own_preexec_observer_invocation" ] \
        && [ "$(sed -n '3p' "$may_own_preexec_observer_ready")" = \
            "$may_own_preexec_observer_main_pid" ] \
        && [ "$(capture_process_starttime "$may_own_preexec_observer_pid")" = \
            "$may_own_preexec_observer_starttime" ] \
        && [ "$(capture_process_starttime \
            "$may_own_preexec_observer_record_pid")" = \
            "$may_own_preexec_observer_record_starttime" ] \
        && kill -0 "$may_own_preexec_observer_record_pid" 2>/dev/null \
        && kill -0 "$may_own_preexec_observer_pid" 2>/dev/null
}

release_may_own_preexec_observer() {
    [ "$#" -eq 1 ] || return 1
    case $1 in one|two|three) ;; *) return 1 ;; esac
    [ "$1" = "$may_own_preexec_observer_label" ] || return 1
    [ "$(capture_process_starttime "$may_own_preexec_observer_record_pid")" = \
        "$may_own_preexec_observer_record_starttime" ] || return 1
    may_own_preexec_observer_release=$temporary_stage/may-own-output/may-own.pre-exec-observer-release.$1
    vp_capture_run "$may_own_preexec_observer_release" printf '%s\n' \
        'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_OBSERVER_V1=release' \
        || return 1
    wait "$may_own_preexec_observer_pid" || return 1
    [ "$(capture_process_starttime "$may_own_preexec_observer_record_pid" \
        2>/dev/null || true)" != "$may_own_preexec_observer_record_starttime" ] \
        || return 1
    may_own_preexec_observer_pid=
    may_own_preexec_observer_starttime=
    may_own_preexec_observer_record_pid=
    may_own_preexec_observer_record_starttime=
    for may_own_preexec_observer_log in \
        "$may_own_preexec_observer_stdout" "$may_own_preexec_observer_stderr"; do
        vp_capture_file_is_safe "$may_own_preexec_observer_log" || return 1
        [ "$(stat -Lc '%s' "$may_own_preexec_observer_log")" -le 1048576 ] \
            || return 1
    done
}

thaw_may_own_crash_boundary_before_restart() {
    [ "$#" -eq 1 ] || return 1
    may_own_thaw_expected_restarts=$1
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ] \
        || return 1
    [ "$(systemctl show --property=NRestarts --value "$unit_name")" = \
        "$may_own_thaw_expected_restarts" ] || return 1
    if [ -d "$may_own_cgroup" ] && [ ! -L "$may_own_cgroup" ]; then
        [ -f "$may_own_cgroup/cgroup.freeze" ] \
            && [ ! -L "$may_own_cgroup/cgroup.freeze" ] || return 1
        printf '%s\n' 0 >"$may_own_cgroup/cgroup.freeze" || return 1
        [ "$(cat "$may_own_cgroup/cgroup.freeze")" = 0 ] || return 1
    elif [ -e "$may_own_cgroup" ] || [ -L "$may_own_cgroup" ]; then
        return 1
    fi
    may_own_cgroup_frozen=no
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ] \
        && [ "$(systemctl show --property=NRestarts --value "$unit_name")" = \
            "$may_own_thaw_expected_restarts" ]
}

may_own_cgroup_is_fully_frozen() {
    [ "$#" -eq 1 ] || return 1
    may_own_frozen_cgroup=$1
    [ "$may_own_frozen_cgroup" = "/sys/fs/cgroup/system.slice/$unit_name" ] \
        || return 1
    may_own_frozen_events=$may_own_frozen_cgroup/cgroup.events
    [ -f "$may_own_frozen_events" ] && [ ! -L "$may_own_frozen_events" ] \
        || return 1
    /usr/bin/awk '
        NR > 32 { exit 1 }
        $1 == "frozen" {
            if (seen || NF != 2 || $2 != "1") exit 1
            seen = 1
        }
        END { if (!seen) exit 1 }
    ' "$may_own_frozen_events"
}

freeze_may_own_cgroup_before_forced_crash() {
    [ "$#" -eq 1 ] || return 1
    may_own_freeze_main_pid=$1
    may_own_service_shape_is_exact "$may_own_freeze_main_pid" \
        "$unit_invocation_id" \
        "$(systemctl show --property=NRestarts --value "$unit_name")" 2 \
        || return 1
    [ "$may_own_cgroup" = "/sys/fs/cgroup/system.slice/$unit_name" ] \
        || return 1
    [ -f "$may_own_cgroup/cgroup.freeze" ] \
        && [ ! -L "$may_own_cgroup/cgroup.freeze" ] || return 1
    printf '%s\n' 1 >"$may_own_cgroup/cgroup.freeze" || return 1
    may_own_cgroup_frozen=yes
    [ "$(cat "$may_own_cgroup/cgroup.freeze")" = 1 ] || return 1
    may_own_freeze_wait=0
    while ! may_own_cgroup_is_fully_frozen "$may_own_cgroup"; do
        [ "$(capture_process_starttime "$may_own_debugger_pid" \
            2>/dev/null || true)" = "$may_own_debugger_starttime" ] \
            || return 1
        may_own_freeze_wait=$((may_own_freeze_wait + 1))
        [ "$may_own_freeze_wait" -lt 600 ] || return 1
        sleep 0.05
    done
}

may_own_initial_namespaces_are_ready() {
    [ "$#" -eq 3 ] || return 1
    may_own_namespace_main_pid=$1
    may_own_namespace_invocation=$2
    may_own_namespace_starttime=$3
    case $may_own_namespace_main_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    unit_invocation_id_is_safe "$may_own_namespace_invocation" || return 1
    case $may_own_namespace_starttime in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    may_own_host_mount_identity=$(stat -Lc '%d:%i' /proc/1/ns/mnt) \
        || return 1
    may_own_host_network_identity=$(stat -Lc '%d:%i' /proc/1/ns/net) \
        || return 1
    may_own_namespace_attempt=0
    while :; do
        if [ "$(systemctl show --property=MainPID --value "$unit_name" \
            2>/dev/null || true)" = "$may_own_namespace_main_pid" ] \
            && [ "$(unit_current_invocation_id 2>/dev/null || true)" = \
                "$may_own_namespace_invocation" ] \
            && [ "$(capture_process_starttime "$may_own_namespace_main_pid" \
                2>/dev/null || true)" = "$may_own_namespace_starttime" ]; then
            may_own_mount_identity_before=$(stat -Lc '%d:%i' \
                "/proc/$may_own_namespace_main_pid/ns/mnt" 2>/dev/null || true)
            may_own_network_identity_before=$(stat -Lc '%d:%i' \
                "/proc/$may_own_namespace_main_pid/ns/net" 2>/dev/null || true)
            may_own_hook_identity_before=$(stat -Lc '%F:%u:%g:%a:%h' \
                "/proc/$may_own_namespace_main_pid/root/run/volparossa-helper-production-ipc-hook" \
                2>/dev/null || true)
            may_own_mount_identity_after=$(stat -Lc '%d:%i' \
                "/proc/$may_own_namespace_main_pid/ns/mnt" 2>/dev/null || true)
            may_own_network_identity_after=$(stat -Lc '%d:%i' \
                "/proc/$may_own_namespace_main_pid/ns/net" 2>/dev/null || true)
            may_own_hook_identity_after=$(stat -Lc '%F:%u:%g:%a:%h' \
                "/proc/$may_own_namespace_main_pid/root/run/volparossa-helper-production-ipc-hook" \
                2>/dev/null || true)
            if [ "$may_own_mount_identity_before" = \
                "$may_own_mount_identity_after" ] \
                && [ "$may_own_network_identity_before" = \
                    "$may_own_network_identity_after" ] \
                && [ "$may_own_hook_identity_before" = \
                    "$may_own_hook_identity_after" ] \
                && [ "$may_own_mount_identity_before" != \
                    "$may_own_host_mount_identity" ] \
                && [ "$may_own_network_identity_before" != \
                    "$may_own_host_network_identity" ] \
                && [ "$may_own_hook_identity_before" = \
                    'regular file:0:0:500:1' ]; then
                return 0
            fi
        fi
        may_own_namespace_attempt=$((may_own_namespace_attempt + 1))
        [ "$may_own_namespace_attempt" -lt 600 ] || return 1
        sleep 0.05
    done
}

start_may_own_driver_observer() {
    [ "$#" -eq 3 ] || return 1
    may_own_driver_label=$1
    may_own_driver_main_pid=$2
    may_own_driver_expected_invocation=$3
    case $may_own_driver_label in one|two|three) ;; *) return 1 ;; esac
    case $may_own_driver_main_pid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    unit_invocation_id_is_safe "$may_own_driver_expected_invocation" \
        || return 1
    [ -z "${may_own_driver_observer_pid:-}" ] \
        && [ -z "${may_own_driver_observer_starttime:-}" ] || return 1
    [ "$(unit_current_invocation_id)" = \
        "$may_own_driver_expected_invocation" ] || return 1
    [ "$(systemctl show --property=MainPID --value "$unit_name")" = \
        "$may_own_driver_main_pid" ] || return 1
    [ "$(stat -Lc '%d:%i' "/proc/$may_own_driver_main_pid/ns/mnt")" != \
        "$(stat -Lc '%d:%i' /proc/1/ns/mnt)" ] || return 1
    [ "$(stat -Lc '%d:%i' "/proc/$may_own_driver_main_pid/ns/net")" != \
        "$(stat -Lc '%d:%i' /proc/1/ns/net)" ] || return 1
    unit_description_matches_marker || return 1
    may_own_driver_observer_stdout=$temporary_stage/may-own-driver-$may_own_driver_label.stdout
    may_own_driver_observer_stderr=$temporary_stage/may-own-driver-$may_own_driver_label.stderr
    for may_own_driver_absent_path in \
        "$may_own_driver_observer_stdout" "$may_own_driver_observer_stderr"; do
        if [ -e "$may_own_driver_absent_path" ] \
            || [ -L "$may_own_driver_absent_path" ]; then
            return 1
        fi
    done
    timeout --preserve-status --signal=TERM --kill-after=5s 180s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        /usr/bin/nsenter --mount="/proc/$may_own_driver_main_pid/ns/mnt" \
            --net="/proc/$may_own_driver_main_pid/ns/net" -- \
        /usr/bin/setpriv --no-new-privs --reuid=0 \
            --regid="$agent_gid" --groups="$agent_gid" -- \
        /run/volparossa-helper-production-ipc-hook may-own-driver-start \
            "$unit_name" "$agent_uid" "$agent_gid" "$operator_gid" \
            "$worker_uid" "$worker_gid" "$may_own_driver_main_pid" \
        >"$may_own_driver_observer_stdout" \
        2>"$may_own_driver_observer_stderr" &
    may_own_driver_observer_pid=$!
    if ! may_own_driver_observer_starttime=$(capture_process_starttime \
        "$may_own_driver_observer_pid"); then
        kill "$may_own_driver_observer_pid" 2>/dev/null || :
        wait "$may_own_driver_observer_pid" 2>/dev/null || :
        may_own_driver_observer_pid=
        may_own_driver_observer_starttime=
        return 1
    fi
}

wait_may_own_driver_observer() {
    [ "$#" -eq 1 ] || return 1
    may_own_driver_expected_result=$1
    case $may_own_driver_expected_result in success|forced-crash) ;; *) return 1 ;; esac
    case ${may_own_driver_observer_pid:-} in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    if wait "$may_own_driver_observer_pid"; then
        may_own_driver_observer_status=0
    else
        may_own_driver_observer_status=$?
    fi
    may_own_driver_observer_pid=
    may_own_driver_observer_starttime=
    for may_own_driver_log in \
        "$may_own_driver_observer_stdout" "$may_own_driver_observer_stderr"; do
        vp_capture_file_is_safe "$may_own_driver_log" || return 1
        [ "$(stat -Lc '%s' "$may_own_driver_log")" -le 1048576 ] \
            || return 1
    done
    case $may_own_driver_expected_result:$may_own_driver_observer_status in
        success:0|forced-crash:1) return 0 ;;
        *) return 1 ;;
    esac
}

retire_failure_stage_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        adoption|identity|initial-snapshot|stop-request|stop-wait|reset-failed|\
        reset-wait|fdstore-clean|post-clean|final-reset|collection)
            return 0
            ;;
        *) return 1 ;;
    esac
}

retire_unit() {
    retire_failure_stage=adoption
    if [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ]; then
        # A successful or interrupted transient-unit request may still be
        # queued while PID 1 briefly reports not-found. Keep the exact random
        # name and marker in affine cleanup custody until bounded adoption;
        # ambiguity must preserve the stage for disposable-VM teardown.
        adopt_launched_tentative_unit || return 1
    fi
    retire_failure_stage=identity
    case $unit_owned in
        no) return 0 ;;
        yes) ;;
        *) return 1 ;;
    esac
    unit_name_is_safe || return 1
    unit_invocation_id_is_safe "$unit_invocation_id" || return 1
    retire_failure_stage=initial-snapshot
    observe_unit_retirement_snapshot || return 1
    if [ "$retire_load_state" = not-found ]; then
        forget_unit_ownership
        return 0
    fi
    [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
    retire_failure_stage=stop-request
    if ! systemctl stop --no-block "$unit_name" >/dev/null 2>&1; then
        observe_unit_retirement_snapshot || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
        return 1
    fi

    retire_failure_stage=stop-wait
    retire_attempt=0
    while :; do
        observe_unit_retirement_snapshot || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
        case $retire_active_state in
            inactive|failed)
                if [ "$retire_job_state" = absent ]; then
                    break
                fi
                ;;
            active|activating|deactivating|reloading) ;;
            *) return 1 ;;
        esac
        retire_attempt=$((retire_attempt + 1))
        [ "$retire_attempt" -lt 1200 ] || return 1
        sleep 0.05
    done

    if [ "$retire_active_state" = failed ]; then
        retire_failure_stage=reset-failed
        if ! systemctl reset-failed "$unit_name" >/dev/null 2>&1; then
            observe_unit_retirement_snapshot || return 1
            if [ "$retire_load_state" = not-found ]; then
                forget_unit_ownership
                return 0
            fi
            [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
            return 1
        fi

        retire_failure_stage=reset-wait
        retire_attempt=0
        while :; do
            observe_unit_retirement_snapshot || return 1
            if [ "$retire_load_state" = not-found ]; then
                forget_unit_ownership
                return 0
            fi
            [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
            if [ "$retire_active_state" = inactive ] \
                && [ "$retire_job_state" = absent ]; then
                break
            fi
            case $retire_active_state in
                active|activating|deactivating|failed|inactive|reloading) ;;
                *) return 1 ;;
            esac
            retire_attempt=$((retire_attempt + 1))
            [ "$retire_attempt" -lt 1200 ] || return 1
            sleep 0.05
        done
    fi

    [ "$retire_active_state" = inactive ] || return 1
    [ "$retire_job_state" = absent ] || return 1
    [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
    retire_failure_stage=fdstore-clean
    if ! systemctl clean --what=fdstore "$unit_name" >/dev/null 2>&1; then
        observe_unit_retirement_snapshot || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
        return 1
    fi
    retire_failure_stage=post-clean
    observe_unit_retirement_snapshot || return 1
    if [ "$retire_load_state" = not-found ]; then
        forget_unit_ownership
        return 0
    fi
    [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
    [ "$retire_fdstore_count" -eq 0 ] || return 1

    retire_failure_stage=final-reset
    if ! systemctl reset-failed "$unit_name" >/dev/null 2>&1; then
        observe_unit_retirement_snapshot || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
        return 1
    fi

    retire_failure_stage=collection
    retire_attempt=0
    while :; do
        observe_unit_retirement_snapshot || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        [ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1
        [ "$retire_active_state" = inactive ] || return 1
        [ "$retire_job_state" = absent ] || return 1
        [ "$retire_fdstore_count" -eq 0 ] || return 1
        retire_attempt=$((retire_attempt + 1))
        [ "$retire_attempt" -lt 1200 ] || return 1
        sleep 0.05
    done
}

remove_temporary_stage() {
    if [ -n "$temporary_stage" ]; then
        case $temporary_stage in
            /var/tmp/volparossa-helper-live-proof.??????)
                observed_identity=$(stat -Lc '%d:%i:%F:%u:%g:%a' "$temporary_stage" 2>/dev/null || true)
                if [ "$observed_identity" = "$temporary_stage_identity" ]; then
                    rm -rf --one-file-system -- "$temporary_stage" || return 1
                    if [ -e "$temporary_stage" ] || [ -L "$temporary_stage" ]; then
                        return 1
                    fi
                    temporary_stage=
                    temporary_stage_identity=
                elif [ ! -e "$temporary_stage" ] && [ ! -L "$temporary_stage" ]; then
                    temporary_stage=
                    temporary_stage_identity=
                else
                    printf 'Refusing to remove replaced proof stage: %s\n' "$temporary_stage" >&2
                    return 1
                fi
                ;;
            *)
                printf 'Refusing to remove unsafe proof stage: %s\n' "$temporary_stage" >&2
                return 1
                ;;
        esac
    fi
}

cleanup() {
    saved_status=$?
    trap - EXIT HUP INT TERM
    if [ -n "${may_own_preexec_observer_pid:-}" ]; then
        if [ "$(capture_process_starttime "$may_own_preexec_observer_pid" \
            2>/dev/null || true)" = \
            "${may_own_preexec_observer_starttime:-}" ]; then
            kill "$may_own_preexec_observer_pid" 2>/dev/null || :
        fi
        wait "$may_own_preexec_observer_pid" 2>/dev/null || :
        may_own_preexec_observer_pid=
        may_own_preexec_observer_starttime=
    fi
    if [ -n "${may_own_preexec_observer_record_pid:-}" ] \
        && [ "$(capture_process_starttime \
            "$may_own_preexec_observer_record_pid" 2>/dev/null || true)" = \
            "${may_own_preexec_observer_record_starttime:-}" ]; then
        kill "$may_own_preexec_observer_record_pid" 2>/dev/null || :
        may_own_preexec_cleanup_wait=0
        while [ "$(capture_process_starttime \
            "$may_own_preexec_observer_record_pid" 2>/dev/null || true)" = \
            "$may_own_preexec_observer_record_starttime" ]; do
            may_own_preexec_cleanup_wait=$((may_own_preexec_cleanup_wait + 1))
            if [ "$may_own_preexec_cleanup_wait" -ge 100 ]; then
                kill -KILL "$may_own_preexec_observer_record_pid" 2>/dev/null || :
                break
            fi
            sleep 0.05
        done
    fi
    may_own_preexec_observer_record_pid=
    may_own_preexec_observer_record_starttime=
    if [ -n "${may_own_driver_observer_pid:-}" ]; then
        if [ "$(capture_process_starttime "$may_own_driver_observer_pid" \
            2>/dev/null || true)" = \
            "${may_own_driver_observer_starttime:-}" ]; then
            kill "$may_own_driver_observer_pid" 2>/dev/null || :
        fi
        wait "$may_own_driver_observer_pid" 2>/dev/null || :
        may_own_driver_observer_pid=
        may_own_driver_observer_starttime=
    fi
    if [ -n "${may_own_debugger_pid:-}" ]; then
        if [ "$(capture_process_starttime "$may_own_debugger_pid" \
            2>/dev/null || true)" = "${may_own_debugger_starttime:-}" ]; then
            kill "$may_own_debugger_pid" 2>/dev/null || :
        fi
        wait "$may_own_debugger_pid" 2>/dev/null || :
        may_own_debugger_pid=
        may_own_debugger_starttime=
    fi
    if [ -n "${may_own_mount_keeper_pid:-}" ]; then
        if [ "$(capture_process_starttime "$may_own_mount_keeper_pid" \
            2>/dev/null || true)" = "${may_own_mount_keeper_starttime:-}" ]; then
            kill "$may_own_mount_keeper_pid" 2>/dev/null || :
        fi
        wait "$may_own_mount_keeper_pid" 2>/dev/null || :
        may_own_mount_keeper_pid=
        may_own_mount_keeper_starttime=
    fi
    if [ "${may_own_cgroup_frozen:-no}" = yes ]; then
        if unit_name_is_safe \
            && [ "$may_own_cgroup" = "/sys/fs/cgroup/system.slice/$unit_name" ] \
            && [ -f "$may_own_cgroup/cgroup.freeze" ] \
            && [ ! -L "$may_own_cgroup/cgroup.freeze" ]; then
            printf '%s\n' 0 >"$may_own_cgroup/cgroup.freeze" 2>/dev/null \
                || cleanup_error=yes
        else
            cleanup_error=yes
        fi
        may_own_cgroup_frozen=no
    fi
    if [ -n "${restart_successor_debugger_pid:-}" ]; then
        if [ "$(capture_process_starttime "$restart_successor_debugger_pid" \
            2>/dev/null || true)" = "${restart_successor_debugger_starttime:-}" ]; then
            kill "$restart_successor_debugger_pid" 2>/dev/null || :
        fi
        wait "$restart_successor_debugger_pid" 2>/dev/null || :
        restart_successor_debugger_pid=
        restart_successor_debugger_starttime=
    fi
    if [ -n "${restart_mount_keeper_pid:-}" ]; then
        if [ "$(capture_process_starttime "$restart_mount_keeper_pid" \
            2>/dev/null || true)" = "${restart_mount_keeper_starttime:-}" ]; then
            kill "$restart_mount_keeper_pid" 2>/dev/null || :
        fi
        wait "$restart_mount_keeper_pid" 2>/dev/null || :
        restart_mount_keeper_pid=
        restart_mount_keeper_starttime=
    fi
    retirement_complete=no
    if retire_unit; then
        retirement_complete=yes
    else
        cleanup_error=yes
    fi
    if [ "$retirement_complete" = yes ]; then
        if ! remove_temporary_stage; then
            cleanup_error=yes
        fi
    fi
    if [ "$cleanup_error" = yes ] && [ "$saved_status" -eq 0 ]; then
        saved_status=1
    fi
    if [ "$saved_status" -ne 0 ] \
        && [ "${structured_failure_reported:-no}" = no ]; then
        report_unexpected_driver_phase "${driver_phase:-}" || :
        report_unexpected_final_checkpoint "${final_checkpoint:-}" || :
    fi
    exit "$saved_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

temporary_stage=$(mktemp -d /var/tmp/volparossa-helper-live-proof.XXXXXX)
case $temporary_stage in
    /var/tmp/volparossa-helper-live-proof.??????) ;;
    *) failed 'mktemp returned an unsafe staging path' ;;
esac
temporary_stage_identity=$(stat -Lc '%d:%i:%F:%u:%g:%a' "$temporary_stage")
case $temporary_stage_identity in
    *:directory:0:0:700) ;;
    *) failed 'temporary stage ownership or mode is unsafe' ;;
esac
stage_suffix=${temporary_stage##*.}
case $stage_suffix in
    ''|*[!A-Za-z0-9]*) failed 'temporary stage suffix is non-canonical' ;;
esac
unit_name=volparossa-helper-live-proof-$stage_suffix.service
initial_unit_load_state=$(unit_load_state) \
    || failed 'random transient unit state could not be determined'
if [ "$initial_unit_load_state" != not-found ]; then
    failed 'random transient unit name is already loaded'
fi
ownership_marker_line=$(printf '%s\n%s\n%s\n' \
    'VOLPAROSSA helper live proof transient ownership marker v1' \
    "$unit_name" "$temporary_stage_identity" | sha256sum) \
    || failed 'transient unit ownership marker could not be derived'
ownership_marker_digest=$(vp_capture_checksum_from_line "$ownership_marker_line") \
    || failed 'transient unit ownership marker is non-canonical'
unit_ownership_marker=volparossa-helper-live-proof-owner-v1-$ownership_marker_digest
unit_ownership_marker_is_safe "$unit_ownership_marker" \
    || failed 'transient unit ownership marker is unsafe'

entry_is_absent() {
    database=$1
    key=$2
    set +e
    getent "$database" "$key" >/dev/null 2>&1
    status=$?
    set -e
    [ "$status" -eq 2 ]
}

base_id=61000
ids_found=no
while [ "$base_id" -le 64990 ]; do
    agent_uid=$base_id
    agent_gid=$base_id
    operator_gid=$((base_id + 1))
    worker_uid=$((base_id + 2))
    worker_gid=$((base_id + 2))
    shadow_gid=$((base_id + 3))
    if entry_is_absent passwd "$agent_uid" \
        && entry_is_absent passwd "$worker_uid" \
        && entry_is_absent group "$agent_gid" \
        && entry_is_absent group "$operator_gid" \
        && entry_is_absent group "$worker_gid" \
        && entry_is_absent group "$shadow_gid"; then
        ids_found=yes
        break
    fi
    base_id=$((base_id + 4))
done
if [ "$ids_found" != yes ]; then
    blocked 'no collision-free synthetic service identity range is available'
fi

source_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$helper_source")
if ! source_snapshot_is_exact "$source_before" 755 "$staged_executable_max_bytes" \
    || [ "$source_before" != "$helper_initial_snapshot" ]; then
    failed 'the helper source changed before its bounded staging copy'
fi
source_digest_before=$(vp_capture_sha256_file "$helper_source") \
    || failed 'the helper source could not be hashed'
prlimit --fsize="$staged_executable_max_bytes:$staged_executable_max_bytes" -- \
    install -o root -g root -m 0500 \
        "$helper_source" "$temporary_stage/volparossa-helper" \
    || failed 'the bounded helper staging copy failed'
source_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$helper_source")
source_digest_after=$(vp_capture_sha256_file "$helper_source") \
    || failed 'the helper source could not be re-hashed'
staged_digest=$(vp_capture_sha256_file "$temporary_stage/volparossa-helper") \
    || failed 'the staged helper could not be hashed'
if [ "$source_before" != "$source_after" ] \
    || [ "$source_digest_before" != "$source_digest_after" ] \
    || [ "$source_digest_before" != "$staged_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/volparossa-helper")" \
        != 'regular file:0:0:500:1' ]; then
    failed 'the real helper changed while copied or the staged image is unsafe'
fi

ipc_probe_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$ipc_probe_source")
if ! source_snapshot_is_exact "$ipc_probe_before" 755 "$staged_executable_max_bytes" \
    || [ "$ipc_probe_before" != "$ipc_probe_initial_snapshot" ]; then
    failed 'the production IPC probe changed before its bounded staging copy'
fi
ipc_probe_digest_before=$(vp_capture_sha256_file "$ipc_probe_source") \
    || failed 'the production IPC probe source could not be hashed'
prlimit --fsize="$staged_executable_max_bytes:$staged_executable_max_bytes" -- \
    install -o root -g "$agent_gid" -m 0550 \
        "$ipc_probe_source" "$temporary_stage/production-ipc-probe" \
    || failed 'the bounded production IPC probe staging copy failed'
ipc_probe_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$ipc_probe_source")
ipc_probe_digest_after=$(vp_capture_sha256_file "$ipc_probe_source") \
    || failed 'the production IPC probe source could not be re-hashed'
staged_ipc_probe_digest=$(vp_capture_sha256_file "$temporary_stage/production-ipc-probe") \
    || failed 'the staged production IPC probe could not be hashed'
if [ "$ipc_probe_before" != "$ipc_probe_after" ] \
    || [ "$ipc_probe_digest_before" != "$ipc_probe_digest_after" ] \
    || [ "$ipc_probe_digest_before" != "$staged_ipc_probe_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/production-ipc-probe")" \
        != "regular file:0:$agent_gid:550:1" ]; then
    failed 'the production IPC probe changed while copied or its staged image is unsafe'
fi

# The two reviewed build artifacts need more than the proof-file ceiling while
# being copied. From this point onward, apply that ceiling to this fixed shell
# and every ordinary descendant before any other staged file is written. No
# later gate path raises it; transient services get an independent PID 1 limit.
install_proof_file_limit "$proof_file_max_bytes" \
    || failed 'the proof-process file-size limit is not exact'

ipc_hook_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$ipc_hook_source")
if ! source_snapshot_is_exact "$ipc_hook_before" 700 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact "$ipc_hook_before" 750 "$proof_file_max_bytes" \
    && ! source_snapshot_is_exact "$ipc_hook_before" 755 "$proof_file_max_bytes"; then
    failed 'the production IPC hook changed before its bounded staging copy'
fi
[ "$ipc_hook_before" = "$ipc_hook_initial_snapshot" ] \
    || failed 'the production IPC hook identity changed before its staging copy'
ipc_hook_digest_before=$(vp_capture_sha256_file "$ipc_hook_source") \
    || failed 'the production IPC hook source could not be hashed'
install -o root -g root -m 0500 "$ipc_hook_source" \
    "$temporary_stage/production-ipc-hook"
ipc_hook_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$ipc_hook_source")
ipc_hook_digest_after=$(vp_capture_sha256_file "$ipc_hook_source") \
    || failed 'the production IPC hook source could not be re-hashed'
staged_ipc_hook_digest=$(vp_capture_sha256_file "$temporary_stage/production-ipc-hook") \
    || failed 'the staged production IPC hook could not be hashed'
if [ "$ipc_hook_before" != "$ipc_hook_after" ] \
    || [ "$ipc_hook_digest_before" != "$ipc_hook_digest_after" ] \
    || [ "$ipc_hook_digest_before" != "$staged_ipc_hook_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/production-ipc-hook")" \
        != 'regular file:0:0:500:1' ]; then
    failed 'the production IPC hook changed while copied or its staged image is unsafe'
fi

restart_observer_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_observer_source")
[ "$restart_observer_before" = "$restart_observer_initial_snapshot" ] \
    || failed 'the restart observer identity changed before staging'
restart_observer_digest_before=$(vp_capture_sha256_file "$restart_observer_source") \
    || failed 'the restart observer could not be hashed'
install -o root -g root -m 0500 "$restart_observer_source" \
    "$temporary_stage/restart-observer"
restart_observer_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_observer_source")
restart_observer_digest_after=$(vp_capture_sha256_file "$restart_observer_source") \
    || failed 'the restart observer could not be re-hashed'
staged_restart_observer_digest=$(vp_capture_sha256_file \
    "$temporary_stage/restart-observer") \
    || failed 'the staged restart observer could not be hashed'
if [ "$restart_observer_before" != "$restart_observer_after" ] \
    || [ "$restart_observer_digest_before" != "$restart_observer_digest_after" ] \
    || [ "$restart_observer_digest_before" != "$staged_restart_observer_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/restart-observer")" \
        != 'regular file:0:0:500:1' ]; then
    failed 'the restart observer changed while copied or its staged image is unsafe'
fi

restart_launcher_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_launcher_source")
[ "$restart_launcher_before" = "$restart_launcher_initial_snapshot" ] \
    || failed 'the restart launcher identity changed before staging'
restart_launcher_digest_before=$(vp_capture_sha256_file "$restart_launcher_source") \
    || failed 'the restart launcher could not be hashed'
install -o root -g root -m 0500 "$restart_launcher_source" \
    "$temporary_stage/restart-launcher"
restart_launcher_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_launcher_source")
restart_launcher_digest_after=$(vp_capture_sha256_file "$restart_launcher_source") \
    || failed 'the restart launcher could not be re-hashed'
staged_restart_launcher_digest=$(vp_capture_sha256_file \
    "$temporary_stage/restart-launcher") \
    || failed 'the staged restart launcher could not be hashed'
if [ "$restart_launcher_before" != "$restart_launcher_after" ] \
    || [ "$restart_launcher_digest_before" != "$restart_launcher_digest_after" ] \
    || [ "$restart_launcher_digest_before" != "$staged_restart_launcher_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/restart-launcher")" \
        != 'regular file:0:0:500:1' ]; then
    failed 'the restart launcher changed while copied or its staged image is unsafe'
fi
may_own_observer_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$may_own_observer_source")
[ "$may_own_observer_before" = "$may_own_observer_initial_snapshot" ] \
    || failed 'the MayOwn Relay observer identity changed before staging'
may_own_observer_digest_before=$(vp_capture_sha256_file "$may_own_observer_source") \
    || failed 'the MayOwn Relay observer could not be hashed'
install -o root -g root -m 0500 "$may_own_observer_source" \
    "$temporary_stage/may-own-observer"
may_own_observer_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$may_own_observer_source")
may_own_observer_digest_after=$(vp_capture_sha256_file "$may_own_observer_source") \
    || failed 'the MayOwn Relay observer could not be re-hashed'
staged_may_own_observer_digest=$(vp_capture_sha256_file \
    "$temporary_stage/may-own-observer") \
    || failed 'the staged MayOwn Relay observer could not be hashed'
if [ "$may_own_observer_before" != "$may_own_observer_after" ] \
    || [ "$may_own_observer_digest_before" != "$may_own_observer_digest_after" ] \
    || [ "$may_own_observer_digest_before" != \
        "$staged_may_own_observer_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/may-own-observer")" \
        != 'regular file:0:0:500:1' ]; then
    failed 'the MayOwn Relay observer changed while copied or its staged image is unsafe'
fi

printf '%s\n' \
    'root:x:0:0:root:/root:/bin/sh' \
    "volparossa:x:$agent_uid:$agent_gid:VOLPAROSSA staged agent:/var/lib/volparossa:/usr/sbin/nologin" \
    "volparossa-worker:x:$worker_uid:$worker_gid:VOLPAROSSA staged worker:/nonexistent:/usr/sbin/nologin" \
    >"$temporary_stage/passwd"
printf '%s\n' \
    'root:x:0:' \
    "volparossa:x:$agent_gid:" \
    "volparossa-users:x:$operator_gid:volparossa" \
    "volparossa-worker:x:$worker_gid:" \
    "shadow:x:$shadow_gid:" \
    >"$temporary_stage/group"
printf '%s\n' \
    'root:!:0:0:99999:7:::' \
    'volparossa:!:0:0:99999:7:::' \
    'volparossa-worker:!:0:0:99999:7::1:' \
    >"$temporary_stage/shadow"
printf '%s\n' \
    'passwd: files' \
    'group: files' \
    'shadow: files' \
    'initgroups: files' \
    >"$temporary_stage/nsswitch.conf"
chown root:root "$temporary_stage/passwd" "$temporary_stage/group" \
    "$temporary_stage/nsswitch.conf"
chmod 0644 "$temporary_stage/passwd" "$temporary_stage/group" \
    "$temporary_stage/nsswitch.conf"
chown "root:$shadow_gid" "$temporary_stage/shadow"
chmod 0640 "$temporary_stage/shadow"
for staged_file in passwd group nsswitch.conf; do
    if [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/$staged_file")" \
        != 'regular file:0:0:644:1' ]; then
        failed "unsafe staged account file: $staged_file"
    fi
done
if [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/shadow")" \
    != "regular file:0:$shadow_gid:640:1" ]; then
    failed 'unsafe staged shadow file'
fi
install -o root -g root -m 0600 /dev/null "$temporary_stage/proof.stdout"
install -o root -g root -m 0600 /dev/null "$temporary_stage/proof.stderr"
install -d -o root -g "$agent_gid" -m 0750 "$temporary_stage/production-runtime"
install -d -o root -g root -m 2700 "$temporary_stage/production-output"
install -d -o root -g root -m 2700 "$temporary_stage/restart-output"
restart_successor_release_fifo=$temporary_stage/restart-output/restart.successor-release
mkfifo -m 0600 "$restart_successor_release_fifo" \
    || failed 'the restart successor release FIFO could not be created'
[ "$(stat -Lc '%F:%u:%g:%a:%h' \
    "$restart_successor_release_fifo" 2>/dev/null || true)" \
    = 'fifo:0:0:600:1' ] \
    || failed 'the restart successor release FIFO is unsafe'
install -d -o root -g root -m 2700 "$temporary_stage/may-own-output"
may_own_preexec_release_fifo=$temporary_stage/may-own-output/may-own.pre-exec-release
mkfifo -m 0600 "$may_own_preexec_release_fifo" \
    || failed 'the MayOwn pre-exec release FIFO could not be created'
[ "$(stat -Lc '%F:%u:%g:%a:%h' "$may_own_preexec_release_fifo" \
    2>/dev/null || true)" = 'fifo:0:0:600:1' ] \
    || failed 'the MayOwn pre-exec release FIFO is unsafe'

state_records='production_runtime_path accounts namespaces mounts resolver sysctls links addresses routes rules nexthops qdiscs nftables wireguard legacy_ipv4_firewall legacy_ipv6_firewall'

publish_streamed_digest_record() {
    [ "$#" -eq 2 ] || failed 'invalid streamed state publication request'
    streamed_digest_capture=$1
    streamed_digest_record=$2
    vp_capture_file_is_safe "$streamed_digest_capture" \
        || failed 'a streamed host-state digest is not a validated private file'
    streamed_digest_line=$(cat "$streamed_digest_capture") \
        || failed 'a streamed host-state digest could not be read'
    streamed_digest=$(vp_capture_checksum_from_line "$streamed_digest_line") \
        || failed 'a streamed host-state digest is malformed'
    vp_capture_run "$streamed_digest_record" printf '%s\n%s\n' PRESENT "$streamed_digest" \
        || failed 'a streamed host-state digest could not be published'
}

publish_absent_record() {
    [ "$#" -eq 1 ] || failed 'invalid absent state publication request'
    vp_capture_run "$1" printf '%s\n' ABSENT \
        || failed 'an absent host-state marker could not be published'
}

capture_host_state() {
    destination=$1
    install -d -o root -g root -m 0700 "$destination"
    capture_directory=$destination/captures
    install -d -o root -g root -m 0700 "$capture_directory"

    if [ -e "$host_runtime_directory" ] || [ -L "$host_runtime_directory" ]; then
        failed 'the host /run/volparossa path is not absent at a state fence'
    fi
    vp_capture_run "$destination/production_runtime_path" printf '%s\n' ABSENT \
        || failed 'host /run/volparossa absence could not be published'

    accounts_capture=$capture_directory/accounts.validated
    : >"$accounts_capture"
    chmod 0600 "$accounts_capture"
    for account_file in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/nsswitch.conf; do
        if [ ! -f "$account_file" ] || [ -L "$account_file" ]; then
            failed "host account database is unsafe: $account_file"
        fi
        account_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$account_file") \
            || failed 'host account metadata could not be captured'
        account_digest=$(vp_capture_sha256_file "$account_file") \
            || failed 'host account content could not be hashed'
        account_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$account_file") \
            || failed 'host account metadata could not be re-captured'
        [ "$account_before" = "$account_after" ] \
            || failed 'host account database changed during one capture'
        printf '%s\n%s\n%s\n' "$account_file" "$account_before" "$account_digest" \
            >>"$accounts_capture" || failed 'host account capture could not be written'
    done
    vp_capture_file_is_safe "$accounts_capture" \
        || failed 'host account capture is not a validated private file'
    vp_capture_publish_digest "$accounts_capture" "$destination/accounts" \
        || failed 'host account capture could not be published'

    namespaces_capture=$capture_directory/namespaces.validated
    : >"$namespaces_capture"
    chmod 0600 "$namespaces_capture"
    for namespace in user net mnt pid pid_for_children; do
        namespace_identity=$(stat -Lc '%d:%i' "/proc/self/ns/$namespace") \
            || failed 'host namespace identity could not be captured'
        printf '%s\n%s\n' "$namespace" "$namespace_identity" >>"$namespaces_capture" \
            || failed 'host namespace capture could not be written'
    done
    vp_capture_file_is_safe "$namespaces_capture" \
        || failed 'host namespace capture is not a validated private file'
    vp_capture_publish_digest "$namespaces_capture" "$destination/namespaces" \
        || failed 'host namespace capture could not be published'

    vp_capture_run "$capture_directory/mounts.raw" cat /proc/self/mountinfo \
        || failed 'host mount producer failed'
    vp_capture_publish_digest "$capture_directory/mounts.raw" "$destination/mounts" \
        || failed 'host mount capture could not be published'

    resolver_authority_before=$capture_directory/resolver-authority-before.validated
    resolver_authority_after=$capture_directory/resolver-authority-after.validated
    resolver_object_capture=$capture_directory/resolver-object.validated
    resolver_capture=$capture_directory/resolver.validated
    vp_capture_run "$resolver_authority_before" resolver_authority_record \
        || failed 'the systemd-resolved authority could not be captured safely'
    resolver_object_contract_is_exact \
        || failed 'the Debian resolver symlink is outside its exact contract'
    vp_capture_resolver_snapshot /etc/resolv.conf "$resolver_object_capture" '/etc /run' \
        /run/systemd/resolve "$resolver_runtime_uid" "$resolver_runtime_gid" \
        || failed 'resolver object or resolved target could not be captured safely'
    resolver_object_contract_is_exact \
        || failed 'the Debian resolver symlink changed during capture'
    vp_capture_run "$resolver_authority_after" resolver_authority_record \
        || failed 'the systemd-resolved authority could not be re-captured safely'
    cmp -s "$resolver_authority_before" "$resolver_authority_after" \
        || failed 'the systemd-resolved authority changed during capture'
    vp_capture_run "$resolver_capture" resolver_state_producer \
        "$resolver_authority_before" "$resolver_object_capture" \
        || failed 'the resolver authority and object capture could not be joined safely'
    vp_capture_publish_digest "$resolver_capture" "$destination/resolver" \
        || failed 'resolver capture could not be published'

    sysctls_capture=$capture_directory/sysctls.validated
    : >"$sysctls_capture"
    chmod 0600 "$sysctls_capture"
    for sysctl_path in \
        /proc/sys/net/ipv4/ip_forward \
        /proc/sys/net/ipv6/conf/all/forwarding \
        /proc/sys/net/ipv6/conf/default/forwarding
    do
        sysctl_value=$(cat "$sysctl_path") || failed 'host forwarding state could not be read'
        case $sysctl_value in 0|1) ;; *) failed 'host forwarding state is non-canonical' ;; esac
        printf '%s=%s\n' "$sysctl_path" "$sysctl_value" >>"$sysctls_capture" \
            || failed 'host forwarding capture could not be written'
    done
    vp_capture_file_is_safe "$sysctls_capture" \
        || failed 'host forwarding capture is not a validated private file'
    vp_capture_publish_digest "$sysctls_capture" "$destination/sysctls" \
        || failed 'host forwarding capture could not be published'

    vp_capture_run "$capture_directory/links.raw" ip -json link show \
        || failed 'host link producer failed'
    vp_capture_normalize "$capture_directory/links.raw" "$capture_directory/links.normalized" \
        link_state_producer || failed 'host link normalization failed'
    vp_capture_publish_digest "$capture_directory/links.normalized" "$destination/links" \
        || failed 'host link capture could not be published'

    vp_capture_run "$capture_directory/addresses.raw" ip -json address show \
        || failed 'host address producer failed'
    vp_capture_normalize "$capture_directory/addresses.raw" \
        "$capture_directory/addresses.normalized" address_state_producer \
        || failed 'host address normalization failed'
    vp_capture_publish_digest "$capture_directory/addresses.normalized" "$destination/addresses" \
        || failed 'host address capture could not be published'

    vp_capture_run "$capture_directory/routes-v4.raw" ip -json -4 route show table all \
        || failed 'host IPv4 route producer failed'
    vp_capture_run "$capture_directory/routes-v6.raw" ip -json -6 route show table all \
        || failed 'host IPv6 route producer failed'
    vp_capture_run "$capture_directory/routes.normalized" route_state_producer \
        "$capture_directory/routes-v4.raw" "$capture_directory/routes-v6.raw" \
        || failed 'host route normalization failed'
    vp_capture_publish_digest "$capture_directory/routes.normalized" "$destination/routes" \
        || failed 'host route capture could not be published'

    vp_capture_run "$capture_directory/rules-v4.raw" ip -json -4 rule show \
        || failed 'host IPv4 rule producer failed'
    vp_capture_run "$capture_directory/rules-v6.raw" ip -json -6 rule show \
        || failed 'host IPv6 rule producer failed'
    vp_capture_run "$capture_directory/rules.normalized" rule_state_producer \
        "$capture_directory/rules-v4.raw" "$capture_directory/rules-v6.raw" \
        || failed 'host rule normalization failed'
    vp_capture_publish_digest "$capture_directory/rules.normalized" "$destination/rules" \
        || failed 'host rule capture could not be published'

    vp_capture_run "$capture_directory/nexthops.raw" ip -json nexthop show \
        || failed 'host nexthop producer failed'
    vp_capture_normalize "$capture_directory/nexthops.raw" \
        "$capture_directory/nexthops.normalized" nexthop_state_producer \
        || failed 'host nexthop normalization failed'
    vp_capture_publish_digest "$capture_directory/nexthops.normalized" "$destination/nexthops" \
        || failed 'host nexthop capture could not be published'

    vp_capture_run "$capture_directory/qdiscs.raw" tc -json qdisc show \
        || failed 'host qdisc producer failed'
    vp_capture_normalize "$capture_directory/qdiscs.raw" \
        "$capture_directory/qdiscs.normalized" qdisc_state_producer \
        || failed 'host qdisc normalization failed'
    vp_capture_publish_digest "$capture_directory/qdiscs.normalized" "$destination/qdiscs" \
        || failed 'host qdisc capture could not be published'

    # The nftables JSON ruleset is also the authoritative state for
    # iptables-nft.  Bookend the separately registered legacy x_tables planes
    # with two identical normalized nft observations.  Never consult Debian's
    # mutable generic iptables alternatives.
    vp_capture_run "$capture_directory/nftables-a.raw" nft --json list ruleset \
        2>/dev/null \
        || failed 'host nftables first producer failed'
    vp_capture_normalize "$capture_directory/nftables-a.raw" \
        "$capture_directory/nftables-a.normalized" nftables_state_producer \
        || failed 'host nftables first normalization failed'

    capture_stable_legacy_firewall_state ipv4 /proc/self/net/ip_tables_names \
        0 0 440 /usr/sbin/iptables-legacy-save \
        "$capture_directory/legacy-ipv4" "$capture_directory/legacy-ipv4.stable" \
        || failed 'host legacy IPv4 firewall capture was not stable'
    capture_stable_legacy_firewall_state ipv6 /proc/self/net/ip6_tables_names \
        0 0 440 /usr/sbin/ip6tables-legacy-save \
        "$capture_directory/legacy-ipv6" "$capture_directory/legacy-ipv6.stable" \
        || failed 'host legacy IPv6 firewall capture was not stable'

    vp_capture_run "$capture_directory/nftables-b.raw" nft --json list ruleset \
        2>/dev/null \
        || failed 'host nftables second producer failed'
    vp_capture_normalize "$capture_directory/nftables-b.raw" \
        "$capture_directory/nftables-b.normalized" nftables_state_producer \
        || failed 'host nftables second normalization failed'
    cmp -s "$capture_directory/nftables-a.normalized" \
        "$capture_directory/nftables-b.normalized" \
        || failed 'host nftables capture was not stable'

    vp_capture_publish_digest "$capture_directory/nftables-a.normalized" \
        "$destination/nftables" || failed 'host nftables capture could not be published'
    vp_capture_publish_digest "$capture_directory/legacy-ipv4.stable" \
        "$destination/legacy_ipv4_firewall" \
        || failed 'host legacy IPv4 firewall capture could not be published'
    vp_capture_publish_digest "$capture_directory/legacy-ipv6.stable" \
        "$destination/legacy_ipv6_firewall" \
        || failed 'host legacy IPv6 firewall capture could not be published'

    # `wg dump` contains private key material. A validated 0600 FIFO streams it
    # directly to a separately checked SHA-256 consumer; raw bytes never enter
    # a regular file, shell variable, published record, or log.
    if command -v wg >/dev/null 2>&1; then
        vp_capture_stream_sha256 "$capture_directory/wireguard.fifo" \
            "$capture_directory/wireguard.digest" wg show all dump \
            || failed 'host WireGuard producer failed'
        publish_streamed_digest_record "$capture_directory/wireguard.digest" \
            "$destination/wireguard"
    else
        publish_absent_record "$destination/wireguard"
    fi

}

state_digest() {
    directory=$1
    aggregate=$directory/state.aggregate
    : >"$aggregate"
    chmod 0600 "$aggregate"
    for record in $state_records; do
        vp_capture_file_is_safe "$directory/$record" \
            || failed "host-state digest record is unsafe: $record"
        printf '%s\n' "$record" >>"$aggregate" \
            || failed 'host-state aggregate could not be written'
        cat "$directory/$record" >>"$aggregate" \
            || failed 'host-state digest record could not be aggregated'
    done
    vp_capture_file_is_safe "$aggregate" \
        || failed 'host-state aggregate is not a validated private file'
    vp_capture_sha256 "$aggregate" || failed 'host-state aggregate could not be hashed'
}

capture_host_state "$temporary_stage/before"
before_digest=$(state_digest "$temporary_stage/before")

capabilities='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'
account_binds="$temporary_stage/passwd:/etc/passwd:norbind $temporary_stage/group:/etc/group:norbind $temporary_stage/shadow:/etc/shadow:norbind $temporary_stage/nsswitch.conf:/etc/nsswitch.conf:norbind"
helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-live-proof:norbind"
system_bus_bind="$system_bus_socket:$system_bus_socket:norbind"
notify_socket_bind="$notify_socket:$notify_socket:norbind"

# The helper owns a 30-second spawn budget followed by a separate five-second
# FD-store publication budget and bounded local retirement. Keep PID1's outer
# limits strictly wider so they cannot pre-empt that fail-closed cleanup path.
# systemd v257 resolves User=/Group= before constructing the unit's mount
# namespace, so account files bound only inside that namespace cannot authorize
# the collision-free staged GID. PID 1 therefore installs only host-present
# root/root credentials. The fixed root-owned setpriv image then sets the raw
# staged primary GID plus exactly that one supplementary GID and execs the bound
# helper in the same MainPID. The diagnostic helper parent contract and the
# production hook independently attest that final identity together with the
# unchanged capability, seccomp and NNP envelope.
# Both staged helper entry paths exist only in the transient mount namespace.
# The fixed distro-only search path is also the child PATH. Type=exec binds the
# start job to successful execution of setpriv; terminal output and process/exe
# predicates separately require its exact helper replacement.
# Failed units remain loaded for terminal classification; bounded retirement
# resets and collects them later.
driver_phase=worker-launch
unit_may_own=yes
set +e
systemd-run \
    --json=short \
    --unit="$unit_name" \
    --slice=system.slice \
    --description="$unit_ownership_marker" \
    --service-type=exec \
    --remain-after-exit \
    --property=CollectMode=inactive \
    --property=RuntimeMaxSec=45s \
    --property=NotifyAccess=main \
    --property=FileDescriptorStoreMax=128 \
    --property=FileDescriptorStorePreserve=yes \
    --property=User=0 \
    --property=Group=0 \
    --property=SupplementaryGroups= \
    --property=UMask=0077 \
    --property=LimitCORE=0 \
    --property=LimitFSIZE=1048576 \
    --property=NoNewPrivileges=yes \
    --property="CapabilityBoundingSet=$capabilities" \
    --property="AmbientCapabilities=$capabilities" \
    --property=PrivateNetwork=yes \
    --property=PrivateMounts=yes \
    --property=PrivateTmp=yes \
    --property=PrivateDevices=no \
    --property=DevicePolicy=closed \
    --property='DeviceAllow=/dev/net/tun rw' \
    --property=ProtectSystem=strict \
    --property=ProtectHome=yes \
    --property=ProtectControlGroupsEx=strict \
    --property=Delegate=no \
    --property=PrivatePIDs=no \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectClock=yes \
    --property=ProtectHostname=yes \
    --property=LockPersonality=yes \
    --property=MemoryDenyWriteExecute=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=no \
    --property=RestrictNamespaces=net \
    --property=SystemCallArchitectures=native \
    --property='SystemCallFilter=@system-service @network-io seccomp' \
    --property='SystemCallFilter=~@mount' \
    --property=SystemCallErrorNumber=EPERM \
    --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
    --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
    --property="BindReadOnlyPaths=$helper_bind $account_binds $system_bus_bind $notify_socket_bind" \
    --property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin' \
    --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property=TimeoutStartSec=45s \
    --property=TimeoutStopSec=10s \
    --property=TasksMax=16 \
    --property=SetLoginEnvironment=no \
    --property="StandardOutput=file:$temporary_stage/proof.stdout" \
    --property="StandardError=file:$temporary_stage/proof.stderr" \
    /usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-live-proof --internal-worker-v3-live-proof \
    >"$temporary_stage/systemd-run.stdout" 2>"$temporary_stage/systemd-run.stderr"
run_status=$?
set -e
driver_phase=worker-terminal-observation

unset production_ok
proof_failure_reason=
proof_ok=yes
worker_confinement_failure=
worker_launch_captures_ok=no
worker_launch_json_ok=no
worker_manager_binding_ok=no
worker_launch_stderr_empty=no
if vp_capture_file_is_safe "$temporary_stage/systemd-run.stdout" \
    && vp_capture_file_is_safe "$temporary_stage/systemd-run.stderr"; then
    worker_launch_captures_ok=yes
    if [ ! -s "$temporary_stage/systemd-run.stderr" ]; then
        worker_launch_stderr_empty=yes
    fi
    parsed_invocation_id=$(jq -ers --arg expected_unit "$unit_name" '
        if length == 1
            and (.[0] | type) == "object"
            and (.[0] | keys) == ["invocation_id", "unit"]
            and .[0].unit == $expected_unit
            and (.[0].invocation_id | type) == "string"
        then .[0].invocation_id
        else empty
        end
    ' "$temporary_stage/systemd-run.stdout" 2>/dev/null) || parsed_invocation_id=
    if unit_invocation_id_is_safe "$parsed_invocation_id"; then
        worker_launch_json_ok=yes
        observed_unit_invocation_id=$(unit_current_invocation_id) \
            || observed_unit_invocation_id=
        if unit_description_matches_marker \
            && [ "$observed_unit_invocation_id" = "$parsed_invocation_id" ]; then
            unit_invocation_id=$parsed_invocation_id unit_owned=yes \
                unit_may_own=no
            worker_manager_binding_ok=yes
        fi
    fi
fi
# systemd v257 returns from a failed blocking Type=exec start job before its
# JSON InvocationID print path. Recover only that exact empty-stdout case from
# PID 1's independently pinned name, ownership marker and current nonzero ID.
# The missing JSON, nonzero status and systemd-run stderr still forbid PASS.
if [ "$worker_manager_binding_ok" != yes ]; then
    recover_failed_worker_manager_binding || true
fi
# Preserve the original generic first-failure precedence when no exact PID1
# binding exists. Only a bound current invocation may defer these predicates
# until after its helper-emitted stage has been considered.
if [ "$worker_manager_binding_ok" != yes ]; then
    record_worker_launch_failure
fi
poll_attempt=0
while :; do
    if ! unit_invocation_is_current; then
        record_proof_failure 'worker-terminal-state'
        break
    fi
    if ! active_state=$(systemctl show --property=ActiveState --value \
        "$unit_name" 2>/dev/null); then
        record_proof_failure 'worker-terminal-state'
        break
    fi
    if ! sub_state=$(systemctl show --property=SubState --value \
        "$unit_name" 2>/dev/null); then
        record_proof_failure 'worker-terminal-state'
        break
    fi
    if [ "$active_state:$sub_state" = active:exited ]; then
        break
    fi
    case $active_state in
        failed|inactive) break ;;
    esac
    poll_attempt=$((poll_attempt + 1))
    if [ "$poll_attempt" -ge 1000 ]; then
        record_proof_failure 'worker-terminal-state'
        break
    fi
    sleep 0.05
done
capture_unit_property() {
    [ "$#" -eq 2 ] || return 1
    unit_name_is_safe || return 1
    unit_invocation_is_current || return 1
    vp_capture_run "$2" systemctl show --property="$1" --value "$unit_name"
}
if capture_unit_property ActiveState "$temporary_stage/unit-active-state"; then
    active_state=$(cat "$temporary_stage/unit-active-state") \
        || record_proof_failure 'worker-terminal-state'
else
    active_state=
    record_proof_failure 'worker-terminal-state'
fi
if capture_unit_property SubState "$temporary_stage/unit-sub-state"; then
    sub_state=$(cat "$temporary_stage/unit-sub-state") \
        || record_proof_failure 'worker-terminal-state'
else
    sub_state=
    record_proof_failure 'worker-terminal-state'
fi
if capture_unit_property Result "$temporary_stage/unit-result"; then
    result=$(cat "$temporary_stage/unit-result") \
        || record_proof_failure 'worker-terminal-state'
else
    result=
    record_proof_failure 'worker-terminal-state'
fi
if capture_unit_property ExecMainStatus "$temporary_stage/unit-exec-status"; then
    exec_status=$(cat "$temporary_stage/unit-exec-status") \
        || record_proof_failure 'worker-terminal-state'
else
    exec_status=
    record_proof_failure 'worker-terminal-state'
fi
if capture_unit_property ExecMainCode "$temporary_stage/unit-exec-code"; then
    exec_code=$(cat "$temporary_stage/unit-exec-code") \
        || record_proof_failure 'worker-terminal-state'
else
    exec_code=
    record_proof_failure 'worker-terminal-state'
fi
# A helper stage is diagnostic authority only after PID1 has bound this exact
# invocation and reports that the staged main process itself returned the one
# fixed failure exit code. The classifier accepts byte-exact, private captures
# only; malformed, extra, truncated, or unknown records remain generic.
classify_worker_live_proof_terminal "$temporary_stage/proof.stderr" \
    || failed 'internal worker terminal classification is invalid'
if capture_unit_property NotifyAccess "$temporary_stage/unit-notify-access"; then
    observed_notify_access=$(cat "$temporary_stage/unit-notify-access") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_notify_access=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property Description "$temporary_stage/unit-description"; then
    observed_description=$(cat "$temporary_stage/unit-description") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_description=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property Environment "$temporary_stage/unit-environment"; then
    observed_environment=$(cat "$temporary_stage/unit-environment") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_environment=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property ExecSearchPath "$temporary_stage/unit-exec-search-path"; then
    observed_exec_search_path=$(cat "$temporary_stage/unit-exec-search-path") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_exec_search_path=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property CollectMode "$temporary_stage/unit-collect-mode"; then
    observed_collect_mode=$(cat "$temporary_stage/unit-collect-mode") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_collect_mode=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property Type "$temporary_stage/unit-type"; then
    observed_unit_type=$(cat "$temporary_stage/unit-type") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_unit_type=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property RemainAfterExit "$temporary_stage/unit-remain-after-exit"; then
    observed_remain_after_exit=$(cat "$temporary_stage/unit-remain-after-exit") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_remain_after_exit=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property RestrictSUIDSGID \
    "$temporary_stage/unit-restrict-suid-sgid"; then
    observed_restrict_suid_sgid=$(cat \
        "$temporary_stage/unit-restrict-suid-sgid") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_restrict_suid_sgid=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property RuntimeMaxUSec "$temporary_stage/unit-runtime-max"; then
    observed_runtime_max=$(cat "$temporary_stage/unit-runtime-max") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_runtime_max=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property FileDescriptorStoreMax "$temporary_stage/unit-fdstore-max"; then
    observed_fdstore_max=$(cat "$temporary_stage/unit-fdstore-max") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_fdstore_max=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property FileDescriptorStorePreserve \
    "$temporary_stage/unit-fdstore-preserve"; then
    observed_fdstore_preserve=$(cat "$temporary_stage/unit-fdstore-preserve") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_fdstore_preserve=
    record_proof_failure 'worker-unit-contract'
fi
if capture_unit_property NFileDescriptorStore "$temporary_stage/unit-fdstore-count"; then
    observed_fdstore_count=$(cat "$temporary_stage/unit-fdstore-count") \
        || record_proof_failure 'worker-unit-contract'
else
    observed_fdstore_count=
    record_proof_failure 'worker-unit-contract'
fi
if [ "$observed_notify_access" != main ] \
    || [ "$observed_description" != "$unit_ownership_marker" ] \
    || [ "$observed_environment" \
        != DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket ] \
    || [ "$observed_exec_search_path" != '/usr/sbin /usr/bin /sbin /bin' ] \
    || [ "$observed_collect_mode" != inactive ] \
    || [ "$observed_unit_type" != exec ] \
    || [ "$observed_remain_after_exit" != yes ] \
    || [ "$observed_restrict_suid_sgid" != no ] \
    || [ "$observed_runtime_max" != 45s ] \
    || [ "$observed_fdstore_max" != 128 ] \
    || [ "$observed_fdstore_preserve" != yes ] || [ "$observed_fdstore_count" != 2 ]; then
    record_proof_failure 'worker-unit-contract'
fi
worker_fdstore_before_retirement=$observed_fdstore_count
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass' \
    'VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass' \
    >"$temporary_stage/expected.stdout"
if ! cmp -s "$temporary_stage/expected.stdout" "$temporary_stage/proof.stdout" \
    || [ -s "$temporary_stage/proof.stderr" ]; then
    record_proof_failure 'worker-proof-records'
fi

normalize_capabilities() {
    [ "$#" -eq 2 ] || return 1
    # The dollar expressions below belong to awk, not the shell.
    # shellcheck disable=SC2016
    vp_capture_normalize "$1" "$2" awk -v expected="$capabilities" '
        BEGIN {
            expected_count = split(expected, ordered, " ")
            for (position = 1; position <= expected_count; position++) {
                allowed[ordered[position]] = 1
            }
        }
        {
            for (field = 1; field <= NF; field++) {
                capability = toupper($field)
                if (!(capability in allowed) || seen[capability]++) exit 1
                observed_count++
            }
        }
        END {
            if (observed_count != expected_count) exit 1
            print expected
        }
    '
}
if capture_unit_property CapabilityBoundingSet "$temporary_stage/unit-bounding.raw" \
    && normalize_capabilities "$temporary_stage/unit-bounding.raw" \
        "$temporary_stage/unit-bounding.normalized"; then
    observed_bounding=$(cat "$temporary_stage/unit-bounding.normalized") \
        || record_worker_confinement_failure 'bounding'
else
    observed_bounding=
    record_worker_confinement_failure 'bounding'
fi
if capture_unit_property AmbientCapabilities "$temporary_stage/unit-ambient.raw" \
    && normalize_capabilities "$temporary_stage/unit-ambient.raw" \
        "$temporary_stage/unit-ambient.normalized"; then
    observed_ambient=$(cat "$temporary_stage/unit-ambient.normalized") \
        || record_worker_confinement_failure 'ambient'
else
    observed_ambient=
    record_worker_confinement_failure 'ambient'
fi
if capture_unit_property PrivateNetwork "$temporary_stage/unit-private-network"; then
    observed_private_network=$(cat "$temporary_stage/unit-private-network") \
        || record_worker_confinement_failure 'private-network'
else
    observed_private_network=
    record_worker_confinement_failure 'private-network'
fi
# The helper's internal live proof has already pinned the parent and worker to
# the same cgroup path and inode while both processes exist. Once this retained
# Type=exec unit reaches active (exited), systemd releases its empty service
# cgroup and must report an empty ControlGroup. Require that exact terminal
# state, then require the persistent manager-owned system.slice placement and
# derive the one safe former cgroup path only for the retirement-absence check.
# The running production unit below continues to require a live ControlGroup.
if capture_unit_property ControlGroup "$temporary_stage/unit-control-group"; then
    observed_terminal_control_group=$(cat "$temporary_stage/unit-control-group") \
        || record_worker_confinement_failure 'control-group'
else
    observed_terminal_control_group=invalid
    record_worker_confinement_failure 'control-group'
fi
if capture_unit_property Slice "$temporary_stage/unit-slice"; then
    observed_slice=$(cat "$temporary_stage/unit-slice") \
        || record_worker_confinement_failure 'control-group'
else
    observed_slice=
    record_worker_confinement_failure 'control-group'
fi
if [ "$observed_bounding" != "$capabilities" ]; then
    record_worker_confinement_failure 'bounding'
fi
if [ "$observed_ambient" != "$capabilities" ]; then
    record_worker_confinement_failure 'ambient'
fi
if [ "$observed_private_network" != yes ]; then
    record_worker_confinement_failure 'private-network'
fi
if [ -n "$observed_terminal_control_group" ]; then
    record_worker_confinement_failure 'control-group'
fi
if [ "$observed_slice" != system.slice ]; then
    record_worker_confinement_failure 'control-group'
fi
worker_control_group=/system.slice/$unit_name

worker_unit_name=$unit_name
worker_invocation_id=$unit_invocation_id
worker_ownership_marker=$unit_ownership_marker
driver_phase=worker-retirement
if ! retire_unit; then
    cleanup_error=yes
    record_proof_failure 'worker-retirement'
fi

if [ "$proof_ok" = yes ]; then
    if [ -n "$unit_name" ] || [ "$unit_owned" != no ] || [ "$unit_may_own" != no ]; then
        record_proof_failure 'worker-retirement'
    else
        unit_name=$worker_unit_name
        reuse_load_state=$(unit_load_state) || reuse_load_state=
        worker_retired_load_state=$reuse_load_state
        if [ "$reuse_load_state" != not-found ] \
            || ! retired_runtime_is_absent \
                "$worker_unit_name" "$worker_control_group" 0 ''; then
            record_proof_failure 'worker-retirement'
        fi
    fi
fi

if [ "$proof_ok" = yes ]; then
    driver_phase=production-launch
    production_marker_line=$(printf '%s\n%s\n%s\n' \
        'VOLPAROSSA helper production IPC transient ownership marker v1' \
        "$unit_name" "$temporary_stage_identity" | sha256sum) \
        || failed 'production IPC ownership marker could not be derived'
    production_marker_digest=$(vp_capture_checksum_from_line "$production_marker_line") \
        || failed 'production IPC ownership marker is non-canonical'
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-$production_marker_digest
    if ! unit_ownership_marker_is_safe "$unit_ownership_marker" \
        || [ "$unit_ownership_marker" = "$worker_ownership_marker" ]; then
        failed 'production IPC ownership marker is unsafe or reused'
    fi

    production_helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-production:norbind"
    production_probe_bind="$temporary_stage/production-ipc-probe:/run/volparossa-helper-production-ipc-probe:norbind"
    production_hook_bind="$temporary_stage/production-ipc-hook:/run/volparossa-helper-production-ipc-hook:norbind"
    production_runtime_bind="$temporary_stage/production-runtime:/run/volparossa:norbind"
    production_output_bind="$temporary_stage/production-output:/run/volparossa-helper-production-proof:norbind"
    production_host_network_identity_file=$temporary_stage/production-host-network.identity
    if [ -e "$production_host_network_identity_file" ] \
        || [ -L "$production_host_network_identity_file" ]; then
        failed 'production host network identity path is not initially absent'
    fi
    production_driver_network_identity=$(stat -Lc '%d:%i' /proc/self/ns/net) \
        || failed 'production driver network identity could not be captured'
    production_host_network_identity=$(stat -Lc '%d:%i' /proc/1/ns/net) \
        || failed 'production host network identity could not be captured'
    [ "$production_driver_network_identity" = "$production_host_network_identity" ] \
        || failed 'production driver is not in PID 1 host network namespace'
    production_host_network_device=${production_host_network_identity%%:*}
    production_host_network_inode=${production_host_network_identity#*:}
    [ "$production_host_network_identity" = \
        "$production_host_network_device:$production_host_network_inode" ] \
        || failed 'production host network identity is ambiguous'
    for production_host_network_number in \
        "$production_host_network_device" "$production_host_network_inode"; do
        case $production_host_network_number in
            ''|0|0*|*[!0-9]*)
                failed 'production host network identity is non-canonical'
                ;;
        esac
    done
    vp_capture_run "$production_host_network_identity_file" \
        printf '%s\n' "$production_host_network_identity" \
        || failed 'production host network identity could not be published'
    vp_capture_file_is_safe "$production_host_network_identity_file" \
        || failed 'production host network identity record is unsafe'
    production_host_network_identity_bind="$production_host_network_identity_file:/run/volparossa-helper-production-host-network.identity:norbind"

    unit_may_own=yes
    set +e
    systemd-run \
        --json=short \
        --unit="$unit_name" \
        --slice=system.slice \
        --description="$unit_ownership_marker" \
        --service-type=exec \
        --property=CollectMode=inactive \
        --property=Restart=no \
        --property=RuntimeMaxSec=180s \
        --property=NotifyAccess=main \
        --property=FileDescriptorStoreMax=128 \
        --property=FileDescriptorStorePreserve=yes \
        --property=User=0 \
        --property=Group=0 \
        --property=SupplementaryGroups= \
        --property=UMask=0077 \
        --property=LimitCORE=0 \
        --property=LimitFSIZE=1048576 \
        --property=NoNewPrivileges=yes \
        --property="CapabilityBoundingSet=$capabilities" \
        --property="AmbientCapabilities=$capabilities" \
        --property=PrivateNetwork=yes \
        --property=PrivateMounts=yes \
        --property=PrivateTmp=yes \
        --property=PrivateDevices=no \
        --property=DevicePolicy=closed \
        --property='DeviceAllow=/dev/net/tun rw' \
        --property=ProtectSystem=strict \
        --property=ProtectHome=yes \
        --property=ProtectControlGroupsEx=strict \
        --property=Delegate=no \
        --property=PrivatePIDs=no \
        --property=ProtectKernelModules=yes \
        --property=ProtectKernelLogs=yes \
        --property=ProtectClock=yes \
        --property=ProtectHostname=yes \
        --property=LockPersonality=yes \
        --property=MemoryDenyWriteExecute=yes \
        --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=no \
        --property=RestrictNamespaces=net \
        --property=SystemCallArchitectures=native \
        --property='SystemCallFilter=@system-service @network-io seccomp' \
        --property='SystemCallFilter=~@mount' \
        --property=SystemCallErrorNumber=EPERM \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
        --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
        --property="BindReadOnlyPaths=$production_helper_bind $production_probe_bind $production_hook_bind $production_host_network_identity_bind $account_binds $system_bus_bind $notify_socket_bind" \
        --property="BindPaths=$production_runtime_bind $production_output_bind" \
        --property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin' \
        --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        --property="ExecStartPost=/usr/bin/setpriv --regid=$agent_gid --groups=$agent_gid -- /run/volparossa-helper-production-ipc-hook start $unit_name $agent_uid $agent_gid $operator_gid $worker_uid $worker_gid" \
        --property="ExecStopPost=/usr/bin/setpriv --regid=$agent_gid --groups=$agent_gid -- /run/volparossa-helper-production-ipc-hook stop $unit_name $agent_gid" \
        --property=KillSignal=SIGTERM \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=90s \
        --property=TimeoutStopSec=45s \
        --property=TasksMax=64 \
        --property=SetLoginEnvironment=no \
        --property=StandardOutput=null \
        --property=StandardError=null \
        /usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-production \
        >"$temporary_stage/systemd-run-production.stdout" \
        2>"$temporary_stage/systemd-run-production.stderr"
    production_run_status=$?
    set -e
    driver_phase=production-observation

    production_ok=yes
    if [ "$production_run_status" -ne 0 ]; then
        record_proof_failure 'production-launch-status'
    elif ! vp_capture_file_is_safe "$temporary_stage/systemd-run-production.stdout" \
        || ! vp_capture_file_is_safe "$temporary_stage/systemd-run-production.stderr"; then
        record_proof_failure 'production-launch-envelope'
    else
        production_invocation_id=$(jq -ers --arg expected_unit "$unit_name" '
            if length == 1
                and (.[0] | type) == "object"
                and (.[0] | keys) == ["invocation_id", "unit"]
                and .[0].unit == $expected_unit
                and (.[0].invocation_id | type) == "string"
            then .[0].invocation_id
            else empty
            end
        ' "$temporary_stage/systemd-run-production.stdout" 2>/dev/null) \
            || production_invocation_id=
        if ! unit_invocation_id_is_safe "$production_invocation_id" \
            || [ "$production_invocation_id" = "$worker_invocation_id" ] \
            || [ -s "$temporary_stage/systemd-run-production.stderr" ]; then
            record_proof_failure 'production-launch-envelope'
        else
            observed_unit_invocation_id=$(unit_current_invocation_id) \
                || observed_unit_invocation_id=
            if ! unit_description_matches_marker \
                || [ "$observed_unit_invocation_id" != "$production_invocation_id" ]; then
                record_proof_failure 'production-manager-binding'
            else
                unit_invocation_id=$production_invocation_id unit_owned=yes \
                    unit_may_own=no
            fi
        fi
    fi

    if [ "$unit_owned" = yes ]; then
        poll_attempt=0
        while :; do
            if ! unit_invocation_is_current; then
                record_proof_failure 'production-running-state'
                break
            fi
            active_state=$(systemctl show --property=ActiveState --value \
                "$unit_name" 2>/dev/null) || {
                record_proof_failure 'production-running-state'
                break
            }
            sub_state=$(systemctl show --property=SubState --value \
                "$unit_name" 2>/dev/null) || {
                record_proof_failure 'production-running-state'
                break
            }
            if [ "$active_state:$sub_state" = active:running ]; then
                break
            fi
            case $active_state in
                failed|inactive)
                    record_proof_failure 'production-running-state'
                    break
                    ;;
            esac
            poll_attempt=$((poll_attempt + 1))
            if [ "$poll_attempt" -ge 2000 ]; then
                record_proof_failure 'production-running-state'
                break
            fi
            sleep 0.05
        done
    else
        record_proof_failure 'production-running-state'
    fi

    if capture_unit_property ActiveState "$temporary_stage/production-active-state"; then
        production_active_state=$(cat "$temporary_stage/production-active-state") \
            || record_proof_failure 'production-running-state'
    else
        production_active_state=
        record_proof_failure 'production-running-state'
    fi
    if capture_unit_property SubState "$temporary_stage/production-sub-state"; then
        production_sub_state=$(cat "$temporary_stage/production-sub-state") \
            || record_proof_failure 'production-running-state'
    else
        production_sub_state=
        record_proof_failure 'production-running-state'
    fi
    if capture_unit_property Result "$temporary_stage/production-result"; then
        production_result=$(cat "$temporary_stage/production-result") \
            || record_proof_failure 'production-running-state'
    else
        production_result=
        record_proof_failure 'production-running-state'
    fi
    if capture_unit_property MainPID "$temporary_stage/production-main-pid"; then
        production_main_pid=$(cat "$temporary_stage/production-main-pid") \
            || record_proof_failure 'production-running-state'
    else
        production_main_pid=
        record_proof_failure 'production-running-state'
    fi
    case $production_main_pid in
        ''|0|*[!0-9]*) record_proof_failure 'production-running-state' ;;
    esac
    if [ "$production_active_state" != active ] \
        || [ "$production_sub_state" != running ] \
        || [ "$production_result" != success ]; then
        record_proof_failure 'production-running-state'
    fi

    if capture_unit_property NotifyAccess "$temporary_stage/production-notify-access"; then
        production_notify_access=$(cat "$temporary_stage/production-notify-access") \
            || record_proof_failure 'production-unit-contract'
    else
        production_notify_access=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property Description "$temporary_stage/production-description"; then
        production_description=$(cat "$temporary_stage/production-description") \
            || record_proof_failure 'production-unit-contract'
    else
        production_description=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property Environment "$temporary_stage/production-environment"; then
        production_environment=$(cat "$temporary_stage/production-environment") \
            || record_proof_failure 'production-unit-contract'
    else
        production_environment=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property ExecSearchPath \
        "$temporary_stage/production-exec-search-path"; then
        production_exec_search_path=$(cat \
            "$temporary_stage/production-exec-search-path") \
            || record_proof_failure 'production-unit-contract'
    else
        production_exec_search_path=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property CollectMode \
        "$temporary_stage/production-collect-mode"; then
        production_collect_mode=$(cat \
            "$temporary_stage/production-collect-mode") \
            || record_proof_failure 'production-unit-contract'
    else
        production_collect_mode=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property Type "$temporary_stage/production-type"; then
        production_unit_type=$(cat "$temporary_stage/production-type") \
            || record_proof_failure 'production-unit-contract'
    else
        production_unit_type=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property RemainAfterExit \
        "$temporary_stage/production-remain-after-exit"; then
        production_remain_after_exit=$(cat \
            "$temporary_stage/production-remain-after-exit") \
            || record_proof_failure 'production-unit-contract'
    else
        production_remain_after_exit=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property Slice "$temporary_stage/production-slice"; then
        production_slice=$(cat "$temporary_stage/production-slice") \
            || record_proof_failure 'production-unit-contract'
    else
        production_slice=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property RestrictSUIDSGID \
        "$temporary_stage/production-restrict-suid-sgid"; then
        production_restrict_suid_sgid=$(cat \
            "$temporary_stage/production-restrict-suid-sgid") \
            || record_proof_failure 'production-unit-contract'
    else
        production_restrict_suid_sgid=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property FileDescriptorStoreMax \
        "$temporary_stage/production-fdstore-max"; then
        production_fdstore_max=$(cat "$temporary_stage/production-fdstore-max") \
            || record_proof_failure 'production-unit-contract'
    else
        production_fdstore_max=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property FileDescriptorStorePreserve \
        "$temporary_stage/production-fdstore-preserve"; then
        production_fdstore_preserve=$(cat "$temporary_stage/production-fdstore-preserve") \
            || record_proof_failure 'production-unit-contract'
    else
        production_fdstore_preserve=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property NFileDescriptorStore \
        "$temporary_stage/production-fdstore-count"; then
        production_fdstore_count=$(cat "$temporary_stage/production-fdstore-count") \
            || record_proof_failure 'production-unit-contract'
    else
        production_fdstore_count=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property RuntimeMaxUSec \
        "$temporary_stage/production-runtime-max"; then
        production_runtime_max=$(cat "$temporary_stage/production-runtime-max") \
            || record_proof_failure 'production-unit-contract'
    else
        production_runtime_max=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property LimitFSIZE "$temporary_stage/production-limit-fsize"; then
        production_limit_fsize=$(cat "$temporary_stage/production-limit-fsize") \
            || record_proof_failure 'production-unit-contract'
    else
        production_limit_fsize=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property LimitFSIZESoft \
        "$temporary_stage/production-limit-fsize-soft"; then
        production_limit_fsize_soft=$(cat "$temporary_stage/production-limit-fsize-soft") \
            || record_proof_failure 'production-unit-contract'
    else
        production_limit_fsize_soft=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property StandardOutput \
        "$temporary_stage/production-standard-output"; then
        production_standard_output=$(cat "$temporary_stage/production-standard-output") \
            || record_proof_failure 'production-unit-contract'
    else
        production_standard_output=
        record_proof_failure 'production-unit-contract'
    fi
    if capture_unit_property StandardError \
        "$temporary_stage/production-standard-error"; then
        production_standard_error=$(cat "$temporary_stage/production-standard-error") \
            || record_proof_failure 'production-unit-contract'
    else
        production_standard_error=
        record_proof_failure 'production-unit-contract'
    fi
    if [ "$production_notify_access" != main ] \
        || [ "$production_description" != "$unit_ownership_marker" ] \
        || [ "$production_environment" \
            != DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket ] \
        || [ "$production_exec_search_path" \
            != '/usr/sbin /usr/bin /sbin /bin' ] \
        || [ "$production_collect_mode" != inactive ] \
        || [ "$production_unit_type" != exec ] \
        || [ "$production_remain_after_exit" != no ] \
        || [ "$production_slice" != system.slice ] \
        || [ "$production_restrict_suid_sgid" != no ] \
        || [ "$production_fdstore_max" != 128 ] \
        || [ "$production_fdstore_preserve" != yes ] \
        || [ "$production_fdstore_count" != 0 ] \
        || [ "$production_runtime_max" != 3min ] \
        || [ "$production_limit_fsize" != 1048576 ] \
        || [ "$production_limit_fsize_soft" != 1048576 ] \
        || [ "$production_standard_output" != null ] \
        || [ "$production_standard_error" != null ]; then
        record_proof_failure 'production-unit-contract'
    fi
    production_fdstore_during_run=$production_fdstore_count

    if capture_unit_property CapabilityBoundingSet \
        "$temporary_stage/production-bounding.raw" \
        && normalize_capabilities "$temporary_stage/production-bounding.raw" \
            "$temporary_stage/production-bounding.normalized"; then
        production_bounding=$(cat "$temporary_stage/production-bounding.normalized") \
            || record_proof_failure 'production-confinement'
    else
        production_bounding=
        record_proof_failure 'production-confinement'
    fi
    if capture_unit_property AmbientCapabilities "$temporary_stage/production-ambient.raw" \
        && normalize_capabilities "$temporary_stage/production-ambient.raw" \
            "$temporary_stage/production-ambient.normalized"; then
        production_ambient=$(cat "$temporary_stage/production-ambient.normalized") \
            || record_proof_failure 'production-confinement'
    else
        production_ambient=
        record_proof_failure 'production-confinement'
    fi
    if capture_unit_property PrivateNetwork "$temporary_stage/production-private-network"; then
        production_private_network=$(cat "$temporary_stage/production-private-network") \
            || record_proof_failure 'production-confinement'
    else
        production_private_network=
        record_proof_failure 'production-confinement'
    fi
    if capture_unit_property ControlGroup "$temporary_stage/production-control-group"; then
        production_control_group=$(cat "$temporary_stage/production-control-group") \
            || record_proof_failure 'production-confinement'
    else
        production_control_group=
        record_proof_failure 'production-confinement'
    fi
    if [ "$production_bounding" != "$capabilities" ] \
        || [ "$production_ambient" != "$capabilities" ] \
        || [ "$production_private_network" != yes ] \
        || [ "$production_control_group" != "/system.slice/$unit_name" ]; then
        record_proof_failure 'production-confinement'
    fi

    # Keep every downstream retirement operand defined even when the bounded
    # identity artifact is absent or unsafe. The recorded fixed predicate must
    # reach normal final reporting instead of an errexit/set-u status 2.
    identity_invocation=
    identity_main_pid=
    identity_launch=
    identity_launch_image=
    identity_starttime=
    identity_starttime_value=
    identity_process_contract=
    identity_extra=
    identity_seccomp_filters=
    production_identity=$temporary_stage/production-output/unit.identity
    if vp_capture_file_is_safe "$production_identity"; then
        identity_invocation=$(sed -n '1p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        identity_main_pid=$(sed -n '2p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        identity_launch=$(sed -n '3p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        identity_launch_image=$(sed -n '4p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        identity_starttime=$(sed -n '5p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        identity_process_contract=$(sed -n '6p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        identity_extra=$(sed -n '7p' "$production_identity") \
            || record_proof_failure 'production-process-identity'
        if ! systemd_launch_record_is_safe "$identity_launch" \
            "$production_main_pid" "$agent_gid"; then
            record_proof_failure 'production-process-identity'
        fi
        if ! launch_image_record_is_safe \
            "$identity_launch_image" "$staged_digest"; then
            record_proof_failure 'production-process-identity'
        fi
        identity_starttime_prefix=process-starttime-v1=
        case $identity_starttime in
            "$identity_starttime_prefix"*)
                identity_starttime_value=${identity_starttime#"$identity_starttime_prefix"}
                ;;
            *)
                identity_starttime_value=
                record_proof_failure 'production-process-identity'
                ;;
        esac
        case $identity_starttime_value in
            ''|0|0*|*[!0-9]*)
                record_proof_failure 'production-process-identity'
                ;;
            *)
                if [ "${#identity_starttime_value}" -gt 20 ]; then
                    record_proof_failure 'production-process-identity'
                fi
                ;;
        esac
        expected_process_contract_prefix="process-status-v1=uid:0:0:0:0;gid:$agent_gid:$agent_gid:$agent_gid:$agent_gid;groups:$agent_gid;nnp:1;seccomp:2;caps:00000000002031e0;filters:"
        case $identity_process_contract in
            "$expected_process_contract_prefix"*)
                identity_seccomp_filters=${identity_process_contract#"$expected_process_contract_prefix"}
                ;;
            *)
                identity_seccomp_filters=
                record_proof_failure 'production-process-identity'
                ;;
        esac
        case $identity_seccomp_filters in
            ''|0|0*|*[!0-9]*)
                record_proof_failure 'production-process-identity'
                ;;
            *)
                if [ "${#identity_seccomp_filters}" -gt 10 ] \
                    || [ "$identity_seccomp_filters" -gt 1024 ]; then
                    record_proof_failure 'production-process-identity'
                fi
                ;;
        esac
        if [ "$identity_invocation" != "$unit_invocation_id" ] \
            || [ "$identity_main_pid" != "$production_main_pid" ] \
            || [ -n "$identity_extra" ]; then
            record_proof_failure 'production-process-identity'
        fi
    else
        record_proof_failure 'production-process-identity'
    fi

    production_socket_identity_file=$temporary_stage/production-output/socket.identity
    if vp_capture_file_is_safe "$production_socket_identity_file"; then
        expected_production_socket_identity=$(cat "$production_socket_identity_file") \
            || record_proof_failure 'production-socket-identity'
    else
        expected_production_socket_identity=
        record_proof_failure 'production-socket-identity'
    fi
    production_socket_identity=$(stat -c '%d:%i:%F:%u:%g:%a:%h' \
        "$temporary_stage/production-runtime/helper.sock" 2>/dev/null) \
        || production_socket_identity=
    case $production_socket_identity in
        *":socket:0:$agent_gid:660:1") ;;
        *) record_proof_failure 'production-socket-identity' ;;
    esac
    if [ "$production_socket_identity" != "$expected_production_socket_identity" ]; then
        record_proof_failure 'production-socket-identity'
    fi

    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_ACTIVATED_KERNEL_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_COMMITTED_KERNEL_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_EXTERNAL_CLEANUP_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=ready' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_ACTIVATED_KERNEL_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_COMMITTED_KERNEL_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_EXTERNAL_CLEANUP_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=ready' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_ACTIVATED_KERNEL_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_COMMITTED_KERNEL_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_EXTERNAL_CLEANUP_V1=pass' \
        >"$temporary_stage/expected-production-start.pass"
    if ! vp_capture_file_is_safe "$temporary_stage/production-output/start.pass" \
        || ! cmp -s "$temporary_stage/expected-production-start.pass" \
            "$temporary_stage/production-output/start.pass"; then
        record_proof_failure 'production-start-records'
    fi

    if [ "$(stat -c '%F:%u:%g:%a' "$temporary_stage/production-runtime" \
        2>/dev/null || true)" != "directory:0:$agent_gid:750" ] \
        || [ "$(stat -c '%F:%u:%g:%a:%h' \
            "$temporary_stage/production-runtime/helper.sock" 2>/dev/null || true)" \
            != "socket:0:$agent_gid:660:1" ] \
        || [ "$(stat -c '%F:%u:%g:%a:%h:%s' \
            "$temporary_stage/production-runtime/helper.cleanup-token" 2>/dev/null || true)" \
            != "regular file:0:$agent_gid:640:1:32" ] \
        || [ "$(stat -c '%f:%u:%g:%a:%h' \
            "$temporary_stage/production-runtime/helper.ownership-v3.lock" \
            2>/dev/null || true)" != "8180:0:$agent_gid:600:1" ] \
        || [ -e "$temporary_stage/production-runtime/helper.ownership-v3.next" ] \
        || [ -L "$temporary_stage/production-runtime/helper.ownership-v3.next" ]; then
        record_proof_failure 'production-runtime-layout'
    fi
    if [ -e "$temporary_stage/production-runtime/helper.ownership-v3" ] \
        || [ -L "$temporary_stage/production-runtime/helper.ownership-v3" ]; then
        if [ "$(stat -c '%f:%u:%g:%a:%h' \
            "$temporary_stage/production-runtime/helper.ownership-v3" \
            2>/dev/null || true)" != "8180:0:$agent_gid:600:1" ]; then
            record_proof_failure 'production-runtime-layout'
        fi
    fi

    if ! unit_invocation_is_current; then
        record_proof_failure 'production-process-stability'
    fi
    final_main_pid=$(systemctl show --property=MainPID --value "$unit_name" 2>/dev/null) \
        || final_main_pid=
    if [ "$final_main_pid" != "$production_main_pid" ]; then
        record_proof_failure 'production-process-stability'
    fi

    production_retirement_confirmed=no
    production_unit_name=$unit_name
    driver_phase=production-retirement
    if ! retire_unit; then
        cleanup_error=yes
        record_proof_failure 'production-retirement'
        failed 'production unit retirement did not settle'
    fi
    if [ -n "$unit_name" ] || [ "$unit_owned" != no ] \
        || [ "$unit_may_own" != no ] || [ -n "$unit_invocation_id" ] \
        || [ -n "$unit_ownership_marker" ]; then
        record_proof_failure 'production-retirement'
        failed 'production unit retirement retained affine ownership state'
    fi
    unit_name=$production_unit_name
    production_retired_load_state=$(unit_load_state) || production_retired_load_state=
    if [ "$production_retired_load_state" != not-found ] \
        || ! retired_runtime_is_absent "$production_unit_name" \
            "$production_control_group" "$production_main_pid" \
            "$identity_starttime_value"; then
        record_proof_failure 'production-retirement'
        failed 'production unit retirement fence did not settle'
    fi
    forget_unit_ownership
    production_retirement_confirmed=yes
    production_lock_path=$temporary_stage/production-runtime/helper.ownership-v3.lock
    production_lock_identity_file=$temporary_stage/production-output/lock.identity
    if vp_capture_file_is_safe "$production_lock_identity_file"; then
        expected_production_lock_identity=$(cat "$production_lock_identity_file") \
            || record_proof_failure 'production-lock-release'
    else
        expected_production_lock_identity=
        record_proof_failure 'production-lock-release'
    fi
    production_lock_path_before=$(stat -c '%d:%i:%f:%u:%g:%a:%h' \
        "$production_lock_path" 2>/dev/null) || production_lock_path_before=
    case $production_lock_path_before in
        *":8180:0:$agent_gid:600:1") ;;
        *) record_proof_failure 'production-lock-release' ;;
    esac
    if [ "$production_lock_path_before" != "$expected_production_lock_identity" ]; then
        record_proof_failure 'production-lock-release'
    fi
    # `exec` is a POSIX special builtin; a redirection failure may otherwise
    # terminate a non-interactive shell with status 2 before the fixed failure
    # predicate and cleanup path run. `command` removes that special status.
    if command exec 9<>"$production_lock_path"; then
        production_lock_fd_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h' \
            /proc/self/fd/9 2>/dev/null) || production_lock_fd_identity=
        if [ "$production_lock_fd_identity" != "$expected_production_lock_identity" ] \
            || ! /usr/bin/flock -n 9; then
            record_proof_failure 'production-lock-release'
        fi
        production_lock_path_after=$(stat -c '%d:%i:%f:%u:%g:%a:%h' \
            "$production_lock_path" 2>/dev/null) || production_lock_path_after=
        if [ "$production_lock_path_after" != "$expected_production_lock_identity" ]; then
            record_proof_failure 'production-lock-release'
        fi
        command exec 9>&- || record_proof_failure 'production-lock-release'
    else
        record_proof_failure 'production-lock-release'
    fi
    printf '%s\n' 'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass' \
        >"$temporary_stage/expected-production-stop.pass"
    if ! vp_capture_file_is_safe "$temporary_stage/production-output/stop.pass" \
        || ! cmp -s "$temporary_stage/expected-production-stop.pass" \
            "$temporary_stage/production-output/stop.pass" \
        || [ -e "$temporary_stage/production-runtime/helper.sock" ] \
        || [ -L "$temporary_stage/production-runtime/helper.sock" ] \
        || [ -e "$temporary_stage/production-runtime/helper.ownership-v3.next" ] \
        || [ -L "$temporary_stage/production-runtime/helper.ownership-v3.next" ]; then
        record_proof_failure 'production-stop-records'
    fi
    printf '%s\n' 'VOLPAROSSA_HELPER_V3_FUNCTIONAL_FDSTORE_CYCLES_V1=pass' \
        >"$temporary_stage/expected-production-fdstore-cycles.pass"
    printf '%s\n' 'VOLPAROSSA_HELPER_V3_FUNCTIONAL_JOURNAL_SETTLED_V1=pass' \
        >"$temporary_stage/expected-production-journal.settled"
    if vp_capture_file_is_safe \
        "$temporary_stage/production-output/fdstore-cycles.pass" \
        && cmp -s "$temporary_stage/expected-production-fdstore-cycles.pass" \
            "$temporary_stage/production-output/fdstore-cycles.pass"; then
        production_fdstore_active_counts='2 2 2'
        production_fdstore_settled_counts='0 0 0'
        production_fdstore_identity_bound=true
    else
        record_proof_failure 'production-stop-records'
    fi
    if vp_capture_file_is_safe \
        "$temporary_stage/production-output/journal.settled" \
        && cmp -s "$temporary_stage/expected-production-journal.settled" \
            "$temporary_stage/production-output/journal.settled" \
        && vp_capture_file_is_safe \
            "$temporary_stage/production-output/journal.settled.state"; then
        production_journal_settled_absent=true
    else
        record_proof_failure 'production-stop-records'
    fi

    # `retire_unit`/`forget_unit_ownership` deliberately clears every affine
    # unit field. Derive a second six-character name which is provably distinct
    # from the collected production name, while retaining the same closed unit
    # grammar and private run binding. This avoids manager/client ambiguity from
    # immediately re-creating one just-collected transient unit object.
    prepare_restart_unit_identity \
        || failed 'production unit retirement was not confirmed before restart'
    driver_phase=restart-launch
    unit_name_is_safe || failed 'singleton restart unit name is unsafe'
    [ "$unit_name" != "$production_unit_name" ] \
        || failed 'singleton restart unit name is not distinct'
    restart_initial_load_state=$(unit_load_state) \
        || failed 'singleton restart unit state could not be determined'
    [ "$restart_initial_load_state" = not-found ] \
        || failed 'singleton restart unit name is already loaded'
    restart_symbol_counts=$(nm -C "$temporary_stage/volparossa-helper" \
        | awk '
          $3 == "volparossa_helper::systemd_fdstore::remove_current_process_custody" {
            current_all++
            if ($2 ~ /^[Tt]$/) current_text++
          }
          $3 == "volparossa_helper::systemd_fdstore::remove_restart_custody" {
            restart_all++
            if ($2 ~ /^[Tt]$/) restart_text++
          }
          END {
            print current_all + 0 ":" current_text + 0 ":" \
                  restart_all + 0 ":" restart_text + 0
          }
        ') || failed 'restart debugger symbols could not be inspected'
    [ "$restart_symbol_counts" = '1:1:1:1' ] \
        || failed 'restart debugger symbols are not exact and unique'
    restart_marker_line=$(printf '%s\n%s\n%s\n' \
        'VOLPAROSSA helper singleton ExactPresent restart marker v1' \
        "$unit_name" "$temporary_stage_identity" | sha256sum) \
        || failed 'restart ownership marker could not be derived'
    restart_marker_digest=$(vp_capture_checksum_from_line "$restart_marker_line") \
        || failed 'restart ownership marker is non-canonical'
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-$restart_marker_digest
    unit_ownership_marker_is_safe "$unit_ownership_marker" \
        || failed 'restart ownership marker is unsafe'
    restart_observer_bind="$temporary_stage/restart-observer:/run/volparossa-helper-restart-observer:norbind"
    restart_launcher_bind="$temporary_stage/restart-launcher:/run/volparossa-helper-restart-launcher:norbind"
    restart_output_bind="$temporary_stage/restart-output:/run/volparossa-helper-production-proof:norbind"
    restart_debugger_initial_commands=$temporary_stage/restart-debugger-initial.gdb
    restart_debugger_successor_commands=$temporary_stage/restart-debugger-successor.gdb
    restart_debugger_initial_stdout=$temporary_stage/restart-debugger-initial.stdout
    restart_debugger_initial_stderr=$temporary_stage/restart-debugger-initial.stderr
    restart_debugger_successor_stdout=$temporary_stage/restart-debugger-successor.stdout
    restart_debugger_successor_stderr=$temporary_stage/restart-debugger-successor.stderr
    for restart_absent_path in \
        "$restart_debugger_initial_commands" "$restart_debugger_successor_commands" \
        "$restart_debugger_initial_stdout" "$restart_debugger_initial_stderr" \
        "$restart_debugger_successor_stdout" "$restart_debugger_successor_stderr"; do
        if [ -e "$restart_absent_path" ] || [ -L "$restart_absent_path" ]; then
            failed 'restart debugger path was not initially absent'
        fi
    done

    unit_may_own=yes
    set +e
    systemd-run \
        --no-block \
        --json=short \
        --unit="$unit_name" \
        --slice=system.slice \
        --description="$unit_ownership_marker" \
        --service-type=exec \
        --property=CollectMode=inactive \
        --property=Restart=on-failure \
        --property=RestartSec=10s \
        --property=StartLimitBurst=2 \
        --property=RuntimeMaxSec=240s \
        --property=NotifyAccess=main \
        --property=FileDescriptorStoreMax=128 \
        --property=FileDescriptorStorePreserve=yes \
        --property=User=0 \
        --property=Group=0 \
        --property=SupplementaryGroups= \
        --property=UMask=0077 \
        --property=LimitCORE=0 \
        --property=LimitFSIZE=1048576 \
        --property=NoNewPrivileges=yes \
        --property="CapabilityBoundingSet=$capabilities" \
        --property="AmbientCapabilities=$capabilities" \
        --property=PrivateNetwork=yes \
        --property=PrivateMounts=yes \
        --property=PrivateTmp=yes \
        --property=PrivateDevices=no \
        --property=DevicePolicy=closed \
        --property='DeviceAllow=/dev/net/tun rw' \
        --property=ProtectSystem=strict \
        --property=ProtectHome=yes \
        --property=ProtectControlGroupsEx=strict \
        --property=Delegate=no \
        --property=PrivatePIDs=no \
        --property=ProtectKernelModules=yes \
        --property=ProtectKernelLogs=yes \
        --property=ProtectClock=yes \
        --property=ProtectHostname=yes \
        --property=LockPersonality=yes \
        --property=MemoryDenyWriteExecute=yes \
        --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=no \
        --property=RestrictNamespaces=net \
        --property=SystemCallArchitectures=native \
        --property='SystemCallFilter=@system-service @network-io seccomp' \
        --property='SystemCallFilter=~@mount' \
        --property=SystemCallErrorNumber=EPERM \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
        --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
        --property="BindReadOnlyPaths=$production_helper_bind $production_probe_bind $production_hook_bind $restart_observer_bind $restart_launcher_bind $production_host_network_identity_bind $account_binds $system_bus_bind $notify_socket_bind" \
        --property="BindPaths=$production_runtime_bind $restart_output_bind" \
        --property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin' \
        --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        --property="ExecStartPost=/usr/bin/setpriv --regid=$agent_gid --groups=$agent_gid -- /run/volparossa-helper-production-ipc-hook restart-start $unit_name $agent_uid $agent_gid $operator_gid $worker_uid $worker_gid" \
        --property=KillSignal=SIGTERM \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=180s \
        --property=TimeoutStopSec=45s \
        --property=TasksMax=64 \
        --property=SetLoginEnvironment=no \
        --property=StandardOutput=null \
        --property=StandardError=null \
        /usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-restart-launcher \
        >"$temporary_stage/systemd-run-restart.stdout" \
        2>"$temporary_stage/systemd-run-restart.stderr"
    restart_run_status=$?
    set -e
    [ "$restart_run_status" -eq 0 ] \
        || failed 'singleton restart unit could not be launched'
    restart_launch_captures_ok=no
    restart_launch_json_ok=no
    restart_launch_fresh=no
    restart_launch_stdout=unsafe
    restart_launch_stderr=unsafe
    restart_launch_binding_ok=no
    restart_launch_manager_binding_ok=no
    restart_initial_invocation_id=
    if vp_capture_file_is_safe "$temporary_stage/systemd-run-restart.stdout" \
        && vp_capture_file_is_safe "$temporary_stage/systemd-run-restart.stderr"; then
        restart_launch_captures_ok=yes
        if [ ! -s "$temporary_stage/systemd-run-restart.stdout" ]; then
            restart_launch_stdout=empty
        elif jq -ers -e --arg expected_unit "$unit_name" '
            length == 1
                and (.[0] | type) == "object"
                and (.[0] | keys) == ["unit"]
                and .[0].unit == $expected_unit
        ' "$temporary_stage/systemd-run-restart.stdout" \
            >/dev/null 2>&1; then
            # With --no-block, systemd v257 may print the exact JSON unit
            # identity before PID 1 has assigned a nonzero InvocationID.
            # Bind that pending launch only through the separately verified
            # Description marker and current manager InvocationID below.
            restart_launch_stdout=unit-only
        else
            restart_launch_stdout=nonempty
        fi
        if [ -s "$temporary_stage/systemd-run-restart.stderr" ]; then
            restart_launch_stderr=nonempty
        else
            restart_launch_stderr=empty
        fi
        restart_initial_invocation_id=$(jq -ers --arg expected_unit "$unit_name" '
            if length == 1
               and (.[0] | type) == "object"
               and (.[0] | keys) == ["invocation_id","unit"]
               and .[0].unit == $expected_unit
               and (.[0].invocation_id | type) == "string"
            then .[0].invocation_id else empty end
        ' "$temporary_stage/systemd-run-restart.stdout" 2>/dev/null) \
            || restart_initial_invocation_id=
        if unit_invocation_id_is_safe "$restart_initial_invocation_id"; then
            restart_launch_json_ok=yes
            if [ "$restart_initial_invocation_id" != "$production_invocation_id" ]; then
                restart_launch_fresh=yes
            fi
        fi
    fi
    if [ "$restart_launch_captures_ok" = yes ] \
        && [ "$restart_launch_json_ok" = yes ] \
        && [ "$restart_launch_fresh" = yes ] \
        && [ "$restart_launch_stderr" = empty ]; then
        restart_observed_invocation_id=$(unit_current_invocation_id 2>/dev/null) \
            || restart_observed_invocation_id=
        if [ "$restart_observed_invocation_id" = \
            "$restart_initial_invocation_id" ] \
            && unit_description_matches_marker; then
            unit_invocation_id=$restart_initial_invocation_id unit_owned=yes \
                unit_may_own=no
            if unit_invocation_is_current && unit_description_matches_marker; then
                restart_launch_binding_ok=yes
            else
                unit_may_own=yes unit_owned=no unit_invocation_id=
            fi
        fi
        [ "$restart_launch_binding_ok" = yes ] \
            || failed 'singleton restart manager binding is invalid'
    elif recover_successful_restart_manager_binding; then
        restart_launch_manager_binding_ok=yes
        restart_launch_binding_ok=yes
    fi
    if [ "$restart_launch_binding_ok" != yes ]; then
        printf 'VOLPAROSSA_HELPER_LIVE_RESTART_LAUNCH_DIAGNOSTIC_V1=captures-%s,json-%s,fresh-%s,stdout-%s,stderr-%s,manager-%s\n' \
            "$restart_launch_captures_ok" "$restart_launch_json_ok" \
            "$restart_launch_fresh" "$restart_launch_stdout" \
            "$restart_launch_stderr" \
            "$restart_launch_manager_binding_ok" >&2
        failed 'singleton restart launch envelope is invalid'
    fi

    restart_wait=0
    while ! vp_capture_file_is_safe \
        "$temporary_stage/restart-output/restart.precrash"; do
        restart_wait=$((restart_wait + 1))
        [ "$restart_wait" -lt 1800 ] \
            || failed 'singleton restart precrash identity did not appear'
        sleep 0.05
    done
    restart_initial_pid=$(systemctl show --property=MainPID --value "$unit_name") \
        || failed 'singleton restart initial MainPID is unavailable'
    case $restart_initial_pid in ''|0|0*|*[!0-9]*) failed 'singleton restart initial MainPID is invalid' ;; esac
    [ "$(sed -n '1p' "$temporary_stage/restart-output/restart.precrash")" = \
        "$restart_initial_invocation_id" ] \
        || failed 'singleton restart initial invocation is not hook-bound'
    [ "$(sed -n '2p' "$temporary_stage/restart-output/restart.precrash")" = \
        "$restart_initial_pid" ] \
        || failed 'singleton restart initial MainPID is not hook-bound'
    restart_initial_hook_pid=$(sed -n '8p' \
        "$temporary_stage/restart-output/restart.precrash") \
        || failed 'singleton restart initial hook PID is unavailable'
    case $restart_initial_hook_pid in
        ''|0|0*|*[!0-9]*) failed 'singleton restart initial hook PID is invalid' ;;
    esac
    if [ "${#restart_initial_hook_pid}" -gt 10 ] \
        || [ "$restart_initial_hook_pid" -gt 4294967294 ]; then
        failed 'singleton restart initial hook PID is invalid'
    fi
    [ "$(systemctl show --property=ControlPID --value "$unit_name")" = \
        "$restart_initial_hook_pid" ] \
        || failed 'singleton restart initial ControlPID is not hook-bound'
    restart_initial_hook_starttime=$(capture_process_starttime \
        "$restart_initial_hook_pid") \
        || failed 'singleton restart initial hook starttime is unavailable'

    /usr/bin/nsenter --mount="/proc/$restart_initial_pid/ns/mnt" -- \
        /usr/bin/sleep 120 &
    restart_mount_keeper_pid=$!
    case $restart_mount_keeper_pid in ''|0|0*|*[!0-9]*) failed 'restart mount keeper PID is invalid' ;; esac
    restart_mount_keeper_starttime=$(capture_process_starttime \
        "$restart_mount_keeper_pid") \
        || failed 'restart mount keeper starttime is unavailable'
    sleep 0.05
    kill -0 "$restart_mount_keeper_pid" 2>/dev/null \
        || failed 'restart mount namespace keeper did not survive'

    # GDB convenience variables must remain literal in the generated file.
    # shellcheck disable=SC2016
    printf '%s\n' \
        'set pagination off' \
        'set confirm off' \
        'set breakpoint pending off' \
        'break volparossa_helper::systemd_fdstore::remove_current_process_custody' \
        'commands' \
        'silent' \
        "shell /usr/bin/nsenter --mount=/proc/$restart_initial_pid/ns/mnt -- /run/volparossa-helper-restart-observer cleanup-confirmed $unit_name $agent_gid $restart_initial_pid" \
        'if !$_isvoid($_shell_exitcode) && $_shell_exitcode == 0' \
        'kill' \
        'quit 0' \
        'else' \
        'detach' \
        'quit 1' \
        'end' \
        'end' \
        "shell /usr/bin/nsenter --mount=/proc/$restart_initial_pid/ns/mnt -- /run/volparossa-helper-restart-observer armed $unit_name $agent_gid $restart_initial_pid" \
        'if !$_isvoid($_shell_exitcode) && $_shell_exitcode == 0' \
        'continue' \
        'else' \
        'detach' \
        'quit 1' \
        'end' >"$restart_debugger_initial_commands" \
        || failed 'initial restart debugger commands could not be written'
    chmod 0600 "$restart_debugger_initial_commands"
    set +e
    timeout --preserve-status --signal=TERM --kill-after=5s 30s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        "$debugger_path" --batch --quiet --nx \
            --pid="$restart_initial_pid" \
            --command="$restart_debugger_initial_commands" \
        >"$restart_debugger_initial_stdout" \
        2>"$restart_debugger_initial_stderr"
    restart_initial_debugger_status=$?
    set -e
    restart_postcrash_main_pid=$(systemctl show --property=MainPID --value "$unit_name") \
        || failed 'post-crash restart MainPID is unavailable'
    restart_postcrash_count=$(systemctl show --property=NRestarts --value "$unit_name") \
        || failed 'post-crash restart count is unavailable'
    restart_unit_result=$(systemctl show --property=Result --value "$unit_name") \
        || failed 'restart unit result is unavailable'
    restart_exec_main_code=$(systemctl show --property=ExecMainCode --value "$unit_name") \
        || failed 'restart ExecMainCode is unavailable'
    restart_exec_main_status=$(systemctl show --property=ExecMainStatus --value "$unit_name") \
        || failed 'restart ExecMainStatus is unavailable'
    [ "$restart_postcrash_main_pid" = 0 ] \
        || failed 'post-crash forced-helper MainPID is not zero'
    [ "$restart_postcrash_count" = 0 ] \
        || failed 'post-crash forced-helper restart count is not zero'
    [ "$restart_unit_result" = signal ] \
        || failed 'post-crash forced-helper result is not signal'
    # `systemctl show` renders the signed ExecMainCode D-Bus property as its
    # numeric siginfo value; Linux CLD_KILLED is exactly 2.
    [ "$restart_exec_main_code" = 2 ] \
        || failed 'post-crash forced-helper code is not CLD_KILLED'
    [ "$restart_exec_main_status" = 9 ] \
        || failed 'post-crash forced-helper status is not SIGKILL'
    if [ "$(unit_load_state)" != loaded ] \
        || ! unit_description_matches_marker \
        || [ "$unit_invocation_id" != "$restart_initial_invocation_id" ] \
        || ! unit_invocation_is_current; then
        failed 'post-crash failed invocation lost its exact ownership fence'
    fi
    unit_may_own=yes unit_owned=no unit_invocation_id=
    if ! vp_capture_file_is_safe \
        "$temporary_stage/restart-output/restart.crash"; then
        report_restart_crash_record_diagnostic \
            "$temporary_stage/restart-output/restart.crash" \
            "$restart_debugger_initial_stderr" || true
        failed 'forced-crash boundary record is unavailable'
    fi
    for restart_debugger_log in \
        "$restart_debugger_initial_stdout" "$restart_debugger_initial_stderr"; do
        vp_capture_file_is_safe "$restart_debugger_log" \
            || failed 'initial debugger log is unsafe'
        [ "$(stat -Lc '%s' "$restart_debugger_log")" -le 1048576 ] \
            || failed 'initial debugger log exceeds 1 MiB'
    done
    # The breakpoint command terminates GDB explicitly with `quit 0` after its
    # own `kill`. Accept only that exact terminal status, and only after PID 1,
    # the ownership marker, the boundary observer, and both bounded debugger
    # logs independently prove the exact forced crash.
    case $restart_initial_debugger_status in
        0) ;;
        *) failed 'initial forced-crash debugger did not complete' ;;
    esac
    if ! consume_expected_restart_initial_start_failure \
        "$temporary_stage/restart-output/start.failure"; then
        report_restart_initial_start_failure_diagnostic \
            "$temporary_stage/restart-output/restart.initial-start.failure-stage" \
            || true
        failed 'initial forced-crash start failure record was not consumed exactly'
    fi
    restart_crashed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
        || failed 'forced-crash time is unavailable'
    /usr/bin/nsenter --mount="/proc/$restart_mount_keeper_pid/ns/mnt" -- \
        /run/volparossa-helper-restart-observer after-crash \
            "$unit_name" "$agent_gid" "$restart_initial_pid" \
        || failed 'post-crash exact custody was not preserved'
    restart_initial_after_crash_observed=yes
    if ! release_expected_restart_initial_terminal \
        "$temporary_stage/restart-output/restart.initial-start.terminal" \
        "$temporary_stage/restart-output/restart.initial-start.failure-stage"; then
        report_restart_initial_start_failure_diagnostic \
            "$temporary_stage/restart-output/restart.initial-start.failure-stage" \
            || true
        failed 'initial forced-crash terminal handshake was not released exactly'
    fi

    driver_phase=restart-observation
    restart_wait=0
    restart_successor_pid=
    while :; do
        restart_successor_pid=$(systemctl show --property=MainPID --value \
            "$unit_name" 2>/dev/null || true)
        case $restart_successor_pid in
            ''|0|0*|*[!0-9]*) ;;
            *)
                if [ "$restart_successor_pid" != "$restart_initial_pid" ]; then
                    break
                fi
                ;;
        esac
        restart_wait=$((restart_wait + 1))
        [ "$restart_wait" -lt 600 ] \
            || failed 'restart successor did not become manager-bound'
        sleep 0.05
    done
    restart_successor_barrier=$temporary_stage/restart-output/restart.successor-barrier
    restart_wait=0
    while ! vp_capture_file_is_safe "$restart_successor_barrier"; do
        if [ "$(systemctl show --property=MainPID --value "$unit_name" \
            2>/dev/null || true)" != "$restart_successor_pid" ]; then
            failed 'restart successor changed before its pre-exec barrier'
        fi
        restart_wait=$((restart_wait + 1))
        [ "$restart_wait" -lt 600 ] \
            || failed 'restart successor pre-exec barrier did not appear'
        sleep 0.05
    done
    [ "$(stat -Lc '%s' "$restart_successor_barrier")" -le 256 ] \
        || failed 'restart successor pre-exec barrier is oversized'
    restart_successor_barrier_invocation=$(sed -n '2p' \
        "$restart_successor_barrier") \
        || failed 'restart successor barrier invocation is unavailable'
    restart_successor_barrier_pid=$(sed -n '3p' "$restart_successor_barrier") \
        || failed 'restart successor barrier PID is unavailable'
    restart_expected_barrier=$temporary_stage/restart-successor-barrier.expected
    install -o root -g root -m 0600 /dev/null "$restart_expected_barrier" \
        || failed 'restart successor barrier expectation could not be created'
    printf '%s\n%s\n%s\n' \
        'VOLPAROSSA_HELPER_RESTART_SUCCESSOR_BARRIER_V1=ready' \
        "$restart_successor_barrier_invocation" \
        "$restart_successor_barrier_pid" >"$restart_expected_barrier" \
        || failed 'restart successor barrier expectation is unavailable'
    if ! vp_capture_file_is_safe "$restart_expected_barrier" \
        || ! cmp -s "$restart_expected_barrier" \
            "$restart_successor_barrier" \
        || ! unit_invocation_id_is_safe \
            "$restart_successor_barrier_invocation" \
        || [ "$restart_successor_barrier_invocation" = \
            "$restart_initial_invocation_id" ] \
        || [ "$restart_successor_barrier_pid" != "$restart_successor_pid" ] \
        || [ "$(unit_current_invocation_id 2>/dev/null || true)" != \
            "$restart_successor_barrier_invocation" ]; then
        failed 'restart successor pre-exec barrier is not manager-bound'
    fi
    restart_successor_starttime=$(capture_process_starttime \
        "$restart_successor_pid") \
        || failed 'restart successor starttime is unavailable'
    restart_successor_restart_count=$(systemctl show \
        --property=NRestarts --value "$unit_name") \
        || failed 'restart successor count is unavailable'
    [ "$restart_successor_restart_count" = 1 ] \
        || failed 'restart successor count is not exactly one'
    unit_description_matches_marker \
        || failed 'restart successor lost the ownership marker'
    adopt_tentative_unit \
        || failed 'restart successor lineage could not be adopted'
    restart_successor_invocation_id=$unit_invocation_id
    if ! unit_invocation_id_is_safe "$restart_successor_invocation_id" \
        || [ "$restart_successor_invocation_id" = \
            "$restart_initial_invocation_id" ]; then
        failed 'restart successor invocation is invalid'
    fi
    if [ "$(systemctl show --property=MainPID --value "$unit_name")" != \
        "$restart_successor_pid" ] \
        || [ "$(capture_process_starttime "$restart_successor_pid")" != \
            "$restart_successor_starttime" ] \
        || [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 1 ] \
        || ! unit_invocation_is_current \
        || ! unit_description_matches_marker; then
        failed 'restart successor lineage changed after adoption'
    fi
    restart_successor_tracer_ready=$temporary_stage/restart-successor-tracer.ready
    # GDB convenience variables must remain literal in the generated file.
    # shellcheck disable=SC2016
    printf '%s\n' \
        'set pagination off' \
        'set confirm off' \
        'set breakpoint pending off' \
        'tcatch exec' \
        "shell printf '%s\\n' ready >$restart_successor_tracer_ready" \
        'continue' \
        'echo VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=exec-caught\n' \
        'break volparossa_helper::systemd_fdstore::remove_restart_custody' \
        'echo VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-installed\n' \
        'commands' \
        'silent' \
        'echo VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-hit\n' \
        "shell /usr/bin/nsenter --mount=/proc/$restart_successor_pid/ns/mnt -- /run/volparossa-helper-restart-observer recovery-boundary $unit_name $agent_gid $restart_successor_pid" \
        'if !$_isvoid($_shell_exitcode) && $_shell_exitcode == 0' \
        'echo VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-ok\n' \
        'detach' \
        'quit 0' \
        'else' \
        'echo VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-failed\n' \
        'detach' \
        'quit 1' \
        'end' \
        'end' \
        'continue' >"$restart_debugger_successor_commands" \
        || failed 'successor debugger commands could not be written'
    chmod 0600 "$restart_debugger_successor_commands"
    timeout --preserve-status --signal=TERM --kill-after=5s 45s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        "$debugger_path" --batch --quiet --nx \
            --pid="$restart_successor_pid" \
            --command="$restart_debugger_successor_commands" \
        >"$restart_debugger_successor_stdout" \
        2>"$restart_debugger_successor_stderr" &
    restart_successor_debugger_pid=$!
    restart_successor_debugger_starttime=$(capture_process_starttime \
        "$restart_successor_debugger_pid") \
        || failed 'successor debugger starttime is unavailable'
    restart_wait=0
    while [ ! -f "$restart_successor_tracer_ready" ]; do
        kill -0 "$restart_successor_debugger_pid" 2>/dev/null \
            || failed 'successor debugger exited before arming'
        restart_wait=$((restart_wait + 1))
        [ "$restart_wait" -lt 600 ] \
            || failed 'successor debugger did not arm'
        sleep 0.05
    done
    vp_capture_file_is_safe "$restart_successor_tracer_ready" \
        || failed 'successor debugger readiness record is unsafe'
    [ "$(stat -Lc '%s' "$restart_successor_tracer_ready")" -le 16 ] \
        || failed 'successor debugger readiness record is oversized'
    [ "$(cat "$restart_successor_tracer_ready")" = ready ] \
        || failed 'successor debugger readiness record is invalid'
    [ "$(stat -Lc '%F:%u:%g:%a:%h' "$restart_successor_release_fifo" \
        2>/dev/null || true)" = 'fifo:0:0:600:1' ] \
        || failed 'restart successor release FIFO changed before release'
    # The inner shell receives the already validated FIFO as positional `$1`.
    # shellcheck disable=SC2016
    timeout --preserve-status --signal=TERM --kill-after=1s 5s \
        /bin/sh -c 'printf %s G >"$1"' sh \
        "$restart_successor_release_fifo" \
        || failed 'restart successor pre-exec barrier could not be released'
    [ "$(stat -Lc '%F:%u:%g:%a:%h' "$restart_successor_release_fifo" \
        2>/dev/null || true)" = 'fifo:0:0:600:1' ] \
        || failed 'restart successor release FIFO changed after release'
    set +e
    wait "$restart_successor_debugger_pid"
    restart_successor_debugger_status=$?
    set -e
    restart_successor_debugger_pid=
    restart_successor_debugger_starttime=
    for restart_debugger_log in \
        "$restart_debugger_successor_stdout" "$restart_debugger_successor_stderr"; do
        vp_capture_file_is_safe "$restart_debugger_log" \
            || failed 'successor debugger log is unsafe'
        [ "$(stat -Lc '%s' "$restart_debugger_log")" -le 1048576 ] \
            || failed 'successor debugger log exceeds 1 MiB'
    done
    if [ "$restart_successor_debugger_status" -ne 0 ]; then
        restart_successor_debugger_failure=$(
            restart_successor_debugger_failure_category \
                "$restart_successor_debugger_status" \
                "$restart_debugger_successor_stdout" \
                "$restart_debugger_successor_stderr"
        ) || failed 'successor debugger failure classification is invalid'
        restart_successor_debugger_failure_category_is_safe \
            "$restart_successor_debugger_failure" \
            || failed 'successor debugger failure classification is invalid'
        failed "successor recovery-boundary debugger failed: $restart_successor_debugger_failure"
    fi
    restart_successor_boundary=$temporary_stage/restart-output/restart.recovery-boundary
    if ! vp_capture_file_is_safe "$restart_successor_boundary" \
        || [ -e "$restart_successor_boundary.next" ] \
        || [ -L "$restart_successor_boundary.next" ] \
        || [ "$(stat -Lc '%s' "$restart_successor_boundary")" -gt 512 ] \
        || [ "$(wc -l <"$restart_successor_boundary")" -ne 6 ]; then
        failed 'successor recovery boundary is not exact'
    fi
    restart_successor_boundary_time=$(sed -n '1p' \
        "$restart_successor_boundary") \
        || failed 'successor recovery boundary is not exact'
    case $restart_successor_boundary_time in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
        *) failed 'successor recovery boundary is not exact' ;;
    esac
    restart_successor_boundary_time_canonical=$(date -u -d \
        "$restart_successor_boundary_time" '+%Y-%m-%dT%H:%M:%SZ' \
        2>/dev/null) \
        || failed 'successor recovery boundary is not exact'
    if [ "$restart_successor_boundary_time_canonical" != \
        "$restart_successor_boundary_time" ] \
        || [ "$(sed -n '2p' "$restart_successor_boundary")" != \
            "$restart_successor_invocation_id" ] \
        || [ "$(sed -n '3p' "$restart_successor_boundary")" != \
            "$restart_successor_pid" ] \
        || [ "$(sed -n '4p' "$restart_successor_boundary")" != \
            "$restart_successor_starttime" ] \
        || [ "$(sed -n '5p' "$restart_successor_boundary")" != \
            'startup-removal-call-v1=systemd_fdstore::remove_restart_custody' ] \
        || [ "$(sed -n '6p' "$restart_successor_boundary")" != \
            'manager-fdstore-before-removal-v1=2' ]; then
        failed 'successor recovery boundary is not exact'
    fi
    kill "$restart_mount_keeper_pid" 2>/dev/null || true
    wait "$restart_mount_keeper_pid" 2>/dev/null || true
    restart_mount_keeper_pid=
    restart_mount_keeper_starttime=

    restart_wait=0
    while ! vp_capture_file_is_safe \
        "$temporary_stage/restart-output/restart.resumed"; do
        restart_successor_start_failure_file=$temporary_stage/restart-output/start.failure
        if [ -e "$restart_successor_start_failure_file" ] \
            || [ -L "$restart_successor_start_failure_file" ]; then
            restart_successor_start_failure=$(
                restart_successor_start_failure_category \
                    "$restart_successor_start_failure_file"
            ) || failed 'restart successor start failure record is invalid'
            restart_readiness_failure_file=$temporary_stage/restart-output/restart.readiness-failure
            case $restart_successor_start_failure in
                preflight)
                    failed 'restart successor start hook failed during preflight' ;;
                recovery-wait)
                    failed 'restart successor start hook failed during recovery wait' ;;
                lineage)
                    failed 'restart successor start hook failed during lineage validation' ;;
                descriptor-settlement)
                    failed 'restart successor start hook failed during descriptor settlement' ;;
                journal-settlement)
                    if [ -e "$restart_readiness_failure_file" ] \
                        || [ -L "$restart_readiness_failure_file" ] \
                        || [ -e "$restart_readiness_failure_file.next" ] \
                        || [ -L "$restart_readiness_failure_file.next" ]; then
                        report_restart_readiness_failure_diagnostic \
                            "$restart_readiness_failure_file" \
                            || failed 'restart successor readiness diagnostic is invalid'
                    fi
                    failed 'restart successor start hook failed during journal settlement' ;;
                socket-validation)
                    report_restart_readiness_failure_diagnostic \
                        "$restart_readiness_failure_file" \
                        || failed 'restart successor readiness diagnostic is invalid'
                    failed 'restart successor start hook failed during socket validation' ;;
                publication)
                    failed 'restart successor start hook failed during publication' ;;
                *) failed 'restart successor start failure category is invalid' ;;
            esac
        fi
        if [ -e "$restart_successor_start_failure_file.next" ] \
            || [ -L "$restart_successor_start_failure_file.next" ]; then
            vp_capture_file_is_safe "$restart_successor_start_failure_file.next" \
                || failed 'restart successor pending start failure record is unsafe'
        fi
        restart_wait=$((restart_wait + 1))
        [ "$restart_wait" -lt 2400 ] \
            || failed 'restart ExactPresent settlement did not complete'
        sleep 0.05
    done
    restart_resumed_invocation_id=$(sed -n '3p' \
        "$temporary_stage/restart-output/restart.resumed") \
        || failed 'restart successor invocation record is unavailable'
    unit_invocation_id_is_safe "$restart_resumed_invocation_id" \
        || failed 'restart successor invocation record is invalid'
    [ "$restart_resumed_invocation_id" = "$restart_successor_invocation_id" ] \
        || failed 'restart settlement changed the adopted successor invocation'
    unit_invocation_id=$restart_resumed_invocation_id
    driver_phase=restart-retirement
    restart_unit_name=$unit_name
    if ! retire_unit; then
        cleanup_error=yes
        retire_failure_stage_is_safe "$retire_failure_stage" \
            || failed 'restart successor retirement failure category is invalid'
        printf 'VOLPAROSSA_HELPER_LIVE_RESTART_RETIREMENT_DIAGNOSTIC_V1=%s\n' \
            "$retire_failure_stage" >&2 \
            || failed 'restart successor retirement diagnostic could not be reported'
        failed 'restart successor could not be retired'
    fi
    unit_name=$restart_unit_name
    restart_retired_load_state=$(unit_load_state) || restart_retired_load_state=
    [ "$restart_retired_load_state" = not-found ] \
        || failed 'restart unit was not collected'
    forget_unit_ownership
    restart_journal_state_record=$temporary_stage/restart-output/restart.journal.settled.state
    restart_expected_journal_state=$(capture_restart_journal_state_record \
        "$restart_journal_state_record" "$agent_gid") \
        || failed 'restart final journal could not be revalidated'
    restart_lock_path=$temporary_stage/production-runtime/helper.ownership-v3.lock
    case $expected_production_lock_identity in
        *":8180:0:$agent_gid:600:1") ;;
        *) failed 'restart journal lock could not be opened after retirement' ;;
    esac
    restart_lock_path_before=$(stat -c '%d:%i:%f:%u:%g:%a:%h' \
        "$restart_lock_path" 2>/dev/null) || restart_lock_path_before=
    [ "$restart_lock_path_before" = "$expected_production_lock_identity" ] \
        || failed 'restart journal lock could not be opened after retirement'
    if command exec 9<"$restart_lock_path"; then
        restart_lock_fd_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h' \
            /proc/self/fd/9 2>/dev/null) || restart_lock_fd_identity=
        [ "$restart_lock_fd_identity" = "$expected_production_lock_identity" ] \
            || failed 'restart journal lock could not be opened after retirement'
        /usr/bin/flock -n 9 || failed 'restart journal lock remained held'
        restart_lock_path_after_flock=$(stat -c '%d:%i:%f:%u:%g:%a:%h' \
            "$restart_lock_path" 2>/dev/null) || restart_lock_path_after_flock=
        [ "$restart_lock_path_after_flock" = \
            "$expected_production_lock_identity" ] \
            || failed 'restart journal lock could not be opened after retirement'
        if [ -e "$temporary_stage/production-runtime/helper.sock" ] \
            || [ -L "$temporary_stage/production-runtime/helper.sock" ] \
            || [ -e "$temporary_stage/production-runtime/helper.ownership-v3.next" ] \
            || [ -L "$temporary_stage/production-runtime/helper.ownership-v3.next" ]; then
            failed 'restart runtime did not retire cleanly'
        fi
        restart_final_journal_state=$(capture_restart_journal_state \
            "$temporary_stage/production-runtime/helper.ownership-v3" \
            "$agent_gid") \
            || failed 'restart final journal could not be revalidated'
        if [ -e "$temporary_stage/production-runtime/helper.sock" ] \
            || [ -L "$temporary_stage/production-runtime/helper.sock" ] \
            || [ -e "$temporary_stage/production-runtime/helper.ownership-v3.next" ] \
            || [ -L "$temporary_stage/production-runtime/helper.ownership-v3.next" ]; then
            failed 'restart runtime did not retire cleanly'
        fi
        [ "$restart_final_journal_state" = \
            "$restart_expected_journal_state" ] \
            || failed 'restart final journal proof is invalid'
        restart_revalidated_expected_journal_state=$( \
            capture_restart_journal_state_record \
                "$restart_journal_state_record" "$agent_gid" \
        ) || failed 'restart final journal could not be revalidated'
        [ "$restart_revalidated_expected_journal_state" = \
            "$restart_expected_journal_state" ] \
            || failed 'restart final journal could not be revalidated'
        printf '%s\n' "$restart_expected_journal_state" \
            | cmp -s - "$restart_journal_state_record" \
            || failed 'restart final journal could not be revalidated'
        restart_lock_path_final=$(stat -c '%d:%i:%f:%u:%g:%a:%h' \
            "$restart_lock_path" 2>/dev/null) || restart_lock_path_final=
        [ "$restart_lock_path_final" = "$expected_production_lock_identity" ] \
            || failed 'restart journal lock could not be opened after retirement'
        unit_name=$restart_unit_name
        restart_final_load_state=$(unit_load_state) || restart_final_load_state=
        [ "$restart_final_load_state" = not-found ] \
            || failed 'restart unit was not collected'
        forget_unit_ownership
        command exec 9>&- \
            || failed 'restart journal lock could not be opened after retirement'
    else
        failed 'restart journal lock could not be opened after retirement'
    fi
    restart_evidence_validated=true

    prepare_may_own_unit_identity \
        || failed 'ExactPresent retirement was not confirmed before MayOwn proof'
    driver_phase=may-own-launch
    unit_name_is_safe || failed 'MayOwn singleton unit name is unsafe'
    may_own_initial_load_state=$(unit_load_state) \
        || failed 'MayOwn singleton unit state could not be determined'
    [ "$may_own_initial_load_state" = not-found ] \
        || failed 'MayOwn singleton unit name is already loaded'
    may_own_symbol_counts=$(nm -C "$temporary_stage/volparossa-helper" | awk '
        /volparossa_helper::worker_v3::DurableCustodyPublicationTerminalGuard::retain_published/ {
            retained_all++
            if ($2 ~ /^[Tt]$/) retained_text++
        }
        /volparossa_helper::ownership_journal::actor::DurableOwnershipStartup::confirm_single_restart_cleanup/ {
            confirmed_all++
            if ($2 ~ /^[Tt]$/) confirmed_text++
        }
        $3 == "volparossa_helper::systemd_fdstore::remove_restart_custody" {
            removal_all++
            if ($2 ~ /^[Tt]$/) removal_text++
        }
        END {
            print retained_all + 0 ":" retained_text + 0 ":" \
                confirmed_all + 0 ":" confirmed_text + 0 ":" \
                removal_all + 0 ":" removal_text + 0
        }
    ') || failed 'MayOwn debugger symbols could not be inspected'
    [ "$may_own_symbol_counts" = '1:1:1:1:1:1' ] \
        || failed 'MayOwn debugger symbols are not exact and unique'
    may_own_marker_line=$(printf '%s\n%s\n%s\n' \
        'VOLPAROSSA helper singleton MayOwn Relay restart marker v1' \
        "$unit_name" "$temporary_stage_identity" | sha256sum) \
        || failed 'MayOwn ownership marker could not be derived'
    may_own_marker_digest=$(vp_capture_checksum_from_line "$may_own_marker_line") \
        || failed 'MayOwn ownership marker is non-canonical'
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-$may_own_marker_digest
    unit_ownership_marker_is_safe "$unit_ownership_marker" \
        || failed 'MayOwn ownership marker is unsafe'
    may_own_observer_bind="$temporary_stage/may-own-observer:/run/volparossa-helper-may-own-observer:norbind"
    may_own_output_bind="$temporary_stage/may-own-output:/run/volparossa-helper-production-proof:norbind"
    may_own_debugger_one_commands=$temporary_stage/may-own-debugger-one.gdb
    may_own_debugger_two_commands=$temporary_stage/may-own-debugger-two.gdb
    may_own_debugger_three_commands=$temporary_stage/may-own-debugger-three.gdb
    for may_own_absent_path in \
        "$may_own_debugger_one_commands" "$may_own_debugger_two_commands" \
        "$may_own_debugger_three_commands"; do
        if [ -e "$may_own_absent_path" ] || [ -L "$may_own_absent_path" ]; then
            failed 'MayOwn debugger command path was not initially absent'
        fi
    done

    unit_may_own=yes
    set +e
    systemd-run \
        --no-block \
        --json=short \
        --unit="$unit_name" \
        --slice=system.slice \
        --description="$unit_ownership_marker" \
        --service-type=simple \
        --property=CollectMode=inactive \
        --property=Restart=on-failure \
        --property='RestartPreventExitStatus=70 71' \
        --property=RestartSec=3s \
        --property=StartLimitBurst=3 \
        --property=RuntimeMaxSec=360s \
        --property=NotifyAccess=main \
        --property=FileDescriptorStoreMax=128 \
        --property=FileDescriptorStorePreserve=yes \
        --property=User=0 \
        --property=Group=0 \
        --property=SupplementaryGroups= \
        --property=UMask=0077 \
        --property=LimitCORE=0 \
        --property=LimitFSIZE=1048576 \
        --property=NoNewPrivileges=yes \
        --property="CapabilityBoundingSet=$capabilities" \
        --property="AmbientCapabilities=$capabilities" \
        --property=PrivateNetwork=yes \
        --property=PrivateMounts=yes \
        --property=PrivateTmp=yes \
        --property=PrivateDevices=no \
        --property=DevicePolicy=closed \
        --property='DeviceAllow=/dev/net/tun rw' \
        --property=ProtectSystem=strict \
        --property=ProtectHome=yes \
        --property=ProtectControlGroupsEx=strict \
        --property=Delegate=no \
        --property=PrivatePIDs=no \
        --property=ProtectKernelModules=yes \
        --property=ProtectKernelLogs=yes \
        --property=ProtectClock=yes \
        --property=ProtectHostname=yes \
        --property=LockPersonality=yes \
        --property=MemoryDenyWriteExecute=yes \
        --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=no \
        --property=RestrictNamespaces=net \
        --property=SystemCallArchitectures=native \
        --property='SystemCallFilter=@system-service @network-io seccomp' \
        --property='SystemCallFilter=~@mount' \
        --property=SystemCallErrorNumber=EPERM \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
        --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
        --property="BindReadOnlyPaths=$production_helper_bind $production_probe_bind $production_hook_bind $restart_launcher_bind $may_own_observer_bind $production_host_network_identity_bind $account_binds $system_bus_bind $notify_socket_bind" \
        --property="BindPaths=$production_runtime_bind $may_own_output_bind" \
        --property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin' \
        --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        --property=Environment=VOLPAROSSA_HELPER_PREEXEC_MODE=may-own \
        --property=KillSignal=SIGTERM \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=240s \
        --property=TimeoutStopSec=45s \
        --property=TasksMax=64 \
        --property=SetLoginEnvironment=no \
        --property=StandardOutput=null \
        --property=StandardError=null \
        /usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-restart-launcher \
        >"$temporary_stage/systemd-run-may-own.stdout" \
        2>"$temporary_stage/systemd-run-may-own.stderr"
    may_own_run_status=$?
    set -e
    [ "$may_own_run_status" -eq 0 ] \
        || failed 'MayOwn singleton unit could not be launched'
    may_own_launch_captures_ok=no
    may_own_launch_json_ok=no
    may_own_launch_fresh=no
    may_own_launch_stdout=unsafe
    may_own_launch_stderr=unsafe
    may_own_launch_binding_ok=no
    may_own_invocation_one=
    if vp_capture_file_is_safe "$temporary_stage/systemd-run-may-own.stdout" \
        && vp_capture_file_is_safe "$temporary_stage/systemd-run-may-own.stderr"; then
        may_own_launch_captures_ok=yes
        if [ ! -s "$temporary_stage/systemd-run-may-own.stdout" ]; then
            may_own_launch_stdout=empty
        elif jq -ers -e --arg expected_unit "$unit_name" '
            length == 1
                and (.[0] | type) == "object"
                and (.[0] | keys) == ["unit"]
                and .[0].unit == $expected_unit
        ' "$temporary_stage/systemd-run-may-own.stdout" \
            >/dev/null 2>&1; then
            may_own_launch_stdout=unit-only
        else
            may_own_launch_stdout=nonempty
        fi
        if [ -s "$temporary_stage/systemd-run-may-own.stderr" ]; then
            may_own_launch_stderr=nonempty
        else
            may_own_launch_stderr=empty
        fi
        may_own_invocation_one=$(jq -ers --arg expected_unit "$unit_name" '
            if length == 1
               and (.[0] | type) == "object"
               and (.[0] | keys) == ["invocation_id","unit"]
               and .[0].unit == $expected_unit
               and (.[0].invocation_id | type) == "string"
            then .[0].invocation_id else empty end
        ' "$temporary_stage/systemd-run-may-own.stdout" 2>/dev/null) \
            || may_own_invocation_one=
        if unit_invocation_id_is_safe "$may_own_invocation_one"; then
            may_own_launch_json_ok=yes
            if [ "$may_own_invocation_one" != "$worker_invocation_id" ] \
                && [ "$may_own_invocation_one" != "$production_invocation_id" ] \
                && [ "$may_own_invocation_one" != \
                    "$restart_initial_invocation_id" ] \
                && [ "$may_own_invocation_one" != \
                    "$restart_successor_invocation_id" ]; then
                may_own_launch_fresh=yes
            fi
        fi
    fi
    if [ "$may_own_launch_captures_ok" = yes ] \
        && [ "$may_own_launch_json_ok" = yes ] \
        && [ "$may_own_launch_fresh" = yes ] \
        && [ "$may_own_launch_stderr" = empty ]; then
        unit_invocation_id=$may_own_invocation_one unit_owned=yes unit_may_own=no
        if unit_invocation_is_current && unit_description_matches_marker; then
            may_own_launch_binding_ok=yes
        else
            unit_may_own=yes unit_owned=no unit_invocation_id=
        fi
    elif recover_successful_may_own_manager_binding; then
        may_own_launch_binding_ok=yes
    fi
    if [ "$may_own_launch_binding_ok" != yes ]; then
        failed 'MayOwn singleton launch envelope is invalid'
    fi
    may_own_wait=0
    may_own_pid_one=
    while :; do
        may_own_pid_one=$(systemctl show --property=MainPID --value \
            "$unit_name" 2>/dev/null || true)
        case $may_own_pid_one in
            ''|0|0*|*[!0-9]*) ;;
            *) break ;;
        esac
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 1200 ] \
            || failed 'MayOwn first MainPID did not appear'
        sleep 0.05
    done
    may_own_pid_one_starttime=$(capture_process_starttime "$may_own_pid_one") \
        || failed 'MayOwn first MainPID birth token is unavailable'
    may_own_initial_namespaces_are_ready "$may_own_pid_one" \
        "$may_own_invocation_one" "$may_own_pid_one_starttime" \
        || failed 'MayOwn first private namespaces did not become stable'
    may_own_cgroup=/sys/fs/cgroup/system.slice/$unit_name
    if ! may_own_preexec_barrier_is_exact "$may_own_pid_one" \
        "$may_own_invocation_one" 0 0; then
        report_may_own_preexec_barrier_failure_stage \
            || failed 'MayOwn first pre-exec barrier diagnostic is invalid'
        failed 'MayOwn first pre-exec barrier is not manager-bound'
    fi
    start_may_own_preexec_observer one "$may_own_pid_one" \
        "$may_own_invocation_one" \
        || failed 'MayOwn first external pre-exec observer did not arm'
    may_own_first_kill_ready=$temporary_stage/may-own-first-kill.ready
    may_own_first_freeze_release=$temporary_stage/may-own-first-freeze.release
    may_own_first_tracer_ready=$temporary_stage/may-own-first-tracer.ready
    may_own_first_helper_exec_ready=$temporary_stage/may-own-first-helper-exec.ready
    may_own_first_driver_release=$temporary_stage/may-own-first-driver.release
    for may_own_first_absent_path in \
        "$may_own_first_kill_ready" "$may_own_first_freeze_release" \
        "$may_own_first_tracer_ready" "$may_own_first_helper_exec_ready" \
        "$may_own_first_driver_release"; do
        if [ -e "$may_own_first_absent_path" ] \
            || [ -L "$may_own_first_absent_path" ]; then
            failed 'MayOwn first freeze handshake path is unsafe'
        fi
    done
    driver_phase=may-own-first-crash
    printf '%s\n' \
        'set pagination off' \
        'set confirm off' \
        'set breakpoint pending on' \
        'break volparossa_helper::worker_v3::DurableCustodyPublicationTerminalGuard::retain_published' \
        'ignore 1 2' \
        'commands' \
        'silent' \
        "shell while [ ! -f $may_own_first_driver_release ]; do /usr/bin/sleep 0.05; done" \
        "shell /usr/bin/nsenter --mount=/proc/$may_own_pid_one/ns/mnt -- /run/volparossa-helper-may-own-observer armed $unit_name $agent_gid $may_own_pid_one" \
        "shell /usr/bin/nsenter --mount=/proc/$may_own_pid_one/ns/mnt -- /run/volparossa-helper-may-own-observer first-publication $unit_name $agent_gid $may_own_pid_one" \
        "shell printf '%s\\n' VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_FIRST_KILL_READY_V1=pass >$may_own_first_kill_ready" \
        "shell while [ ! -f $may_own_first_freeze_release ]; do /usr/bin/sleep 0.05; done" \
        'kill' \
        'quit 0' \
        'end' \
        'tcatch exec' \
        "shell printf '%s\\n' ready >$may_own_first_tracer_ready" \
        'continue' \
        'delete 2' \
        "shell printf '%s\\n' ready >$may_own_first_helper_exec_ready" \
        'continue' >"$may_own_debugger_one_commands" \
        || failed 'MayOwn first debugger commands could not be written'
    chmod 0600 "$may_own_debugger_one_commands"
    timeout --preserve-status --signal=TERM --kill-after=5s 60s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        "$debugger_path" --batch --quiet --nx --pid="$may_own_pid_one" \
            --command="$may_own_debugger_one_commands" \
        >"$temporary_stage/may-own-debugger-one.stdout" \
        2>"$temporary_stage/may-own-debugger-one.stderr" &
    may_own_debugger_pid=$!
    may_own_debugger_starttime=$(capture_process_starttime \
        "$may_own_debugger_pid") \
        || failed 'MayOwn first debugger identity is unavailable'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_first_tracer_ready"; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn first debugger exited before exec-catch readiness'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn first debugger did not arm its exec catch'
        sleep 0.05
    done
    [ "$(cat "$may_own_first_tracer_ready")" = ready ] \
        || failed 'MayOwn first debugger readiness record is invalid'
    release_may_own_preexec_barrier "$may_own_pid_one" \
        "$may_own_invocation_one" \
        || failed 'MayOwn first pre-exec barrier could not be released'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_first_helper_exec_ready"; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn first debugger exited before helper exec'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn first helper exec was not observed'
        sleep 0.05
    done
    release_may_own_preexec_observer one \
        || failed 'MayOwn first external pre-exec observer did not retire'
    /usr/bin/nsenter --mount="/proc/$may_own_pid_one/ns/mnt" -- \
        /usr/bin/sleep 180 &
    may_own_mount_keeper_pid=$!
    may_own_mount_keeper_starttime=$(capture_process_starttime \
        "$may_own_mount_keeper_pid") \
        || failed 'MayOwn first mount keeper identity is unavailable'
    start_may_own_driver_observer one "$may_own_pid_one" \
        "$may_own_invocation_one" \
        || failed 'MayOwn first driver-side observer could not be started'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$temporary_stage/may-own-output/unit.identity"; do
        kill -0 "$may_own_driver_observer_pid" 2>/dev/null \
            || failed 'MayOwn first driver-side observer exited before identity proof'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 1200 ] \
            || failed 'MayOwn first invocation identity did not appear'
        sleep 0.05
    done
    if [ "$(sed -n '1p' "$temporary_stage/may-own-output/unit.identity")" != \
        "$may_own_invocation_one" ] \
        || [ "$(sed -n '2p' "$temporary_stage/may-own-output/unit.identity")" != \
            "$may_own_pid_one" ]; then
        failed 'MayOwn first invocation is not hook-bound'
    fi
    may_own_service_shape_is_exact "$may_own_pid_one" \
        "$may_own_invocation_one" 0 2 \
        || failed 'MayOwn first service shape is not production-exact'
    if [ ! -f "$may_own_cgroup/cgroup.freeze" ] \
        || [ -L "$may_own_cgroup/cgroup.freeze" ] \
        || [ "$(stat -Lc '%u:%g:%a:%h' "$may_own_cgroup/cgroup.freeze" \
            2>/dev/null || true)" != '0:0:644:1' ]; then
        failed 'MayOwn cgroup freezer is unavailable'
    fi
    vp_capture_run "$may_own_first_driver_release" printf '%s\n' \
        'VOLPAROSSA_HELPER_MAY_OWN_FIRST_DRIVER_V1=release' \
        || failed 'MayOwn first debugger driver release could not be published'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_first_kill_ready"; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn first debugger exited before the freeze fence'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn first debugger did not reach the crash boundary'
        sleep 0.05
    done
    [ "$(cat "$may_own_first_kill_ready")" = \
        'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_FIRST_KILL_READY_V1=pass' ] \
        || failed 'MayOwn first kill-ready marker is invalid'
    freeze_may_own_cgroup_before_forced_crash "$may_own_pid_one" \
        || failed 'MayOwn cgroup did not freeze before the first crash'
    vp_capture_run "$may_own_first_freeze_release" \
        printf '%s\n' \
            'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_FIRST_FREEZE_RELEASE_V1=pass' \
        || failed 'MayOwn first freeze release could not be published'
    wait "$may_own_debugger_pid" \
        || failed 'MayOwn first forced-crash debugger did not complete'
    may_own_debugger_pid=
    may_own_debugger_starttime=
    may_own_wait=0
    while [ "$(systemctl show --property=MainPID --value "$unit_name")" != 0 ]; do
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] || failed 'MayOwn first crash did not settle'
        sleep 0.05
    done
    if [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 0 ] \
        || [ "$(systemctl show --property=Result --value "$unit_name")" != signal ] \
        || [ "$(systemctl show --property=ExecMainCode --value "$unit_name")" != 2 ] \
        || [ "$(systemctl show --property=ExecMainStatus --value "$unit_name")" != 9 ]; then
        failed 'MayOwn first forced-crash fence is not exact'
    fi
    thaw_may_own_crash_boundary_before_restart 0 \
        || failed 'MayOwn first crash freezer was not retired before restart'
    wait_may_own_driver_observer forced-crash \
        || failed 'MayOwn first driver-side observer did not terminate at the forced crash'
    may_own_crash_one_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
        || failed 'MayOwn first crash time is unavailable'
    /usr/bin/nsenter --mount="/proc/$may_own_mount_keeper_pid/ns/mnt" -- \
        /run/volparossa-helper-may-own-observer after-first-crash \
            "$unit_name" "$agent_gid" "$may_own_pid_one" \
        || failed 'MayOwn first crash did not preserve exact Relay custody'
    unit_owned=no
    unit_may_own=yes
    unit_invocation_id=
    kill "$may_own_mount_keeper_pid" 2>/dev/null || true
    wait "$may_own_mount_keeper_pid" 2>/dev/null || true
    may_own_mount_keeper_pid=
    may_own_mount_keeper_starttime=

    driver_phase=may-own-second-crash
    may_own_wait=0
    may_own_pid_two=
    while :; do
        may_own_pid_two=$(systemctl show --property=MainPID --value \
            "$unit_name" 2>/dev/null || true)
        case $may_own_pid_two in
            ''|0|0*|*[!0-9]*) ;;
            *) [ "$may_own_pid_two" != "$may_own_pid_one" ] && break ;;
        esac
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] || failed 'MayOwn second invocation did not appear'
        sleep 0.05
    done
    unit_description_matches_marker \
        || failed 'MayOwn second invocation lost the ownership marker'
    adopt_tentative_unit || failed 'MayOwn second invocation could not be adopted'
    may_own_invocation_two=$unit_invocation_id
    if ! unit_invocation_id_is_safe "$may_own_invocation_two" \
        || [ "$may_own_invocation_two" = "$may_own_invocation_one" ] \
        || [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 1 ]; then
        failed 'MayOwn second invocation lineage is invalid'
    fi
    if ! may_own_preexec_barrier_is_exact "$may_own_pid_two" \
        "$may_own_invocation_two" 1 2; then
        report_may_own_preexec_barrier_failure_stage \
            || failed 'MayOwn second pre-exec barrier diagnostic is invalid'
        failed 'MayOwn second pre-exec barrier is not manager-bound'
    fi
    start_may_own_preexec_observer two "$may_own_pid_two" \
        "$may_own_invocation_two" \
        || failed 'MayOwn second external pre-exec observer did not arm'
    may_own_driver_second_ready=$temporary_stage/may-own-output/may-own.driver-second-ready
    may_own_tracer_ready=$temporary_stage/may-own-second-tracer.ready
    may_own_second_helper_exec_ready=$temporary_stage/may-own-second-helper-exec.ready
    may_own_second_driver_release=$temporary_stage/may-own-second-driver.release
    may_own_second_kill_ready=$temporary_stage/may-own-second-kill.ready
    may_own_second_freeze_release=$temporary_stage/may-own-second-freeze.release
    for may_own_second_absent_path in \
        "$may_own_second_helper_exec_ready" "$may_own_second_driver_release" \
        "$may_own_second_kill_ready" "$may_own_second_freeze_release"; do
        if [ -e "$may_own_second_absent_path" ] \
            || [ -L "$may_own_second_absent_path" ]; then
            failed 'MayOwn second driver handshake path is unsafe'
        fi
    done
    printf '%s\n' \
        'set pagination off' \
        'set confirm off' \
        'set breakpoint pending on' \
        'break volparossa_helper::ownership_journal::actor::DurableOwnershipStartup::confirm_single_restart_cleanup' \
        'commands' \
        'silent' \
        "shell /usr/bin/nsenter --mount=/proc/$may_own_pid_two/ns/mnt -- /run/volparossa-helper-may-own-observer second-confirm $unit_name $agent_gid $may_own_pid_two" \
        "shell printf '%s\\n' VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_SECOND_KILL_READY_V1=pass >$may_own_second_kill_ready" \
        "shell while [ ! -f $may_own_second_freeze_release ]; do /usr/bin/sleep 0.05; done" \
        'kill' \
        'quit 0' \
        'end' \
        'tcatch exec' \
        "shell printf '%s\\n' ready >$may_own_tracer_ready" \
        'continue' \
        'delete 2' \
        "shell printf '%s\\n' ready >$may_own_second_helper_exec_ready" \
        "shell while [ ! -f $may_own_second_driver_release ]; do /usr/bin/sleep 0.05; done" \
        'continue' >"$may_own_debugger_two_commands" \
        || failed 'MayOwn second debugger commands could not be written'
    chmod 0600 "$may_own_debugger_two_commands"
    timeout --preserve-status --signal=TERM --kill-after=5s 60s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        "$debugger_path" --batch --quiet --nx --pid="$may_own_pid_two" \
            --command="$may_own_debugger_two_commands" \
        >"$temporary_stage/may-own-debugger-two.stdout" \
        2>"$temporary_stage/may-own-debugger-two.stderr" &
    may_own_debugger_pid=$!
    may_own_debugger_starttime=$(capture_process_starttime "$may_own_debugger_pid") \
        || failed 'MayOwn second debugger identity is unavailable'
    may_own_wait=0
    while [ ! -f "$may_own_tracer_ready" ]; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn second debugger exited before arming'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] || failed 'MayOwn second debugger did not arm'
        sleep 0.05
    done
    [ "$(cat "$may_own_tracer_ready")" = ready ] \
        || failed 'MayOwn second debugger readiness record is invalid'
    release_may_own_preexec_barrier "$may_own_pid_two" \
        "$may_own_invocation_two" \
        || failed 'MayOwn second pre-exec barrier could not be released'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_second_helper_exec_ready"; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn second debugger exited before helper exec'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn second helper exec was not observed'
        sleep 0.05
    done
    [ "$(cat "$may_own_second_helper_exec_ready")" = ready ] \
        || failed 'MayOwn second helper-exec marker is invalid'
    release_may_own_preexec_observer two \
        || failed 'MayOwn second external pre-exec observer did not retire'
    /usr/bin/nsenter --mount="/proc/$may_own_pid_two/ns/mnt" -- \
        /usr/bin/sleep 180 &
    may_own_mount_keeper_pid=$!
    may_own_mount_keeper_starttime=$(capture_process_starttime \
        "$may_own_mount_keeper_pid") \
        || failed 'MayOwn second mount keeper identity is unavailable'
    start_may_own_driver_observer two "$may_own_pid_two" \
        "$may_own_invocation_two" \
        || failed 'MayOwn second driver-side observer could not be started'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_driver_second_ready"; do
        kill -0 "$may_own_driver_observer_pid" 2>/dev/null \
            || failed 'MayOwn second driver-side observer exited before arming'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn second driver-side observer did not arm'
        sleep 0.05
    done
    if [ "$(sed -n '1p' "$may_own_driver_second_ready")" != \
        'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_DRIVER_SECOND_READY_V1=pass' ] \
        || [ "$(sed -n '2p' "$may_own_driver_second_ready")" != \
            "$may_own_invocation_two" ] \
        || [ "$(sed -n '3p' "$may_own_driver_second_ready")" != \
            "$may_own_pid_two" ]; then
        failed 'MayOwn second driver-ready record is invalid'
    fi
    may_own_service_shape_is_exact "$may_own_pid_two" \
        "$may_own_invocation_two" 1 2 \
        || failed 'MayOwn second service shape is not production-exact'
    vp_capture_run "$may_own_second_driver_release" \
        printf '%s\n' \
            'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_DRIVER_SECOND_RELEASE_V1=pass' \
        || failed 'MayOwn second driver release could not be published'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_second_kill_ready"; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn second debugger exited before the freeze fence'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn second debugger did not reach the crash boundary'
        sleep 0.05
    done
    [ "$(cat "$may_own_second_kill_ready")" = \
        'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_SECOND_KILL_READY_V1=pass' ] \
        || failed 'MayOwn second kill-ready marker is invalid'
    freeze_may_own_cgroup_before_forced_crash "$may_own_pid_two" \
        || failed 'MayOwn cgroup did not freeze before the second crash'
    vp_capture_run "$may_own_second_freeze_release" \
        printf '%s\n' \
            'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_SECOND_FREEZE_RELEASE_V1=pass' \
        || failed 'MayOwn second freeze release could not be published'
    wait "$may_own_debugger_pid" \
        || failed 'MayOwn second forced-crash debugger did not complete'
    may_own_debugger_pid=
    may_own_debugger_starttime=
    may_own_wait=0
    while [ "$(systemctl show --property=MainPID --value "$unit_name")" != 0 ]; do
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] || failed 'MayOwn second crash did not settle'
        sleep 0.05
    done
    if [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 1 ] \
        || [ "$(systemctl show --property=Result --value "$unit_name")" != signal ] \
        || [ "$(systemctl show --property=ExecMainCode --value "$unit_name")" != 2 ] \
        || [ "$(systemctl show --property=ExecMainStatus --value "$unit_name")" != 9 ]; then
        failed 'MayOwn second forced-crash fence is not exact'
    fi
    thaw_may_own_crash_boundary_before_restart 1 \
        || failed 'MayOwn second crash freezer was not retired before restart'
    wait_may_own_driver_observer success \
        || failed 'MayOwn second driver-side observer did not preserve the crash boundary'
    may_own_crash_two_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
        || failed 'MayOwn second crash time is unavailable'
    /usr/bin/nsenter --mount="/proc/$may_own_mount_keeper_pid/ns/mnt" -- \
        /run/volparossa-helper-may-own-observer after-second-crash \
            "$unit_name" "$agent_gid" "$may_own_pid_two" \
        || failed 'MayOwn second crash did not preserve exact Relay custody'
    unit_owned=no
    unit_may_own=yes
    unit_invocation_id=
    kill "$may_own_mount_keeper_pid" 2>/dev/null || true
    wait "$may_own_mount_keeper_pid" 2>/dev/null || true
    may_own_mount_keeper_pid=
    may_own_mount_keeper_starttime=

    driver_phase=may-own-recovery
    may_own_wait=0
    may_own_pid_three=
    while :; do
        may_own_pid_three=$(systemctl show --property=MainPID --value \
            "$unit_name" 2>/dev/null || true)
        case $may_own_pid_three in
            ''|0|0*|*[!0-9]*) ;;
            *)
                if [ "$may_own_pid_three" != "$may_own_pid_one" ] \
                    && [ "$may_own_pid_three" != "$may_own_pid_two" ]; then
                    break
                fi
                ;;
        esac
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] || failed 'MayOwn third invocation did not appear'
        sleep 0.05
    done
    unit_description_matches_marker \
        || failed 'MayOwn third invocation lost the ownership marker'
    adopt_tentative_unit || failed 'MayOwn third invocation could not be adopted'
    may_own_invocation_three=$unit_invocation_id
    if ! unit_invocation_id_is_safe "$may_own_invocation_three" \
        || [ "$may_own_invocation_three" = "$may_own_invocation_one" ] \
        || [ "$may_own_invocation_three" = "$may_own_invocation_two" ] \
        || [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 2 ]; then
        failed 'MayOwn third invocation lineage is invalid'
    fi
    if ! may_own_preexec_barrier_is_exact "$may_own_pid_three" \
        "$may_own_invocation_three" 2 2; then
        report_may_own_preexec_barrier_failure_stage \
            || failed 'MayOwn third pre-exec barrier diagnostic is invalid'
        failed 'MayOwn third pre-exec barrier is not manager-bound'
    fi
    start_may_own_preexec_observer three "$may_own_pid_three" \
        "$may_own_invocation_three" \
        || failed 'MayOwn third external pre-exec observer did not arm'
    may_own_driver_third_ready=$temporary_stage/may-own-output/may-own.driver-third-ready
    may_own_third_tracer_ready=$temporary_stage/may-own-third-tracer.ready
    may_own_third_helper_exec_ready=$temporary_stage/may-own-third-helper-exec.ready
    may_own_third_driver_release=$temporary_stage/may-own-third-driver.release
    for may_own_third_absent_path in \
        "$may_own_third_helper_exec_ready" "$may_own_third_driver_release"; do
        if [ -e "$may_own_third_absent_path" ] \
            || [ -L "$may_own_third_absent_path" ]; then
            failed 'MayOwn third driver handshake path is unsafe'
        fi
    done
    printf '%s\n' \
        'set pagination off' \
        'set confirm off' \
        'set breakpoint pending on' \
        'break volparossa_helper::systemd_fdstore::remove_restart_custody' \
        'commands' \
        'silent' \
        "shell /usr/bin/nsenter --mount=/proc/$may_own_pid_three/ns/mnt -- /run/volparossa-helper-may-own-observer third-removal $unit_name $agent_gid $may_own_pid_three" \
        'detach' \
        'quit' \
        'end' \
        'tcatch exec' \
        "shell printf '%s\\n' ready >$may_own_third_tracer_ready" \
        'continue' \
        'delete 2' \
        "shell printf '%s\\n' ready >$may_own_third_helper_exec_ready" \
        "shell while [ ! -f $may_own_third_driver_release ]; do /usr/bin/sleep 0.05; done" \
        'continue' >"$may_own_debugger_three_commands" \
        || failed 'MayOwn third debugger commands could not be written'
    chmod 0600 "$may_own_debugger_three_commands"
    timeout --preserve-status --signal=TERM --kill-after=5s 60s \
        prlimit --core=0:0 --fsize=1048576:1048576 -- \
        "$debugger_path" --batch --quiet --nx --pid="$may_own_pid_three" \
            --command="$may_own_debugger_three_commands" \
        >"$temporary_stage/may-own-debugger-three.stdout" \
        2>"$temporary_stage/may-own-debugger-three.stderr" &
    may_own_debugger_pid=$!
    may_own_debugger_starttime=$(capture_process_starttime "$may_own_debugger_pid") \
        || failed 'MayOwn third debugger identity is unavailable'
    may_own_wait=0
    while [ ! -f "$may_own_third_tracer_ready" ]; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn third debugger exited before arming'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] || failed 'MayOwn third debugger did not arm'
        sleep 0.05
    done
    [ "$(cat "$may_own_third_tracer_ready")" = ready ] \
        || failed 'MayOwn third debugger readiness record is invalid'
    release_may_own_preexec_barrier "$may_own_pid_three" \
        "$may_own_invocation_three" \
        || failed 'MayOwn third pre-exec barrier could not be released'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_third_helper_exec_ready"; do
        kill -0 "$may_own_debugger_pid" 2>/dev/null \
            || failed 'MayOwn third debugger exited before helper exec'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn third helper exec was not observed'
        sleep 0.05
    done
    [ "$(cat "$may_own_third_helper_exec_ready")" = ready ] \
        || failed 'MayOwn third helper-exec marker is invalid'
    release_may_own_preexec_observer three \
        || failed 'MayOwn third external pre-exec observer did not retire'
    start_may_own_driver_observer three "$may_own_pid_three" \
        "$may_own_invocation_three" \
        || failed 'MayOwn third driver-side observer could not be started'
    may_own_wait=0
    while ! vp_capture_file_is_safe "$may_own_driver_third_ready"; do
        kill -0 "$may_own_driver_observer_pid" 2>/dev/null \
            || failed 'MayOwn third driver-side observer exited before arming'
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 600 ] \
            || failed 'MayOwn third driver-side observer did not arm'
        sleep 0.05
    done
    if [ "$(sed -n '1p' "$may_own_driver_third_ready")" != \
        'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_DRIVER_THIRD_READY_V1=pass' ] \
        || [ "$(sed -n '2p' "$may_own_driver_third_ready")" != \
            "$may_own_invocation_three" ] \
        || [ "$(sed -n '3p' "$may_own_driver_third_ready")" != \
            "$may_own_pid_three" ]; then
        failed 'MayOwn third driver-ready record is invalid'
    fi
    may_own_service_shape_is_exact "$may_own_pid_three" \
        "$may_own_invocation_three" 2 2 \
        || failed 'MayOwn third service shape is not production-exact'
    vp_capture_run "$may_own_third_driver_release" \
        printf '%s\n' \
            'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_DRIVER_THIRD_RELEASE_V1=pass' \
        || failed 'MayOwn third driver release could not be published'
    wait "$may_own_debugger_pid" \
        || failed 'MayOwn removal-boundary debugger did not complete'
    may_own_debugger_pid=
    may_own_debugger_starttime=
    may_own_wait=0
    while ! vp_capture_file_is_safe "$temporary_stage/may-own-output/may-own.resumed"; do
        may_own_wait=$((may_own_wait + 1))
        [ "$may_own_wait" -lt 1800 ] \
            || failed 'MayOwn Relay settlement did not complete'
        sleep 0.05
    done
    [ "$(sed -n '2p' "$temporary_stage/may-own-output/may-own.resumed")" = \
        "$may_own_invocation_three" ] \
        || failed 'MayOwn resumed record changed the third invocation'
    wait_may_own_driver_observer success \
        || failed 'MayOwn third driver-side observer did not validate settlement'
    unit_invocation_id=$may_own_invocation_three
    driver_phase=may-own-retirement
    may_own_unit_name=$unit_name
    if ! retire_unit; then
        cleanup_error=yes
        failed 'MayOwn recovered unit could not be retired'
    fi
    unit_name=$may_own_unit_name
    may_own_retired_load_state=$(unit_load_state) || may_own_retired_load_state=
    [ "$may_own_retired_load_state" = not-found ] \
        || failed 'MayOwn recovered unit was not collected'
    forget_unit_ownership
    may_own_lock_path=$temporary_stage/production-runtime/helper.ownership-v3.lock
    if command exec 9<>"$may_own_lock_path"; then
        /usr/bin/flock -n 9 || failed 'MayOwn journal lock remained held'
        command exec 9>&-
    else
        failed 'MayOwn journal lock could not be opened after retirement'
    fi
    if [ -e "$temporary_stage/production-runtime/helper.sock" ] \
        || [ -L "$temporary_stage/production-runtime/helper.sock" ] \
        || [ -e "$temporary_stage/production-runtime/helper.ownership-v3.next" ] \
        || [ -L "$temporary_stage/production-runtime/helper.ownership-v3.next" ]; then
        failed 'MayOwn runtime did not retire cleanly'
    fi
    may_own_final_journal=$(
        /usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- \
            "$temporary_stage/production-ipc-probe" \
                prove-restart-may-own-relay-settled "$may_own_pid_three" \
                "$agent_gid" \
                "$(sed -n '4p' "$temporary_stage/may-own-output/may-own.first-boundary")" \
                2>/dev/null
    ) || failed 'MayOwn final journal could not be revalidated'
    [ "$may_own_final_journal" = \
        'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_RELAY_SETTLED_V1=pass' ] \
        || failed 'MayOwn final journal proof is invalid'
    may_own_evidence_validated=true
    if [ "$production_ok" != "$proof_ok" ]; then
        failed 'internal production proof failure state is inconsistent'
    fi
fi
driver_phase=final-verification
final_checkpoint=host-state
capture_host_state "$temporary_stage/after"
after_digest=$(state_digest "$temporary_stage/after")
changed_records=
for record in $state_records; do
    if ! cmp -s "$temporary_stage/before/$record" "$temporary_stage/after/$record"; then
        changed_records="$changed_records $record"
    fi
done
if [ -n "$changed_records" ] || [ "$before_digest" != "$after_digest" ]; then
    printf 'Host state changed in:%s\n' "$changed_records" >&2
    failed 'privacy-safe before/after host-state digests differ'
fi
final_checkpoint=structured-reporting
if [ "$proof_ok" != yes ]; then
    if [ "$proof_failure_reason" = worker-launch-status ]; then
        report_worker_launch_diagnostic \
            || failed 'the fixed worker launch diagnostic could not be reported'
    elif [ "$proof_failure_reason" = worker-confinement ]; then
        report_worker_confinement_diagnostic \
            || failed 'the fixed worker confinement diagnostic could not be reported'
    elif [ "$proof_failure_reason" = production-launch-status ]; then
        report_production_launch_diagnostic || :
    fi
    report_proof_failure "$proof_failure_reason"
fi
final_checkpoint=cleanup-summary
if [ "$cleanup_error" != no ]; then
    failed 'the staged proof recorded an earlier retirement or cleanup failure'
fi
final_checkpoint=lifecycle-summary
if [ "$worker_fdstore_before_retirement" != 2 ] \
    || [ "$worker_retired_load_state" != not-found ] \
    || [ "$production_fdstore_during_run" != 0 ] \
    || [ "$production_fdstore_active_counts" != '2 2 2' ] \
    || [ "$production_fdstore_settled_counts" != '0 0 0' ] \
    || [ "$production_fdstore_identity_bound" != true ] \
    || [ "$production_journal_settled_absent" != true ] \
    || [ "$production_retired_load_state" != not-found ] \
    || [ "$restart_evidence_validated" != true ] \
    || [ "$restart_retired_load_state" != not-found ] \
    || [ "$may_own_evidence_validated" != true ] \
    || [ "$may_own_retired_load_state" != not-found ]; then
    failed 'the retained fdstore or exact-unit retirement observations are incomplete'
fi

final_checkpoint=artifact-integrity
source_final=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$helper_source") \
    || failed 'the helper source metadata could not be revalidated'
source_digest_final=$(vp_capture_sha256_file "$helper_source") \
    || failed 'the helper source could not be revalidated'
staged_digest_final=$(vp_capture_sha256_file "$temporary_stage/volparossa-helper") \
    || failed 'the staged helper could not be revalidated'
ipc_probe_final=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$ipc_probe_source") \
    || failed 'the production IPC probe metadata could not be revalidated'
ipc_probe_digest_final=$(vp_capture_sha256_file "$ipc_probe_source") \
    || failed 'the production IPC probe source could not be revalidated'
staged_ipc_probe_digest_final=$(vp_capture_sha256_file \
    "$temporary_stage/production-ipc-probe") \
    || failed 'the staged production IPC probe could not be revalidated'
ipc_hook_final=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$ipc_hook_source") \
    || failed 'the production IPC hook metadata could not be revalidated'
ipc_hook_digest_final=$(vp_capture_sha256_file "$ipc_hook_source") \
    || failed 'the production IPC hook source could not be revalidated'
staged_ipc_hook_digest_final=$(vp_capture_sha256_file \
    "$temporary_stage/production-ipc-hook") \
    || failed 'the staged production IPC hook could not be revalidated'
restart_observer_final=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_observer_source") \
    || failed 'the restart observer metadata could not be revalidated'
restart_observer_digest_final=$(vp_capture_sha256_file "$restart_observer_source") \
    || failed 'the restart observer source could not be revalidated'
staged_restart_observer_digest_final=$(vp_capture_sha256_file \
    "$temporary_stage/restart-observer") \
    || failed 'the staged restart observer could not be revalidated'
restart_launcher_final=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$restart_launcher_source") \
    || failed 'the restart launcher metadata could not be revalidated'
restart_launcher_digest_final=$(vp_capture_sha256_file "$restart_launcher_source") \
    || failed 'the restart launcher source could not be revalidated'
staged_restart_launcher_digest_final=$(vp_capture_sha256_file \
    "$temporary_stage/restart-launcher") \
    || failed 'the staged restart launcher could not be revalidated'
staged_restart_launcher_final=$(stat -Lc '%F:%u:%g:%a:%h' \
    "$temporary_stage/restart-launcher" 2>/dev/null || true)
may_own_observer_final=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
    "$may_own_observer_source") \
    || failed 'the MayOwn Relay observer metadata could not be revalidated'
may_own_observer_digest_final=$(vp_capture_sha256_file "$may_own_observer_source") \
    || failed 'the MayOwn Relay observer source could not be revalidated'
staged_may_own_observer_digest_final=$(vp_capture_sha256_file \
    "$temporary_stage/may-own-observer") \
    || failed 'the staged MayOwn Relay observer could not be revalidated'
debugger_digest_final=$(vp_capture_sha256_file "$debugger_path") \
    || failed 'the debugger could not be revalidated'
if [ "$source_before" != "$source_final" ] \
    || [ "$source_digest_before" != "$source_digest_final" ] \
    || [ "$staged_digest" != "$staged_digest_final" ] \
    || [ "$ipc_probe_before" != "$ipc_probe_final" ] \
    || [ "$ipc_probe_digest_before" != "$ipc_probe_digest_final" ] \
    || [ "$staged_ipc_probe_digest" != "$staged_ipc_probe_digest_final" ] \
    || [ "$ipc_hook_before" != "$ipc_hook_final" ] \
    || [ "$ipc_hook_digest_before" != "$ipc_hook_digest_final" ] \
    || [ "$staged_ipc_hook_digest" != "$staged_ipc_hook_digest_final" ] \
    || [ "$restart_observer_before" != "$restart_observer_final" ] \
    || [ "$restart_observer_digest_before" != "$restart_observer_digest_final" ] \
    || [ "$staged_restart_observer_digest" != \
        "$staged_restart_observer_digest_final" ] \
    || [ "$restart_launcher_before" != "$restart_launcher_final" ] \
    || [ "$restart_launcher_digest_before" != \
        "$restart_launcher_digest_final" ] \
    || [ "$staged_restart_launcher_digest" != \
        "$staged_restart_launcher_digest_final" ] \
    || [ "$staged_restart_launcher_final" != 'regular file:0:0:500:1' ] \
    || [ "$may_own_observer_before" != "$may_own_observer_final" ] \
    || [ "$may_own_observer_digest_before" != "$may_own_observer_digest_final" ] \
    || [ "$staged_may_own_observer_digest" != \
        "$staged_may_own_observer_digest_final" ] \
    || [ "$debugger_digest" != "$debugger_digest_final" ]; then
    failed 'a source or staged proof artifact changed during live execution'
fi
final_checkpoint=source-integrity
final_repository_root=$(git -c safe.directory="$repository_directory" \
    -C "$repository_directory" rev-parse --show-toplevel 2>/dev/null) \
    || failed 'the repository root could not be revalidated'
final_source_commit=$(git -c safe.directory="$repository_directory" \
    -C "$repository_directory" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
    || failed 'the source commit could not be revalidated'
final_source_status=$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$repository_directory" \
    -C "$repository_directory" status --porcelain=v1 --untracked-files=normal \
    --ignore-submodules=none 2>/dev/null) \
    || failed 'the source worktree state could not be revalidated'
if [ "$final_repository_root" != "$repository_directory" ] \
    || [ "$final_source_commit" != "$source_commit" ] \
    || [ -n "$final_source_status" ]; then
    failed 'the exact clean source revision changed during live execution'
fi

final_checkpoint=report-times
finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
    || failed 'the execution finish time cannot be established'
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
    || failed 'the report generation time cannot be established'
final_checkpoint=report-generation
report_path=$temporary_stage/helper-boundary-evidence-v1.json
jq -n -S -c \
    --arg source_commit "$source_commit" \
    --arg helper_digest "$staged_digest" \
    --arg probe_digest "$staged_ipc_probe_digest" \
    --arg hook_digest "$staged_ipc_hook_digest" \
    --arg kernel_release "$kernel_release" \
    --arg virtualization "$virtualization" \
    --arg started_at "$started_at" \
    --arg finished_at "$finished_at" \
    --arg generated_at "$generated_at" \
    --arg worker_invocation "$worker_invocation_id" \
    --arg production_invocation "$production_invocation_id" \
    --arg before_digest "$before_digest" \
    --arg after_digest "$after_digest" \
    --arg state_records "$state_records" \
    --arg worker_fdstore_before_retirement "$worker_fdstore_before_retirement" \
    --arg worker_retired_load_state "$worker_retired_load_state" \
    --arg production_fdstore_during_run "$production_fdstore_during_run" \
    --arg production_fdstore_active_counts "$production_fdstore_active_counts" \
    --arg production_fdstore_settled_counts "$production_fdstore_settled_counts" \
    --arg production_retired_load_state "$production_retired_load_state" '
    {
      schema_version: 1,
      report_kind: "volparossa-helper-boundary-evidence",
      observed_source: {commit_sha: $source_commit, worktree_clean: true},
      observed_artifact_hashes: {
        volparossa_helper_sha256: $helper_digest,
        production_ipc_probe_sha256: $probe_digest,
        production_ipc_unit_hook_sha256: $hook_digest
      },
      environment: {
        debian_version: "13",
        dpkg_architecture: "amd64",
        machine: "x86_64",
        kernel_release: $kernel_release,
        systemd_version: 257,
        virtualization: $virtualization
      },
      started_at: $started_at,
      finished_at: $finished_at,
      generated_at: $generated_at,
      invocation_ids: [$worker_invocation, $production_invocation],
      worker: {
        fdstore_before_retirement: ($worker_fdstore_before_retirement | tonumber),
        unit_load_state_after_retirement: $worker_retired_load_state
      },
      production: {
        argumentless: true,
        fdstore_idle_observation: ($production_fdstore_during_run | tonumber),
        fdstore_active_cycle_counts:
          ($production_fdstore_active_counts | split(" ") | map(tonumber)),
        fdstore_settled_cycle_counts:
          ($production_fdstore_settled_counts | split(" ") | map(tonumber)),
        fdstore_exact_identity_bound: true,
        unit_load_state_after_retirement: $production_retired_load_state
      },
      retirement: {
        journal_settled_absent: true,
        lock_released: true,
        socket_absent: true
      },
      enumerated_host_state: {
        before_sha256: $before_digest,
        after_sha256: $after_digest,
        equal_at_fences: true,
        records: ($state_records | split(" "))
      },
      scope: {
        helper_boundary_only: true,
        cleanup_owned: false,
        restart_recovery: false,
        installed_package: false,
        datapath: false,
        acceptance_a01_a15: false
      },
      checks: [
        "OBSERVED_SOURCE_TREE_CLEAN",
        "OBSERVED_ARTIFACT_HASHES",
        "DEBIAN_13_AMD64_X86_64_SYSTEMD_257_VM",
        "WORKER_INVOCATION_BOUND",
        "WORKER_LIVE_IDENTITY",
        "WORKER_FDSTORE_TWO_BEFORE_RETIREMENT",
        "WORKER_RETIRED_UNIT_NOT_FOUND",
        "PRODUCTION_DISTINCT_INVOCATION_BOUND",
        "PRODUCTION_ARGUMENTLESS",
        "PRODUCTION_IPC_BOUNDARY",
        "PRODUCTION_FDSTORE_ZERO_AT_IDLE_OBSERVATION",
        "PRODUCTION_FDSTORE_EXACT_CUSTODY_DURING_ACTIVE_CYCLES",
        "PRODUCTION_FDSTORE_ZERO_AFTER_SETTLED_CYCLES",
        "PRODUCTION_RETIRED_UNIT_NOT_FOUND",
        "RETIREMENT_JOURNAL_SETTLED_ABSENT",
        "RETIREMENT_LOCK_RELEASED",
        "RETIREMENT_SOCKET_ABSENT",
        "ENUMERATED_HOST_STATE_EQUAL_AT_FENCES"
      ] | map({id: ., result: "PASS"}),
      overall: "PASS"
    }
' >"$report_path" || failed 'the canonical helper-boundary report could not be generated'
chmod 0600 "$report_path" || failed 'the helper-boundary report mode could not be fixed'
vp_capture_file_is_safe "$report_path" \
    || failed 'the helper-boundary report is not one validated private file'
final_checkpoint=report-validation
validator_stdout=$temporary_stage/report-validator.stdout
validator_stderr=$temporary_stage/report-validator.stderr
install -o root -g root -m 0600 /dev/null "$validator_stdout" \
    || failed 'private validator stdout could not be created'
install -o root -g root -m 0600 /dev/null "$validator_stderr" \
    || failed 'private validator stderr could not be created'
set +e
"$evidence_validator" "$report_path" >"$validator_stdout" 2>"$validator_stderr"
validator_status=$?
set -e
if ! vp_capture_file_is_safe "$validator_stdout" \
    || ! vp_capture_file_is_safe "$validator_stderr" \
    || [ "$validator_status" -ne 0 ] \
    || [ -s "$validator_stdout" ] \
    || [ -s "$validator_stderr" ]; then
    report_boundary_validator_failure_diagnostic \
        "$report_path" "$validator_status" \
        "$validator_stdout" \
        "$validator_stderr" || :
    failed 'the helper-boundary report failed strict validation'
fi
validated_report=$(cat "$report_path") \
    || failed 'the validated helper-boundary report could not be retained for publication'
if [ -z "$validated_report" ] || [ "${#validated_report}" -gt 65535 ]; then
    failed 'the validated helper-boundary report has an invalid publication size'
fi
restart_cleanup_confirmed_at=$(sed -n '1p' \
    "$temporary_stage/restart-output/restart.crash") \
    || failed 'restart CleanupConfirmed timestamp is unavailable'
restart_restarted_at=$(sed -n '1p' \
    "$temporary_stage/restart-output/restart.resumed") \
    || failed 'restart successor timestamp is unavailable'
restart_settled_at=$(sed -n '2p' \
    "$temporary_stage/restart-output/restart.resumed") \
    || failed 'restart settlement timestamp is unavailable'
restart_startup_call_record=$(sed -n '5p' \
    "$temporary_stage/restart-output/restart.recovery-boundary") \
    || failed 'restart startup removal call is unavailable'
restart_manager_before_record=$(sed -n '6p' \
    "$temporary_stage/restart-output/restart.recovery-boundary") \
    || failed 'restart pre-removal descriptor count is unavailable'
restart_manager_after_record=$(sed -n '6p' \
    "$temporary_stage/restart-output/restart.resumed") \
    || failed 'restart post-removal descriptor count is unavailable'
if [ "$restart_startup_call_record" != \
    'startup-removal-call-v1=systemd_fdstore::remove_restart_custody' ] \
    || [ "$restart_manager_before_record" != \
        'manager-fdstore-before-removal-v1=2' ] \
    || [ "$restart_manager_after_record" != \
        'manager-fdstore-after-removal-v1=0' ]; then
    failed 'restart live observation records are not exact'
fi
restart_startup_call=${restart_startup_call_record#startup-removal-call-v1=}
restart_manager_before=${restart_manager_before_record#manager-fdstore-before-removal-v1=}
restart_manager_after=${restart_manager_after_record#manager-fdstore-after-removal-v1=}
restart_report_path=$temporary_stage/helper-restart-exact-present-evidence-v1.json
jq -n -S -c \
    --arg source_commit "$source_commit" \
    --arg helper_digest "$staged_digest" \
    --arg probe_digest "$staged_ipc_probe_digest" \
    --arg hook_digest "$staged_ipc_hook_digest" \
    --arg observer_digest "$staged_restart_observer_digest" \
    --arg launcher_digest "$staged_restart_launcher_digest" \
    --arg debugger_digest "$debugger_digest" \
    --arg kernel_release "$kernel_release" \
    --arg started_at "$started_at" \
    --arg cleanup_confirmed_at "$restart_cleanup_confirmed_at" \
    --arg crashed_at "$restart_crashed_at" \
    --arg restarted_at "$restart_restarted_at" \
    --arg settled_at "$restart_settled_at" \
    --arg finished_at "$finished_at" \
    --arg generated_at "$generated_at" \
    --arg initial_invocation "$restart_initial_invocation_id" \
    --arg successor_invocation "$restart_successor_invocation_id" \
    --arg before_digest "$before_digest" \
    --arg after_digest "$after_digest" \
    --arg startup_call "$restart_startup_call" \
    --arg manager_before "$restart_manager_before" \
    --arg manager_after "$restart_manager_after" \
    --arg state_records "$state_records" '
    {
      schema_version: 1,
      report_kind: "volparossa-helper-restart-exact-present-evidence",
      observed_source: {commit_sha: $source_commit, worktree_clean: true},
      observed_artifact_hashes: {
        debugger_sha256: $debugger_digest,
        production_ipc_probe_sha256: $probe_digest,
        production_ipc_unit_hook_sha256: $hook_digest,
        restart_launcher_sha256: $launcher_digest,
        restart_observer_sha256: $observer_digest,
        volparossa_helper_sha256: $helper_digest
      },
      environment: {
        debian_version: "13", dpkg_architecture: "amd64",
        machine: "x86_64", kernel_release: $kernel_release,
        systemd_version: 257, virtualization: "vm"
      },
      started_at: $started_at,
      finished_at: $finished_at,
      generated_at: $generated_at,
      invocation_ids: [$initial_invocation, $successor_invocation],
      restart: {
        initial: {
          argumentless: true,
          target_count: 1,
          target_role: "Client",
          worker_kernel_cleanup_confirmed: true,
          journal_phase_before_crash: "CleanupConfirmed",
          fdstore_before_crash: 2,
          fdstore_exact_identity_bound: true,
          cleanup_confirmed_at: $cleanup_confirmed_at
        },
        crash: {
          signal: "SIGKILL",
          unit_result: "signal",
          exec_main_code: "killed",
          exec_main_status: 9,
          failed_unit_retained: true,
          fdstore_after_crash: 2,
          fdstore_exact_identity_preserved: true,
          crashed_at: $crashed_at
        },
        resumed: {
          argumentless: true,
          restarted_at: $restarted_at,
          inherited_descriptor_count: ($manager_before | tonumber),
          target_count: 1,
          target_phase: "CleanupConfirmed",
          target_disposition: "ExactPresent",
          manager_fdstore_before_removal: ($manager_before | tonumber),
          new_socket_published_before_settlement: false,
          startup_removal_call: $startup_call,
          manager_fdstore_after_removal: ($manager_after | tonumber),
          settled_at: $settled_at,
          journal_phase_after_settlement: "Absent",
          journal_absent_origin: "RecoveredMayOwn",
          journal_stable_read_count: 2,
          journal_temporary_entry_absent: true,
          new_socket_published_after_settlement: true,
          unit_load_state_after_retirement: "not-found"
        }
      },
      retirement: {
        journal_settled_absent: true,
        lock_released: true,
        socket_absent: true
      },
      enumerated_host_state: {
        before_sha256: $before_digest,
        after_sha256: $after_digest,
        equal_at_fences: true,
        records: ($state_records | split(" "))
      },
      scope: {
        helper_boundary_only: true,
        cleanup_confirmed_exact_present_singleton: true,
        cleanup_confirmed_mixed_restart: false,
        forced_helper_crash: true,
        restart_recovery: false,
        may_own_recovery: false,
        cleanup_owned: false,
        installed_package: false,
        datapath: false,
        acceptance_a01_a15: false
      },
      checks: [
        "OBSERVED_SOURCE_TREE_CLEAN",
        "OBSERVED_ARTIFACT_HASHES",
        "DEBIAN_13_AMD64_X86_64_SYSTEMD_257_VM",
        "INITIAL_INVOCATION_BOUND",
        "INITIAL_ARGUMENTLESS_PRODUCTION_BOUNDARY",
        "SINGLETON_WORKER_KERNEL_CLEANUP_CONFIRMED",
        "SINGLETON_CLEANUP_CONFIRMED_EXACT_CUSTODY",
        "FORCED_HELPER_SIGKILL_OBSERVED",
        "SYSTEMD_FDSTORE_EXACT_CUSTODY_PRESERVED_AFTER_CRASH",
        "RESTART_DISTINCT_ARGUMENTLESS_INVOCATION_BOUND",
        "RESTART_INHERITED_SINGLETON_EXACT_PRESENT",
        "RESTART_SOCKET_UNPUBLISHED_BEFORE_SETTLEMENT",
        "RESTART_STARTUP_REMOVAL_CALL_OBSERVED",
        "RESTART_FDSTORE_ZERO_AFTER_STABLE_EMPTY_OBSERVATION",
        "RESTART_JOURNAL_ABSENT_RECOVERED_MAY_OWN",
        "RESTART_SOCKET_PUBLISHED_AFTER_SETTLEMENT",
        "RESTART_RETIRED_UNIT_NOT_FOUND",
        "RETIREMENT_LOCK_RELEASED",
        "RETIREMENT_SOCKET_ABSENT",
        "ENUMERATED_HOST_STATE_EQUAL_AT_FENCES"
      ] | map({id: ., result: "PASS"}),
      overall: "PASS"
    }
' >"$restart_report_path" \
    || failed 'the canonical restart evidence report could not be generated'
chmod 0600 "$restart_report_path" \
    || failed 'the restart evidence report mode could not be fixed'
vp_capture_file_is_safe "$restart_report_path" \
    || failed 'the restart evidence report is not one validated private file'
final_checkpoint=restart-report-validation
restart_validator_stdout=$temporary_stage/restart-validator.stdout
restart_validator_stderr=$temporary_stage/restart-validator.stderr
install -o root -g root -m 0600 /dev/null "$restart_validator_stdout" \
    || failed 'private restart validator stdout could not be created'
install -o root -g root -m 0600 /dev/null "$restart_validator_stderr" \
    || failed 'private restart validator stderr could not be created'
set +e
"$restart_evidence_validator" "$restart_report_path" \
    >"$restart_validator_stdout" 2>"$restart_validator_stderr"
restart_validator_status=$?
set -e
if ! vp_capture_file_is_safe "$restart_validator_stdout" \
    || ! vp_capture_file_is_safe "$restart_validator_stderr" \
    || [ "$restart_validator_status" -ne 0 ] \
    || [ -s "$restart_validator_stdout" ] || [ -s "$restart_validator_stderr" ]; then
    failed 'the restart evidence report failed strict validation'
fi
validated_restart_report=$(cat "$restart_report_path") \
    || failed 'the validated restart report could not be retained'
if [ -z "$validated_restart_report" ] \
    || [ "${#validated_restart_report}" -gt 32768 ]; then
    failed 'the validated restart report has an invalid publication size'
fi

may_own_first_boundary_at=$(sed -n '1p' \
    "$temporary_stage/may-own-output/may-own.first-boundary") \
    || failed 'MayOwn first boundary time is unavailable'
may_own_first_boundary_call=$(sed -n '7p' \
    "$temporary_stage/may-own-output/may-own.first-boundary") \
    || failed 'MayOwn first boundary call is unavailable'
may_own_second_boundary_at=$(sed -n '1p' \
    "$temporary_stage/may-own-output/may-own.second-boundary") \
    || failed 'MayOwn second boundary time is unavailable'
may_own_second_boundary_call=$(sed -n '6p' \
    "$temporary_stage/may-own-output/may-own.second-boundary") \
    || failed 'MayOwn second boundary call is unavailable'
may_own_third_boundary_at=$(sed -n '1p' \
    "$temporary_stage/may-own-output/may-own.third-boundary") \
    || failed 'MayOwn third boundary time is unavailable'
may_own_third_boundary_call=$(sed -n '6p' \
    "$temporary_stage/may-own-output/may-own.third-boundary") \
    || failed 'MayOwn removal boundary call is unavailable'
may_own_settled_at=$(sed -n '1p' \
    "$temporary_stage/may-own-output/may-own.resumed") \
    || failed 'MayOwn settlement time is unavailable'
may_own_manager_after=$(sed -n '4p' \
    "$temporary_stage/may-own-output/may-own.resumed") \
    || failed 'MayOwn post-removal descriptor count is unavailable'
if [ "$may_own_first_boundary_call" != \
    'crash-boundary-v1=worker_v3::DurableCustodyPublicationTerminalGuard::retain_published' ] \
    || [ "$may_own_second_boundary_call" != \
        'crash-boundary-v1=ownership_journal::actor::DurableOwnershipStartup::confirm_single_restart_cleanup' ] \
    || [ "$may_own_third_boundary_call" != \
        'observation-boundary-v1=systemd_fdstore::remove_restart_custody' ] \
    || [ "$may_own_manager_after" != 0 ]; then
    failed 'MayOwn live observation records are not exact'
fi
may_own_first_boundary_call=${may_own_first_boundary_call#crash-boundary-v1=}
may_own_second_boundary_call=${may_own_second_boundary_call#crash-boundary-v1=}
may_own_third_boundary_call=${may_own_third_boundary_call#observation-boundary-v1=}
may_own_report_path=$temporary_stage/helper-restart-may-own-custody-relay-evidence-v1.json
jq -n -S -c \
    --arg source_commit "$source_commit" \
    --arg helper_digest "$staged_digest" \
    --arg probe_digest "$staged_ipc_probe_digest" \
    --arg hook_digest "$staged_ipc_hook_digest" \
    --arg observer_digest "$staged_may_own_observer_digest" \
    --arg debugger_digest "$debugger_digest" \
    --arg kernel_release "$kernel_release" \
    --arg started_at "$started_at" \
    --arg first_boundary_at "$may_own_first_boundary_at" \
    --arg first_crashed_at "$may_own_crash_one_at" \
    --arg second_boundary_at "$may_own_second_boundary_at" \
    --arg second_crashed_at "$may_own_crash_two_at" \
    --arg third_boundary_at "$may_own_third_boundary_at" \
    --arg settled_at "$may_own_settled_at" \
    --arg finished_at "$finished_at" \
    --arg generated_at "$generated_at" \
    --arg invocation_one "$may_own_invocation_one" \
    --arg invocation_two "$may_own_invocation_two" \
    --arg invocation_three "$may_own_invocation_three" \
    --arg first_call "$may_own_first_boundary_call" \
    --arg second_call "$may_own_second_boundary_call" \
    --arg removal_call "$may_own_third_boundary_call" \
    --arg before_digest "$before_digest" \
    --arg after_digest "$after_digest" \
    --arg state_records "$state_records" '
    {
      schema_version: 1,
      report_kind: "volparossa-helper-restart-may-own-custody-relay-evidence",
      observed_source: {commit_sha: $source_commit, worktree_clean: true},
      observed_artifact_hashes: {
        debugger_sha256: $debugger_digest,
        may_own_observer_sha256: $observer_digest,
        production_ipc_probe_sha256: $probe_digest,
        production_ipc_unit_hook_sha256: $hook_digest,
        volparossa_helper_sha256: $helper_digest
      },
      environment: {
        debian_version: "13", dpkg_architecture: "amd64",
        machine: "x86_64", kernel_release: $kernel_release,
        systemd_version: 257, virtualization: "vm"
      },
      started_at: $started_at,
      finished_at: $finished_at,
      generated_at: $generated_at,
      invocation_ids: [$invocation_one, $invocation_two, $invocation_three],
      restart: {
        initial: {
          argumentless: true,
          target_count: 1,
          target_role: "Relay",
          target_phase: "MayOwnCustody",
          target_disposition: "ExactPresent",
          manager_fdstore_count: 2,
          publication_boundary: $first_call,
          publication_observed_at: $first_boundary_at
        },
        crashes: [
          {
            sequence: 1,
            boundary: $first_call,
            crashed_at: $first_crashed_at,
            signal: "SIGKILL", unit_result: "signal",
            exec_main_code: 2, exec_main_status: 9,
            manager_fdstore_after_crash: 2,
            journal_phase_after_crash: "MayOwnCustody"
          },
          {
            sequence: 2,
            boundary: $second_call,
            boundary_observed_at: $second_boundary_at,
            crashed_at: $second_crashed_at,
            signal: "SIGKILL", unit_result: "signal",
            exec_main_code: 2, exec_main_status: 9,
            manager_fdstore_after_crash: 2,
            journal_phase_after_crash: "MayOwnCustody"
          }
        ],
        recovered: {
          argumentless: true,
          target_count: 1,
          target_role: "Relay",
          inherited_descriptor_count: 2,
          cleanup_confirmed_before_removal: true,
          removal_boundary: $removal_call,
          removal_observed_at: $third_boundary_at,
          manager_fdstore_after_removal: 0,
          journal_phase_after_settlement: "Absent",
          journal_absent_origin: "RecoveredMayOwn",
          new_socket_published_before_settlement: false,
          new_socket_published_after_settlement: true,
          settled_at: $settled_at,
          unit_load_state_after_retirement: "not-found"
        }
      },
      retirement: {
        journal_settled_absent: true,
        lock_released: true,
        socket_absent: true
      },
      enumerated_host_state: {
        before_sha256: $before_digest,
        after_sha256: $after_digest,
        equal_at_fences: true,
        records: ($state_records | split(" "))
      },
      scope: {
        helper_boundary_only: true,
        may_own_custody_exact_present_singleton_relay: true,
        forced_helper_crash_count: 2,
        general_restart_recovery: false,
        cleanup_owned: false,
        installed_package: false,
        usable_datapath: false,
        acceptance_a01_a15: false
      },
      checks: [
        "OBSERVED_SOURCE_TREE_CLEAN",
        "OBSERVED_ARTIFACT_HASHES",
        "DEBIAN_13_AMD64_X86_64_SYSTEMD_257_VM",
        "INITIAL_INVOCATION_BOUND",
        "INITIAL_ARGUMENTLESS_PRODUCTION_BOUNDARY",
        "SINGLETON_RELAY_MAY_OWN_CUSTODY_EXACT_PRESENT",
        "FIRST_CRASH_AT_PUBLISHED_TERMINAL_GUARD",
        "FIRST_FORCED_HELPER_SIGKILL_OBSERVED",
        "FIRST_SYSTEMD_FDSTORE_EXACT_CUSTODY_PRESERVED",
        "SECOND_DISTINCT_ARGUMENTLESS_INVOCATION_BOUND",
        "SECOND_INHERITED_SINGLETON_MAY_OWN_EXACT_PRESENT",
        "REAPER_CLEANUP_EVIDENCE_REACHED_JOURNAL_BOUNDARY",
        "SECOND_FORCED_HELPER_SIGKILL_OBSERVED",
        "SECOND_SYSTEMD_FDSTORE_EXACT_CUSTODY_PRESERVED",
        "THIRD_DISTINCT_ARGUMENTLESS_INVOCATION_BOUND",
        "THIRD_INHERITED_SINGLETON_MAY_OWN_EXACT_PRESENT",
        "CLEANUP_CONFIRMED_BEFORE_MANAGER_REMOVAL",
        "STARTUP_REMOVAL_CALL_OBSERVED",
        "MANAGER_FDSTORE_ZERO_AFTER_REMOVAL",
        "JOURNAL_ABSENT_RECOVERED_MAY_OWN",
        "SOCKET_PUBLISHED_ONLY_AFTER_SETTLEMENT",
        "RECOVERED_UNIT_RETIRED_NOT_FOUND",
        "RETIREMENT_LOCK_RELEASED",
        "RETIREMENT_SOCKET_ABSENT",
        "ENUMERATED_HOST_STATE_EQUAL_AT_FENCES"
      ] | map({id: ., result: "PASS"}),
      overall: "PASS"
    }
' >"$may_own_report_path" \
    || failed 'the canonical MayOwn Relay report could not be generated'
chmod 0600 "$may_own_report_path" \
    || failed 'the MayOwn Relay report mode could not be fixed'
may_own_validator_stdout=$temporary_stage/may-own-validator.stdout
may_own_validator_stderr=$temporary_stage/may-own-validator.stderr
install -o root -g root -m 0600 /dev/null \
    "$may_own_validator_stdout" "$may_own_validator_stderr"
set +e
"$may_own_evidence_validator" "$may_own_report_path" \
    >"$may_own_validator_stdout" 2>"$may_own_validator_stderr"
may_own_validator_status=$?
set -e
if [ "$may_own_validator_status" -ne 0 ] \
    || [ -s "$may_own_validator_stdout" ] \
    || [ -s "$may_own_validator_stderr" ]; then
    failed 'the MayOwn Relay report failed strict validation'
fi
validated_may_own_report=$(cat "$may_own_report_path") \
    || failed 'the validated MayOwn Relay report could not be retained'
if [ -z "$validated_may_own_report" ] \
    || [ "${#validated_may_own_report}" -gt 32768 ]; then
    failed 'the validated MayOwn Relay report has an invalid publication size'
fi
final_checkpoint=publication-fence
publication_source_commit=$(git -c safe.directory="$repository_directory" \
    -C "$repository_directory" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) \
    || failed 'the source commit could not be publication-fenced'
publication_source_status=$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$repository_directory" \
    -C "$repository_directory" status --porcelain=v1 --untracked-files=normal \
    --ignore-submodules=none 2>/dev/null) \
    || failed 'the source worktree state could not be publication-fenced'
if [ "$publication_source_commit" != "$source_commit" ] \
    || [ -n "$publication_source_status" ]; then
    failed 'the exact clean source revision changed before report publication'
fi
final_checkpoint=stage-retirement
if ! remove_temporary_stage; then
    cleanup_error=yes
    failed 'the validated temporary proof stage could not be removed before publication'
fi

printf '%s\n' \
    'PASS: staged helper identity plus exact CleanupConfirmed and MayOwn Relay singleton restart slices were proved.' \
    'SCOPE: helper boundary only; no mixed, CleanupOwned, general restart-recovery, usable datapath, or A01-A15 claim.' >&2
printf '%s\n' "$validated_report"
printf '%s\n' "$validated_restart_report"
printf '%s\n' "$validated_may_own_report"
