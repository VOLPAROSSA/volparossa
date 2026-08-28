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
        'It is not package-install, restart-recovery, CleanupOwned, datapath, or A01-A15 evidence.'
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
    awk cat chmod chown cmp cp date dpkg find flock getent git id install ip jq mkfifo mktemp mv nft \
    paste prlimit readlink rm sed setpriv sha256sum sleep sort stat systemctl systemd-detect-virt \
    systemd-run tc tr uname
do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        blocked "required Debian tool is unavailable: $command_name"
    fi
done
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
helper_source=$repository_directory/target/debug/volparossa-helper
ipc_probe_source=$repository_directory/target/debug/examples/volparossa-helper-production-ipc-probe
ipc_hook_source=$script_directory/lib/production-ipc-unit-hook.sh
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
production_retired_load_state=

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
    unit_owned=no
    unit_may_own=no
    unit_invocation_id=
    unit_ownership_marker=
    unit_name=
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

unit_job_is_absent() {
    unit_name_is_safe || return 1
    unit_job_value=$(systemctl show --property=Job --value "$unit_name" 2>/dev/null) \
        || return 1
    [ -z "$unit_job_value" ]
}

unit_fdstore_count() {
    unit_name_is_safe || return 1
    unit_fdstore_count_value=$(systemctl show --property=NFileDescriptorStore --value \
        "$unit_name" 2>/dev/null) || return 1
    case $unit_fdstore_count_value in
        0|[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])
            printf '%s\n' "$unit_fdstore_count_value"
            ;;
        *) return 1 ;;
    esac
}

retired_runtime_is_absent() {
    [ "$#" -eq 4 ] || return 1
    retired_unit_name=$1
    retired_control_group=$2
    retired_main_pid=$3
    retired_executable_metadata=$4
    case $retired_unit_name in
        volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service) ;;
        *) return 1 ;;
    esac
    [ "$retired_control_group" = "/system.slice/$retired_unit_name" ] || return 1
    case $retired_main_pid in
        0) [ -z "$retired_executable_metadata" ] || return 1 ;;
        ''|*[!0-9]*) return 1 ;;
        *) [ "$retired_main_pid" -le 4194304 ] || return 1
            [ -n "$retired_executable_metadata" ] || return 1
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
        if [ "$retired_main_pid" -ne 0 ] \
            && { [ -e "/proc/$retired_main_pid/exe" ] \
                || [ -L "/proc/$retired_main_pid/exe" ]; }; then
            retired_observed_executable=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h' \
                "/proc/$retired_main_pid/exe" 2>/dev/null) \
                || retired_observed_executable=
            if [ "$retired_observed_executable" = "$retired_executable_metadata" ]; then
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
    [ "$unit_owned" = no ] || return 1
    [ "$unit_may_own" = yes ] || return 1
    unit_name_is_safe || return 1
    unit_ownership_marker_is_safe "$unit_ownership_marker" || return 1

    adopt_attempt=0
    while :; do
        adopt_load_state=$(unit_load_state) || return 1
        if [ "$adopt_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        unit_description_matches_marker || return 1
        adopted_invocation_id=$(unit_current_invocation_id 2>/dev/null) \
            || adopted_invocation_id=
        if unit_invocation_id_is_safe "$adopted_invocation_id"; then
            unit_description_matches_marker || return 1
            unit_invocation_id=$adopted_invocation_id
            unit_owned=yes
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

retire_unit() {
    if [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ]; then
        adopt_tentative_unit || return 1
    fi
    case $unit_owned in
        no) return 0 ;;
        yes) ;;
        *) return 1 ;;
    esac
    unit_name_is_safe || return 1
    unit_invocation_id_is_safe "$unit_invocation_id" || return 1
    retire_load_state=$(unit_load_state) || return 1
    if [ "$retire_load_state" = not-found ]; then
        forget_unit_ownership
        return 0
    fi
    unit_invocation_is_current || return 1
    if ! systemctl stop --no-block "$unit_name" >/dev/null 2>&1; then
        retire_load_state=$(unit_load_state) || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        unit_invocation_is_current || return 1
        return 1
    fi

    retire_attempt=0
    while :; do
        retire_load_state=$(unit_load_state) || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        unit_invocation_is_current || return 1
        retire_active_state=$(unit_active_state) || return 1
        case $retire_active_state in
            inactive|failed)
                if unit_job_is_absent; then
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
        unit_invocation_is_current || return 1
        if ! systemctl reset-failed "$unit_name" >/dev/null 2>&1; then
            retire_load_state=$(unit_load_state) || return 1
            if [ "$retire_load_state" = not-found ]; then
                forget_unit_ownership
                return 0
            fi
            unit_invocation_is_current || return 1
            return 1
        fi

        retire_attempt=0
        while :; do
            retire_load_state=$(unit_load_state) || return 1
            if [ "$retire_load_state" = not-found ]; then
                forget_unit_ownership
                return 0
            fi
            unit_invocation_is_current || return 1
            retire_active_state=$(unit_active_state) || return 1
            if [ "$retire_active_state" = inactive ] && unit_job_is_absent; then
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
    unit_job_is_absent || return 1
    unit_invocation_is_current || return 1
    if ! systemctl clean --what=fdstore "$unit_name" >/dev/null 2>&1; then
        retire_load_state=$(unit_load_state) || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        unit_invocation_is_current || return 1
        return 1
    fi
    retire_load_state=$(unit_load_state) || return 1
    if [ "$retire_load_state" = not-found ]; then
        forget_unit_ownership
        return 0
    fi
    unit_invocation_is_current || return 1
    retire_fdstore_count=$(unit_fdstore_count) || return 1
    [ "$retire_fdstore_count" -eq 0 ] || return 1

    unit_invocation_is_current || return 1
    if ! systemctl reset-failed "$unit_name" >/dev/null 2>&1; then
        retire_load_state=$(unit_load_state) || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        unit_invocation_is_current || return 1
        return 1
    fi

    retire_attempt=0
    while :; do
        retire_load_state=$(unit_load_state) || return 1
        if [ "$retire_load_state" = not-found ]; then
            forget_unit_ownership
            return 0
        fi
        unit_invocation_is_current || return 1
        retire_active_state=$(unit_active_state) || return 1
        [ "$retire_active_state" = inactive ] || return 1
        unit_job_is_absent || return 1
        retire_fdstore_count=$(unit_fdstore_count) || return 1
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
    if ! retire_unit; then
        cleanup_error=yes
    fi
    if ! remove_temporary_stage; then
        cleanup_error=yes
    fi
    if [ "$cleanup_error" = yes ] && [ "$saved_status" -eq 0 ]; then
        saved_status=1
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

state_records='production_runtime_path accounts namespaces mounts resolver sysctls links addresses routes rules nexthops qdiscs nftables wireguard legacy_ipv4_firewall legacy_ipv6_firewall'

publish_optional_digest_record() {
    [ "$#" -eq 2 ] || failed 'invalid optional state publication request'
    optional_capture=$1
    optional_record=$2
    optional_digest=$(vp_capture_sha256 "$optional_capture") \
        || failed 'an optional host-state capture could not be hashed'
    vp_capture_run "$optional_record" printf '%s\n%s\n' PRESENT "$optional_digest" \
        || failed 'an optional host-state digest could not be published'
}

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
        jq -S -c '
        map(del(.operstate,.link_netnsid,.promiscuity,.allmulti,.stats,.stats64)
            | .flags=((.flags // []) | map(select(. != "LOWER_UP" and . != "RUNNING"
                and . != "DORMANT" and . != "NO-CARRIER")) | sort)
            | if has("altnames") then .altnames |= sort else . end)
        | sort_by(.ifindex,.ifname)
    ' || failed 'host link normalization failed'
    vp_capture_publish_digest "$capture_directory/links.normalized" "$destination/links" \
        || failed 'host link capture could not be published'

    vp_capture_run "$capture_directory/addresses.raw" ip -json address show \
        || failed 'host address producer failed'
    vp_capture_normalize "$capture_directory/addresses.raw" \
        "$capture_directory/addresses.normalized" jq -S -c '
        map({ifindex,ifname,addr_info:((.addr_info // [])
            | map(del(.valid_life_time,.preferred_life_time,.valid_lft,.preferred_lft,
                .tstamp,.cstamp,.tentative,.dadfailed,.deprecated,.optimistic))
            | sort_by(.family,.local,(.peer // ""),.prefixlen,.scope,(.label // "")))})
        | sort_by(.ifindex,.ifname)
    ' || failed 'host address normalization failed'
    vp_capture_publish_digest "$capture_directory/addresses.normalized" "$destination/addresses" \
        || failed 'host address capture could not be published'

    vp_capture_run "$capture_directory/routes-v4.raw" ip -json -4 route show table all \
        || failed 'host IPv4 route producer failed'
    vp_capture_run "$capture_directory/routes-v6.raw" ip -json -6 route show table all \
        || failed 'host IPv6 route producer failed'
    vp_capture_run "$capture_directory/routes.normalized" jq -S -c -s '
        add | walk(if type == "object" then
            del(.expires,.used,.age,.lastuse,.users,.cache,.statistics)
            | if ((.flags? // null)|type) == "array" then
                .flags |= map(select(. != "linkdown" and . != "dead" and . != "offload"
                    and . != "trap" and . != "unresolved")) | sort
              else . end
          else . end)
        | sort_by((.family // ""),(.table // ""|tostring),(.dst // ""),(.src // ""),
            (.metric // 0),(.protocol // ""),(.dev // ""),(.gateway // ""))
    ' "$capture_directory/routes-v4.raw" "$capture_directory/routes-v6.raw" \
        || failed 'host route normalization failed'
    vp_capture_publish_digest "$capture_directory/routes.normalized" "$destination/routes" \
        || failed 'host route capture could not be published'

    vp_capture_run "$capture_directory/rules-v4.raw" ip -json -4 rule show \
        || failed 'host IPv4 rule producer failed'
    vp_capture_run "$capture_directory/rules-v6.raw" ip -json -6 rule show \
        || failed 'host IPv6 rule producer failed'
    vp_capture_run "$capture_directory/rules.normalized" jq -S -c -s '
        add | sort_by(.family,.priority,(.table // ""|tostring),
            (.src // ""),(.dst // ""))
    ' "$capture_directory/rules-v4.raw" "$capture_directory/rules-v6.raw" \
        || failed 'host rule normalization failed'
    vp_capture_publish_digest "$capture_directory/rules.normalized" "$destination/rules" \
        || failed 'host rule capture could not be published'

    vp_capture_run "$capture_directory/nexthops.raw" ip -json nexthop show \
        || failed 'host nexthop producer failed'
    vp_capture_normalize "$capture_directory/nexthops.raw" \
        "$capture_directory/nexthops.normalized" jq -S -c '
        walk(if type == "object" then del(.used,.age,.lastuse,.statistics)
            | if ((.flags? // null)|type) == "array" then
                .flags |= map(select(. != "offload" and . != "trap")) | sort
              else . end else . end)
        | sort_by(.id,(.dev // ""),(.via // ""|tostring))
    ' || failed 'host nexthop normalization failed'
    vp_capture_publish_digest "$capture_directory/nexthops.normalized" "$destination/nexthops" \
        || failed 'host nexthop capture could not be published'

    vp_capture_run "$capture_directory/qdiscs.raw" tc -json qdisc show \
        || failed 'host qdisc producer failed'
    vp_capture_normalize "$capture_directory/qdiscs.raw" \
        "$capture_directory/qdiscs.normalized" jq -S -c '
        walk(if type == "object" then
            del(.refcnt,.bytes,.packets,.drops,.overlimits,.requeues,.backlog,.qlen,
                .direct_packets_stat,.xstats) else . end)
        | sort_by(.dev,(.parent // ""),(.handle // ""),.kind)
    ' || failed 'host qdisc normalization failed'
    vp_capture_publish_digest "$capture_directory/qdiscs.normalized" "$destination/qdiscs" \
        || failed 'host qdisc capture could not be published'

    vp_capture_run "$capture_directory/nftables.raw" nft --json list ruleset \
        || failed 'host nftables producer failed'
    vp_capture_normalize "$capture_directory/nftables.raw" \
        "$capture_directory/nftables.normalized" jq -S -c '
        walk(if type == "object" then
            if has("counter") then .counter |= del(.packets,.bytes) else . end
            | del(.expires,.last,.used) else . end)
    ' || failed 'host nftables normalization failed'
    vp_capture_publish_digest "$capture_directory/nftables.normalized" "$destination/nftables" \
        || failed 'host nftables capture could not be published'

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

    if command -v iptables-save >/dev/null 2>&1; then
        vp_capture_run "$capture_directory/iptables.raw" iptables-save \
            || failed 'host legacy IPv4 firewall producer failed'
        vp_capture_normalize "$capture_directory/iptables.raw" \
            "$capture_directory/iptables.normalized" \
            sed -E 's/\[[0-9]+:[0-9]+\]/[COUNTERS]/g' \
            || failed 'host legacy IPv4 firewall normalization failed'
        publish_optional_digest_record "$capture_directory/iptables.normalized" \
            "$destination/legacy_ipv4_firewall"
    else
        publish_absent_record "$destination/legacy_ipv4_firewall"
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        vp_capture_run "$capture_directory/ip6tables.raw" ip6tables-save \
            || failed 'host legacy IPv6 firewall producer failed'
        vp_capture_normalize "$capture_directory/ip6tables.raw" \
            "$capture_directory/ip6tables.normalized" \
            sed -E 's/\[[0-9]+:[0-9]+\]/[COUNTERS]/g' \
            || failed 'host legacy IPv6 firewall normalization failed'
        publish_optional_digest_record "$capture_directory/ip6tables.normalized" \
            "$destination/legacy_ipv6_firewall"
    else
        publish_absent_record "$destination/legacy_ipv6_firewall"
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

# The helper owns a 30-second spawn budget followed by a separate five-second
# FD-store publication budget and bounded local retirement. Keep PID1's outer
# limits strictly wider so they cannot pre-empt that fail-closed cleanup path.
unit_may_own=yes
set +e
systemd-run \
    --json=short \
    --ignore-failure \
    --collect \
    --unit="$unit_name" \
    --description="$unit_ownership_marker" \
    --service-type=oneshot \
    --remain-after-exit \
    --property=NotifyAccess=main \
    --property=FileDescriptorStoreMax=128 \
    --property=FileDescriptorStorePreserve=yes \
    --property=User=0 \
    --property=Group="$agent_gid" \
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
    --property=ProtectControlGroups=strict \
    --property=Delegate=no \
    --property=PrivatePIDs=no \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectClock=yes \
    --property=ProtectHostname=yes \
    --property=LockPersonality=yes \
    --property=MemoryDenyWriteExecute=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=RestrictNamespaces=net \
    --property=SystemCallArchitectures=native \
    --property='SystemCallFilter=@system-service @network-io seccomp' \
    --property='SystemCallFilter=~@mount' \
    --property=SystemCallErrorNumber=EPERM \
    --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
    --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
    --property="BindReadOnlyPaths=$helper_bind $account_binds $system_bus_bind" \
    --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property=TimeoutStartSec=45s \
    --property=TimeoutStopSec=10s \
    --property=TasksMax=16 \
    --property=SetLoginEnvironment=no \
    --property="StandardOutput=file:$temporary_stage/proof.stdout" \
    --property="StandardError=file:$temporary_stage/proof.stderr" \
    /run/volparossa-helper-live-proof --internal-worker-v3-live-proof \
    >"$temporary_stage/systemd-run.stdout" 2>"$temporary_stage/systemd-run.stderr"
run_status=$?
set -e

proof_ok=yes
if [ "$run_status" -ne 0 ]; then
    proof_ok=no
elif ! vp_capture_file_is_safe "$temporary_stage/systemd-run.stdout" \
    || ! vp_capture_file_is_safe "$temporary_stage/systemd-run.stderr"; then
    proof_ok=no
else
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
    if ! unit_invocation_id_is_safe "$parsed_invocation_id" \
        || [ -s "$temporary_stage/systemd-run.stderr" ]; then
        proof_ok=no
    else
        observed_unit_invocation_id=$(unit_current_invocation_id) \
            || observed_unit_invocation_id=
        if ! unit_description_matches_marker \
            || [ "$observed_unit_invocation_id" != "$parsed_invocation_id" ]; then
            proof_ok=no
        else
            unit_invocation_id=$parsed_invocation_id
            unit_owned=yes
            unit_may_own=no
        fi
    fi
fi
poll_attempt=0
while :; do
    if ! unit_invocation_is_current; then
        proof_ok=no
        break
    fi
    if ! active_state=$(systemctl show --property=ActiveState --value \
        "$unit_name" 2>/dev/null); then
        proof_ok=no
        break
    fi
    if ! sub_state=$(systemctl show --property=SubState --value \
        "$unit_name" 2>/dev/null); then
        proof_ok=no
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
        proof_ok=no
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
    active_state=$(cat "$temporary_stage/unit-active-state") || proof_ok=no
else
    active_state=
    proof_ok=no
fi
if capture_unit_property SubState "$temporary_stage/unit-sub-state"; then
    sub_state=$(cat "$temporary_stage/unit-sub-state") || proof_ok=no
else
    sub_state=
    proof_ok=no
fi
if capture_unit_property Result "$temporary_stage/unit-result"; then
    result=$(cat "$temporary_stage/unit-result") || proof_ok=no
else
    result=
    proof_ok=no
fi
if capture_unit_property ExecMainStatus "$temporary_stage/unit-exec-status"; then
    exec_status=$(cat "$temporary_stage/unit-exec-status") || proof_ok=no
else
    exec_status=
    proof_ok=no
fi
if [ "$active_state" != active ] || [ "$sub_state" != exited ] \
    || [ "$result" != success ] || [ "$exec_status" != 0 ]; then
    proof_ok=no
fi
if capture_unit_property NotifyAccess "$temporary_stage/unit-notify-access"; then
    observed_notify_access=$(cat "$temporary_stage/unit-notify-access") || proof_ok=no
else
    observed_notify_access=
    proof_ok=no
fi
if capture_unit_property Description "$temporary_stage/unit-description"; then
    observed_description=$(cat "$temporary_stage/unit-description") || proof_ok=no
else
    observed_description=
    proof_ok=no
fi
if capture_unit_property Environment "$temporary_stage/unit-environment"; then
    observed_environment=$(cat "$temporary_stage/unit-environment") || proof_ok=no
else
    observed_environment=
    proof_ok=no
fi
if capture_unit_property FileDescriptorStoreMax "$temporary_stage/unit-fdstore-max"; then
    observed_fdstore_max=$(cat "$temporary_stage/unit-fdstore-max") || proof_ok=no
else
    observed_fdstore_max=
    proof_ok=no
fi
if capture_unit_property FileDescriptorStorePreserve \
    "$temporary_stage/unit-fdstore-preserve"; then
    observed_fdstore_preserve=$(cat "$temporary_stage/unit-fdstore-preserve") || proof_ok=no
else
    observed_fdstore_preserve=
    proof_ok=no
fi
if capture_unit_property NFileDescriptorStore "$temporary_stage/unit-fdstore-count"; then
    observed_fdstore_count=$(cat "$temporary_stage/unit-fdstore-count") || proof_ok=no
else
    observed_fdstore_count=
    proof_ok=no
fi
if [ "$observed_notify_access" != main ] \
    || [ "$observed_description" != "$unit_ownership_marker" ] \
    || [ "$observed_environment" \
        != DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket ] \
    || [ "$observed_fdstore_max" != 128 ] \
    || [ "$observed_fdstore_preserve" != yes ] || [ "$observed_fdstore_count" != 2 ]; then
    proof_ok=no
fi
worker_fdstore_before_retirement=$observed_fdstore_count
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass' \
    'VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass' \
    >"$temporary_stage/expected.stdout"
if ! cmp -s "$temporary_stage/expected.stdout" "$temporary_stage/proof.stdout" \
    || [ -s "$temporary_stage/proof.stderr" ]; then
    proof_ok=no
fi

normalize_capabilities() {
    [ "$#" -eq 2 ] || return 1
    # The dollar expressions below belong to awk, not the shell.
    # shellcheck disable=SC2016
    vp_capture_normalize "$1" "$2" awk -v expected="$capabilities" '
        BEGIN {
            expected_count = split(expected, ordered, " ")
            for (index = 1; index <= expected_count; index++) {
                allowed[ordered[index]] = 1
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
    observed_bounding=$(cat "$temporary_stage/unit-bounding.normalized") || proof_ok=no
else
    observed_bounding=
    proof_ok=no
fi
if capture_unit_property AmbientCapabilities "$temporary_stage/unit-ambient.raw" \
    && normalize_capabilities "$temporary_stage/unit-ambient.raw" \
        "$temporary_stage/unit-ambient.normalized"; then
    observed_ambient=$(cat "$temporary_stage/unit-ambient.normalized") || proof_ok=no
else
    observed_ambient=
    proof_ok=no
fi
if capture_unit_property PrivateNetwork "$temporary_stage/unit-private-network"; then
    observed_private_network=$(cat "$temporary_stage/unit-private-network") || proof_ok=no
else
    observed_private_network=
    proof_ok=no
fi
if capture_unit_property ControlGroup "$temporary_stage/unit-control-group"; then
    worker_control_group=$(cat "$temporary_stage/unit-control-group") || proof_ok=no
else
    worker_control_group=
    proof_ok=no
fi
if [ "$observed_bounding" != "$capabilities" ] \
    || [ "$observed_ambient" != "$capabilities" ] \
    || [ "$observed_private_network" != yes ] \
    || [ "$worker_control_group" != "/system.slice/$unit_name" ]; then
    proof_ok=no
fi

worker_unit_name=$unit_name
worker_invocation_id=$unit_invocation_id
worker_ownership_marker=$unit_ownership_marker
if ! retire_unit; then
    cleanup_error=yes
    proof_ok=no
fi

if [ "$proof_ok" = yes ]; then
    if [ -n "$unit_name" ] || [ "$unit_owned" != no ] || [ "$unit_may_own" != no ]; then
        proof_ok=no
    else
        unit_name=$worker_unit_name
        reuse_load_state=$(unit_load_state) || reuse_load_state=
        worker_retired_load_state=$reuse_load_state
        if [ "$reuse_load_state" != not-found ] \
            || ! retired_runtime_is_absent \
                "$worker_unit_name" "$worker_control_group" 0 ''; then
            proof_ok=no
        fi
    fi
fi

if [ "$proof_ok" = yes ]; then
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

    unit_may_own=yes
    set +e
    systemd-run \
        --json=short \
        --ignore-failure \
        --collect \
        --unit="$unit_name" \
        --description="$unit_ownership_marker" \
        --service-type=exec \
        --property=Restart=no \
        --property=RuntimeMaxSec=180s \
        --property=NotifyAccess=main \
        --property=FileDescriptorStoreMax=128 \
        --property=FileDescriptorStorePreserve=yes \
        --property=User=0 \
        --property=Group="$agent_gid" \
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
        --property=ProtectControlGroups=strict \
        --property=Delegate=no \
        --property=PrivatePIDs=no \
        --property=ProtectKernelModules=yes \
        --property=ProtectKernelLogs=yes \
        --property=ProtectClock=yes \
        --property=ProtectHostname=yes \
        --property=LockPersonality=yes \
        --property=MemoryDenyWriteExecute=yes \
        --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=yes \
        --property=RestrictNamespaces=net \
        --property=SystemCallArchitectures=native \
        --property='SystemCallFilter=@system-service @network-io seccomp' \
        --property='SystemCallFilter=~@mount' \
        --property=SystemCallErrorNumber=EPERM \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
        --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
        --property="BindReadOnlyPaths=$production_helper_bind $production_probe_bind $production_hook_bind $account_binds $system_bus_bind" \
        --property="BindPaths=$production_runtime_bind $production_output_bind" \
        --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        --property="ExecStartPost=/run/volparossa-helper-production-ipc-hook start $unit_name $agent_uid $agent_gid $operator_gid $worker_uid $worker_gid" \
        --property="ExecStopPost=/run/volparossa-helper-production-ipc-hook stop $unit_name $agent_gid" \
        --property=KillSignal=SIGTERM \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=90s \
        --property=TimeoutStopSec=45s \
        --property=TasksMax=64 \
        --property=SetLoginEnvironment=no \
        --property=StandardOutput=null \
        --property=StandardError=null \
        /run/volparossa-helper-production \
        >"$temporary_stage/systemd-run-production.stdout" \
        2>"$temporary_stage/systemd-run-production.stderr"
    production_run_status=$?
    set -e

    production_ok=yes
    if [ "$production_run_status" -ne 0 ]; then
        production_ok=no
    elif ! vp_capture_file_is_safe "$temporary_stage/systemd-run-production.stdout" \
        || ! vp_capture_file_is_safe "$temporary_stage/systemd-run-production.stderr"; then
        production_ok=no
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
            production_ok=no
        else
            observed_unit_invocation_id=$(unit_current_invocation_id) \
                || observed_unit_invocation_id=
            if ! unit_description_matches_marker \
                || [ "$observed_unit_invocation_id" != "$production_invocation_id" ]; then
                production_ok=no
            else
                unit_invocation_id=$production_invocation_id
                unit_owned=yes
                unit_may_own=no
            fi
        fi
    fi

    if [ "$unit_owned" = yes ]; then
        poll_attempt=0
        while :; do
            if ! unit_invocation_is_current; then
                production_ok=no
                break
            fi
            active_state=$(systemctl show --property=ActiveState --value \
                "$unit_name" 2>/dev/null) || {
                production_ok=no
                break
            }
            sub_state=$(systemctl show --property=SubState --value \
                "$unit_name" 2>/dev/null) || {
                production_ok=no
                break
            }
            if [ "$active_state:$sub_state" = active:running ]; then
                break
            fi
            case $active_state in
                failed|inactive) production_ok=no; break ;;
            esac
            poll_attempt=$((poll_attempt + 1))
            if [ "$poll_attempt" -ge 2000 ]; then
                production_ok=no
                break
            fi
            sleep 0.05
        done
    else
        production_ok=no
    fi

    if capture_unit_property ActiveState "$temporary_stage/production-active-state"; then
        production_active_state=$(cat "$temporary_stage/production-active-state") \
            || production_ok=no
    else
        production_active_state=
        production_ok=no
    fi
    if capture_unit_property SubState "$temporary_stage/production-sub-state"; then
        production_sub_state=$(cat "$temporary_stage/production-sub-state") \
            || production_ok=no
    else
        production_sub_state=
        production_ok=no
    fi
    if capture_unit_property Result "$temporary_stage/production-result"; then
        production_result=$(cat "$temporary_stage/production-result") || production_ok=no
    else
        production_result=
        production_ok=no
    fi
    if capture_unit_property MainPID "$temporary_stage/production-main-pid"; then
        production_main_pid=$(cat "$temporary_stage/production-main-pid") || production_ok=no
    else
        production_main_pid=
        production_ok=no
    fi
    case $production_main_pid in
        ''|0|*[!0-9]*) production_ok=no ;;
    esac
    if [ "$production_active_state" != active ] \
        || [ "$production_sub_state" != running ] \
        || [ "$production_result" != success ]; then
        production_ok=no
    fi

    if capture_unit_property NotifyAccess "$temporary_stage/production-notify-access"; then
        production_notify_access=$(cat "$temporary_stage/production-notify-access") \
            || production_ok=no
    else
        production_notify_access=
        production_ok=no
    fi
    if capture_unit_property Description "$temporary_stage/production-description"; then
        production_description=$(cat "$temporary_stage/production-description") \
            || production_ok=no
    else
        production_description=
        production_ok=no
    fi
    if capture_unit_property Environment "$temporary_stage/production-environment"; then
        production_environment=$(cat "$temporary_stage/production-environment") \
            || production_ok=no
    else
        production_environment=
        production_ok=no
    fi
    if capture_unit_property FileDescriptorStoreMax \
        "$temporary_stage/production-fdstore-max"; then
        production_fdstore_max=$(cat "$temporary_stage/production-fdstore-max") \
            || production_ok=no
    else
        production_fdstore_max=
        production_ok=no
    fi
    if capture_unit_property FileDescriptorStorePreserve \
        "$temporary_stage/production-fdstore-preserve"; then
        production_fdstore_preserve=$(cat "$temporary_stage/production-fdstore-preserve") \
            || production_ok=no
    else
        production_fdstore_preserve=
        production_ok=no
    fi
    if capture_unit_property NFileDescriptorStore \
        "$temporary_stage/production-fdstore-count"; then
        production_fdstore_count=$(cat "$temporary_stage/production-fdstore-count") \
            || production_ok=no
    else
        production_fdstore_count=
        production_ok=no
    fi
    if capture_unit_property RuntimeMaxUSec \
        "$temporary_stage/production-runtime-max"; then
        production_runtime_max=$(cat "$temporary_stage/production-runtime-max") \
            || production_ok=no
    else
        production_runtime_max=
        production_ok=no
    fi
    if capture_unit_property LimitFSIZE "$temporary_stage/production-limit-fsize"; then
        production_limit_fsize=$(cat "$temporary_stage/production-limit-fsize") \
            || production_ok=no
    else
        production_limit_fsize=
        production_ok=no
    fi
    if capture_unit_property LimitFSIZESoft \
        "$temporary_stage/production-limit-fsize-soft"; then
        production_limit_fsize_soft=$(cat "$temporary_stage/production-limit-fsize-soft") \
            || production_ok=no
    else
        production_limit_fsize_soft=
        production_ok=no
    fi
    if capture_unit_property StandardOutput \
        "$temporary_stage/production-standard-output"; then
        production_standard_output=$(cat "$temporary_stage/production-standard-output") \
            || production_ok=no
    else
        production_standard_output=
        production_ok=no
    fi
    if capture_unit_property StandardError \
        "$temporary_stage/production-standard-error"; then
        production_standard_error=$(cat "$temporary_stage/production-standard-error") \
            || production_ok=no
    else
        production_standard_error=
        production_ok=no
    fi
    if [ "$production_notify_access" != main ] \
        || [ "$production_description" != "$unit_ownership_marker" ] \
        || [ "$production_environment" \
            != DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket ] \
        || [ "$production_fdstore_max" != 128 ] \
        || [ "$production_fdstore_preserve" != yes ] \
        || [ "$production_fdstore_count" != 0 ] \
        || [ "$production_runtime_max" != 3min ] \
        || [ "$production_limit_fsize" != 1048576 ] \
        || [ "$production_limit_fsize_soft" != 1048576 ] \
        || [ "$production_standard_output" != null ] \
        || [ "$production_standard_error" != null ]; then
        production_ok=no
    fi
    production_fdstore_during_run=$production_fdstore_count

    if capture_unit_property CapabilityBoundingSet \
        "$temporary_stage/production-bounding.raw" \
        && normalize_capabilities "$temporary_stage/production-bounding.raw" \
            "$temporary_stage/production-bounding.normalized"; then
        production_bounding=$(cat "$temporary_stage/production-bounding.normalized") \
            || production_ok=no
    else
        production_bounding=
        production_ok=no
    fi
    if capture_unit_property AmbientCapabilities "$temporary_stage/production-ambient.raw" \
        && normalize_capabilities "$temporary_stage/production-ambient.raw" \
            "$temporary_stage/production-ambient.normalized"; then
        production_ambient=$(cat "$temporary_stage/production-ambient.normalized") \
            || production_ok=no
    else
        production_ambient=
        production_ok=no
    fi
    if capture_unit_property PrivateNetwork "$temporary_stage/production-private-network"; then
        production_private_network=$(cat "$temporary_stage/production-private-network") \
            || production_ok=no
    else
        production_private_network=
        production_ok=no
    fi
    if capture_unit_property ControlGroup "$temporary_stage/production-control-group"; then
        production_control_group=$(cat "$temporary_stage/production-control-group") \
            || production_ok=no
    else
        production_control_group=
        production_ok=no
    fi
    if [ "$production_bounding" != "$capabilities" ] \
        || [ "$production_ambient" != "$capabilities" ] \
        || [ "$production_private_network" != yes ] \
        || [ "$production_control_group" != "/system.slice/$unit_name" ]; then
        production_ok=no
    fi

    production_identity=$temporary_stage/production-output/unit.identity
    if vp_capture_file_is_safe "$production_identity"; then
        identity_invocation=$(sed -n '1p' "$production_identity") || production_ok=no
        identity_main_pid=$(sed -n '2p' "$production_identity") || production_ok=no
        identity_executable=$(sed -n '3p' "$production_identity") || production_ok=no
        identity_extra=$(sed -n '4p' "$production_identity") || production_ok=no
        if [ "$identity_invocation" != "$unit_invocation_id" ] \
            || [ "$identity_main_pid" != "$production_main_pid" ] \
            || [ -z "$identity_executable" ] || [ -n "$identity_extra" ]; then
            production_ok=no
        fi
    else
        production_ok=no
    fi

    production_socket_identity_file=$temporary_stage/production-output/socket.identity
    if vp_capture_file_is_safe "$production_socket_identity_file"; then
        expected_production_socket_identity=$(cat "$production_socket_identity_file") \
            || production_ok=no
    else
        expected_production_socket_identity=
        production_ok=no
    fi
    production_socket_identity=$(stat -c '%d:%i:%F:%u:%g:%a:%h' \
        "$temporary_stage/production-runtime/helper.sock" 2>/dev/null) \
        || production_socket_identity=
    case $production_socket_identity in
        *":socket:0:$agent_gid:660:1") ;;
        *) production_ok=no ;;
    esac
    if [ "$production_socket_identity" != "$expected_production_socket_identity" ]; then
        production_ok=no
    fi

    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
        >"$temporary_stage/expected-production-start.pass"
    if ! vp_capture_file_is_safe "$temporary_stage/production-output/start.pass" \
        || ! cmp -s "$temporary_stage/expected-production-start.pass" \
            "$temporary_stage/production-output/start.pass"; then
        production_ok=no
    fi

    if [ "$(stat -c '%F:%u:%g:%a' "$temporary_stage/production-runtime" \
        2>/dev/null || true)" != "directory:0:$agent_gid:750" ] \
        || [ "$(stat -c '%F:%u:%g:%a:%h' \
            "$temporary_stage/production-runtime/helper.sock" 2>/dev/null || true)" \
            != "socket:0:$agent_gid:660:1" ] \
        || [ "$(stat -c '%F:%u:%g:%a:%h:%s' \
            "$temporary_stage/production-runtime/helper.cleanup-token" 2>/dev/null || true)" \
            != "regular file:0:$agent_gid:640:1:32" ] \
        || [ "$(stat -c '%F:%u:%g:%a:%h' \
            "$temporary_stage/production-runtime/helper.ownership-v3.lock" \
            2>/dev/null || true)" != "regular file:0:$agent_gid:600:1" ] \
        || [ -e "$temporary_stage/production-runtime/helper.ownership-v3.next" ] \
        || [ -L "$temporary_stage/production-runtime/helper.ownership-v3.next" ]; then
        production_ok=no
    fi
    if [ -e "$temporary_stage/production-runtime/helper.ownership-v3" ] \
        || [ -L "$temporary_stage/production-runtime/helper.ownership-v3" ]; then
        if [ "$(stat -c '%F:%u:%g:%a:%h' \
            "$temporary_stage/production-runtime/helper.ownership-v3" \
            2>/dev/null || true)" != "regular file:0:$agent_gid:600:1" ]; then
            production_ok=no
        fi
    fi

    if ! unit_invocation_is_current; then
        production_ok=no
    fi
    final_main_pid=$(systemctl show --property=MainPID --value "$unit_name" 2>/dev/null) \
        || final_main_pid=
    if [ "$final_main_pid" != "$production_main_pid" ]; then
        production_ok=no
    fi

    production_unit_name=$unit_name
    if ! retire_unit; then
        cleanup_error=yes
        production_ok=no
    fi
    if [ -n "$unit_name" ] || [ "$unit_owned" != no ] || [ "$unit_may_own" != no ]; then
        production_ok=no
    else
        unit_name=$production_unit_name
        production_retired_load_state=$(unit_load_state) || production_retired_load_state=
        if [ "$production_retired_load_state" != not-found ] \
            || ! retired_runtime_is_absent "$production_unit_name" \
                "$production_control_group" "$production_main_pid" \
                "$identity_executable"; then
            production_ok=no
        fi
        forget_unit_ownership
    fi
    production_lock_path=$temporary_stage/production-runtime/helper.ownership-v3.lock
    production_lock_identity_file=$temporary_stage/production-output/lock.identity
    if vp_capture_file_is_safe "$production_lock_identity_file"; then
        expected_production_lock_identity=$(cat "$production_lock_identity_file") \
            || production_ok=no
    else
        expected_production_lock_identity=
        production_ok=no
    fi
    production_lock_path_before=$(stat -c '%d:%i:%F:%u:%g:%a:%h' \
        "$production_lock_path" 2>/dev/null) || production_lock_path_before=
    case $production_lock_path_before in
        *":regular file:0:$agent_gid:600:1") ;;
        *) production_ok=no ;;
    esac
    if [ "$production_lock_path_before" != "$expected_production_lock_identity" ]; then
        production_ok=no
    fi
    if exec 9<>"$production_lock_path"; then
        production_lock_fd_identity=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h' \
            /proc/self/fd/9 2>/dev/null) || production_lock_fd_identity=
        if [ "$production_lock_fd_identity" != "$expected_production_lock_identity" ] \
            || ! /usr/bin/flock -n 9; then
            production_ok=no
        fi
        production_lock_path_after=$(stat -c '%d:%i:%F:%u:%g:%a:%h' \
            "$production_lock_path" 2>/dev/null) || production_lock_path_after=
        if [ "$production_lock_path_after" != "$expected_production_lock_identity" ]; then
            production_ok=no
        fi
        exec 9>&-
    else
        production_ok=no
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
        production_ok=no
    fi
    if [ "$production_ok" != yes ]; then
        proof_ok=no
    fi
fi
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
if [ "$proof_ok" != yes ]; then
    failed 'the staged helper did not produce the exact identity/fdstore and production IPC proofs'
fi
if [ "$cleanup_error" != no ]; then
    failed 'the staged proof recorded an earlier retirement or cleanup failure'
fi
if [ "$worker_fdstore_before_retirement" != 2 ] \
    || [ "$worker_retired_load_state" != not-found ] \
    || [ "$production_fdstore_during_run" != 0 ] \
    || [ "$production_retired_load_state" != not-found ]; then
    failed 'the retained fdstore or exact-unit retirement observations are incomplete'
fi

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
if [ "$source_before" != "$source_final" ] \
    || [ "$source_digest_before" != "$source_digest_final" ] \
    || [ "$staged_digest" != "$staged_digest_final" ] \
    || [ "$ipc_probe_before" != "$ipc_probe_final" ] \
    || [ "$ipc_probe_digest_before" != "$ipc_probe_digest_final" ] \
    || [ "$staged_ipc_probe_digest" != "$staged_ipc_probe_digest_final" ] \
    || [ "$ipc_hook_before" != "$ipc_hook_final" ] \
    || [ "$ipc_hook_digest_before" != "$ipc_hook_digest_final" ] \
    || [ "$staged_ipc_hook_digest" != "$staged_ipc_hook_digest_final" ]; then
    failed 'a source or staged proof artifact changed during live execution'
fi
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

finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
    || failed 'the execution finish time cannot be established'
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
    || failed 'the report generation time cannot be established'
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
        fdstore_during_run: ($production_fdstore_during_run | tonumber),
        unit_load_state_after_retirement: $production_retired_load_state
      },
      retirement: {journal_unchanged: true, lock_released: true, socket_absent: true},
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
        "PRODUCTION_FDSTORE_ZERO_DURING_RUN",
        "PRODUCTION_RETIRED_UNIT_NOT_FOUND",
        "RETIREMENT_JOURNAL_UNCHANGED",
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
validator_stdout=$temporary_stage/report-validator.stdout
validator_stderr=$temporary_stage/report-validator.stderr
install -o root -g root -m 0600 /dev/null "$validator_stdout" "$validator_stderr" \
    || failed 'private validator output files could not be created'
set +e
"$evidence_validator" "$report_path" >"$validator_stdout" 2>"$validator_stderr"
validator_status=$?
set -e
if ! vp_capture_file_is_safe "$validator_stdout" \
    || ! vp_capture_file_is_safe "$validator_stderr" \
    || [ "$validator_status" -ne 0 ] \
    || [ -s "$validator_stdout" ] \
    || [ -s "$validator_stderr" ]; then
    failed 'the helper-boundary report failed strict validation'
fi
validated_report=$(cat "$report_path") \
    || failed 'the validated helper-boundary report could not be retained for publication'
if [ -z "$validated_report" ] || [ "${#validated_report}" -gt 65535 ]; then
    failed 'the validated helper-boundary report has an invalid publication size'
fi
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
if ! remove_temporary_stage; then
    cleanup_error=yes
    failed 'the validated temporary proof stage could not be removed before publication'
fi

printf '%s\n' \
    'PASS: staged helper identity, exact two-FD custody, production IPC, clean stop, confinement, and pin release were proved.' \
    'SCOPE: helper boundary only; no CleanupOwned, datapath, or A01-A15 result is claimed.' >&2
printf '%s\n' "$validated_report"
