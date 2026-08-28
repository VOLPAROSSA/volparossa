#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed start/stop proof hook for the live production helper IPC phase.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

runtime_directory=/run/volparossa
helper_socket=$runtime_directory/helper.sock
cleanup_token=$runtime_directory/helper.cleanup-token
journal=$runtime_directory/helper.ownership-v3
journal_lock=$runtime_directory/helper.ownership-v3.lock
journal_next=$runtime_directory/helper.ownership-v3.next
proof_directory=/run/volparossa-helper-production-proof
probe=/run/volparossa-helper-production-ipc-probe
production_helper=/run/volparossa-helper-production

fail() {
    printf 'production IPC unit hook failed: %s\n' "$1" >&2
    exit 1
}

number_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|0|0*|*[!0-9]*) return 1 ;;
        *) [ "${#1}" -le 10 ] && [ "$1" -le 4294967294 ] ;;
    esac
}

unit_name_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service)
            return 0
            ;;
        *) return 1 ;;
    esac
}

invocation_id_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ "${#1}" -eq 32 ] || return 1
    case $1 in
        *[!0-9a-f]*|00000000000000000000000000000000) return 1 ;;
        *) return 0 ;;
    esac
}

private_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    # 0x8180 is S_IFREG | 0600 for both empty and non-empty regular files.
    [ "$(stat -Lc '%f:%u:%g:%a:%h' "$1" 2>/dev/null || true)" = \
        '8180:0:0:600:1' ]
}

write_private_file() {
    [ "$#" -eq 2 ] || return 1
    hook_destination=$1
    hook_payload=$2
    hook_temporary=$hook_destination.next
    [ ! -e "$hook_destination" ] && [ ! -L "$hook_destination" ] || return 1
    [ ! -e "$hook_temporary" ] && [ ! -L "$hook_temporary" ] || return 1
    if ! printf '%s\n' "$hook_payload" >"$hook_temporary"; then
        rm -f -- "$hook_temporary"
        return 1
    fi
    chmod 0600 "$hook_temporary" || {
        rm -f -- "$hook_temporary"
        return 1
    }
    private_file_is_safe "$hook_temporary" || {
        rm -f -- "$hook_temporary"
        return 1
    }
    mv -- "$hook_temporary" "$hook_destination" || {
        rm -f -- "$hook_temporary"
        return 1
    }
    private_file_is_safe "$hook_destination"
}

checksum_file() {
    [ "$#" -eq 1 ] || return 1
    hook_checksum_line=$(sha256sum "$1") || return 1
    hook_checksum=${hook_checksum_line%% *}
    [ "${#hook_checksum}" -eq 64 ] || return 1
    case $hook_checksum in
        ''|*[!0-9a-f]*) return 1 ;;
        *) printf '%s\n' "$hook_checksum" ;;
    esac
}

unit_invocation_id() {
    [ "$#" -eq 1 ] || return 1
    unit_name_is_safe "$1" || return 1
    hook_invocation=$(systemctl show --property=InvocationID --value "$1" 2>/dev/null) \
        || return 1
    invocation_id_is_safe "$hook_invocation" || return 1
    printf '%s\n' "$hook_invocation"
}

unit_main_pid() {
    [ "$#" -eq 1 ] || return 1
    unit_name_is_safe "$1" || return 1
    hook_main_pid=$(systemctl show --property=MainPID --value "$1" 2>/dev/null) || return 1
    number_is_safe "$hook_main_pid" || return 1
    printf '%s\n' "$hook_main_pid"
}

capture_socket_identity() {
    [ "$#" -eq 1 ] || return 1
    hook_socket_gid=$1
    number_is_safe "$hook_socket_gid" || return 1
    hook_socket_identity=$(stat -c '%d:%i:%F:%u:%g:%a:%h' \
        "$helper_socket" 2>/dev/null) || return 1
    case $hook_socket_identity in
        *":socket:0:$hook_socket_gid:660:1") printf '%s\n' "$hook_socket_identity" ;;
        *) return 1 ;;
    esac
}

socket_identity_is_unchanged() {
    [ "$#" -eq 2 ] || return 1
    hook_socket_identity_file=$1
    hook_socket_gid=$2
    private_file_is_safe "$hook_socket_identity_file" || return 1
    hook_expected_socket_identity=$(cat "$hook_socket_identity_file") || return 1
    hook_observed_socket_identity=$(capture_socket_identity "$hook_socket_gid") || return 1
    [ "$hook_observed_socket_identity" = "$hook_expected_socket_identity" ]
}

capture_lock_identity() {
    [ "$#" -eq 1 ] || return 1
    hook_lock_gid=$1
    number_is_safe "$hook_lock_gid" || return 1
    hook_lock_identity=$(stat -c '%d:%i:%f:%u:%g:%a:%h' \
        "$journal_lock" 2>/dev/null) || return 1
    case $hook_lock_identity in
        *":8180:0:$hook_lock_gid:600:1") printf '%s\n' "$hook_lock_identity" ;;
        *) return 1 ;;
    esac
}

command_line_is_argumentless() {
    [ "$#" -eq 1 ] || return 1
    hook_command_pid=$1
    number_is_safe "$hook_command_pid" || return 1
    hook_expected_command=$proof_directory/expected-command-line
    [ ! -e "$hook_expected_command" ] && [ ! -L "$hook_expected_command" ] || return 1
    printf '%s\000' "$production_helper" >"$hook_expected_command" || return 1
    chmod 0600 "$hook_expected_command" || return 1
    if ! private_file_is_safe "$hook_expected_command" \
        || ! cmp -s "$hook_expected_command" "/proc/$hook_command_pid/cmdline"; then
        rm -f -- "$hook_expected_command"
        return 1
    fi
    rm -f -- "$hook_expected_command"
}

capture_running_identity() {
    [ "$#" -eq 1 ] || return 1
    hook_identity_unit=$1
    hook_identity_invocation=$(unit_invocation_id "$hook_identity_unit") || return 1
    hook_identity_pid=$(unit_main_pid "$hook_identity_unit") || return 1
    command_line_is_argumentless "$hook_identity_pid" || return 1
    hook_executable_metadata=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h' \
        "/proc/$hook_identity_pid/exe" 2>/dev/null) || return 1
    hook_expected_executable_metadata=$(stat -c '%d:%i:%F:%u:%g:%a:%h' \
        "$production_helper" 2>/dev/null) || return 1
    [ "$hook_executable_metadata" = "$hook_expected_executable_metadata" ] || return 1
    printf '%s\n%s\n%s\n' \
        "$hook_identity_invocation" "$hook_identity_pid" "$hook_executable_metadata"
}

running_identity_is_unchanged() {
    [ "$#" -eq 2 ] || return 1
    hook_identity_unit=$1
    hook_identity_file=$2
    private_file_is_safe "$hook_identity_file" || return 1
    hook_expected_identity=$(cat "$hook_identity_file") || return 1
    hook_observed_identity=$(capture_running_identity "$hook_identity_unit") || return 1
    [ "$hook_observed_identity" = "$hook_expected_identity" ]
}

probe_output_is_exact() {
    [ "$#" -eq 2 ] || return 1
    hook_probe_output=$1
    hook_expected_line=$2
    private_file_is_safe "$hook_probe_output" || return 1
    hook_expected_output=$hook_probe_output.expected
    [ ! -e "$hook_expected_output" ] && [ ! -L "$hook_expected_output" ] || return 1
    printf '%s\n' "$hook_expected_line" >"$hook_expected_output" || return 1
    chmod 0600 "$hook_expected_output" || return 1
    if ! private_file_is_safe "$hook_expected_output" \
        || ! cmp -s "$hook_expected_output" "$hook_probe_output"; then
        rm -f -- "$hook_expected_output"
        return 1
    fi
    rm -f -- "$hook_expected_output"
}

run_probe() {
    [ "$#" -eq 11 ] || return 1
    hook_probe_name=$1
    hook_probe_mode=$2
    hook_probe_uid=$3
    hook_probe_gid=$4
    hook_probe_groups=$5
    hook_probe_expected=$6
    hook_probe_unit=$7
    hook_probe_identity=$8
    hook_probe_socket_identity=$9
    hook_expected_main_pid=${10}
    hook_expected_agent_gid=${11}
    number_is_safe "$hook_expected_main_pid" || return 1
    number_is_safe "$hook_expected_agent_gid" || return 1
    hook_probe_stdout=$proof_directory/$hook_probe_name.stdout
    hook_probe_stderr=$proof_directory/$hook_probe_name.stderr
    [ ! -e "$hook_probe_stdout" ] && [ ! -L "$hook_probe_stdout" ] || return 1
    [ ! -e "$hook_probe_stderr" ] && [ ! -L "$hook_probe_stderr" ] || return 1
    running_identity_is_unchanged "$hook_probe_unit" "$hook_probe_identity" || return 1
    socket_identity_is_unchanged \
        "$hook_probe_socket_identity" "$hook_expected_agent_gid" || return 1

    if [ "$hook_probe_groups" = clear ]; then
        if /usr/bin/setpriv \
            --reuid="$hook_probe_uid" \
            --regid="$hook_probe_gid" \
            --clear-groups \
            --inh-caps=-all \
            --ambient-caps=-all \
            --bounding-set=-all \
            --no-new-privs \
            "$probe" "$hook_probe_mode" \
                "$hook_expected_main_pid" "$hook_expected_agent_gid" \
            >"$hook_probe_stdout" 2>"$hook_probe_stderr"; then
            hook_probe_status=0
        else
            hook_probe_status=$?
        fi
    else
        number_is_safe "$hook_probe_groups" || return 1
        if /usr/bin/setpriv \
            --reuid="$hook_probe_uid" \
            --regid="$hook_probe_gid" \
            --groups="$hook_probe_groups" \
            --inh-caps=-all \
            --ambient-caps=-all \
            --bounding-set=-all \
            --no-new-privs \
            "$probe" "$hook_probe_mode" \
                "$hook_expected_main_pid" "$hook_expected_agent_gid" \
            >"$hook_probe_stdout" 2>"$hook_probe_stderr"; then
            hook_probe_status=0
        else
            hook_probe_status=$?
        fi
    fi
    running_identity_is_unchanged "$hook_probe_unit" "$hook_probe_identity" || return 1
    socket_identity_is_unchanged \
        "$hook_probe_socket_identity" "$hook_expected_agent_gid" || return 1
    [ "$hook_probe_status" -eq 0 ] || return 1
    chmod 0600 "$hook_probe_stdout" "$hook_probe_stderr" || return 1
    probe_output_is_exact "$hook_probe_stdout" "$hook_probe_expected" || return 1
    private_file_is_safe "$hook_probe_stderr" || return 1
    [ ! -s "$hook_probe_stderr" ] || return 1
    rm -f -- "$hook_probe_stdout" "$hook_probe_stderr"
}

validate_runtime_metadata() {
    [ "$#" -eq 1 ] || return 1
    hook_agent_gid=$1
    [ "$(stat -c '%F:%u:%g:%a' "$runtime_directory" 2>/dev/null || true)" = \
        "directory:0:$hook_agent_gid:750" ] || return 1
    [ "$(stat -c '%F:%u:%g:%a:%h' "$helper_socket" 2>/dev/null || true)" = \
        "socket:0:$hook_agent_gid:660:1" ] || return 1
    [ "$(stat -c '%F:%u:%g:%a:%h:%s' "$cleanup_token" 2>/dev/null || true)" = \
        "regular file:0:$hook_agent_gid:640:1:32" ] || return 1
    if [ -e "$journal" ] || [ -L "$journal" ]; then
        [ "$(stat -c '%f:%u:%g:%a:%h' "$journal" 2>/dev/null || true)" = \
            "8180:0:$hook_agent_gid:600:1" ] || return 1
    fi
    [ "$(stat -c '%f:%u:%g:%a:%h' "$journal_lock" 2>/dev/null || true)" = \
        "8180:0:$hook_agent_gid:600:1" ] || return 1
    [ ! -e "$journal_next" ] && [ ! -L "$journal_next" ]
}

capture_journal_state() {
    [ "$#" -eq 1 ] || return 1
    hook_agent_gid=$1
    if [ ! -e "$journal" ] && [ ! -L "$journal" ]; then
        printf '%s\n' ABSENT
        return 0
    fi
    hook_journal_before=$(stat -c '%d:%i:%f:%u:%g:%a:%h:%s:%y:%z' \
        "$journal" 2>/dev/null) || return 1
    case $hook_journal_before in
        *":8180:0:$hook_agent_gid:600:1:"*) ;;
        *) return 1 ;;
    esac
    hook_journal_checksum=$(checksum_file "$journal") || return 1
    hook_journal_after=$(stat -c '%d:%i:%f:%u:%g:%a:%h:%s:%y:%z' \
        "$journal" 2>/dev/null) || return 1
    [ "$hook_journal_before" = "$hook_journal_after" ] || return 1
    printf 'PRESENT\n%s\n%s\n' "$hook_journal_before" "$hook_journal_checksum"
}

start_hook() {
    [ "$#" -eq 6 ] || fail 'start hook argument count is invalid'
    hook_unit=$1
    agent_uid=$2
    agent_gid=$3
    operator_gid=$4
    worker_uid=$5
    worker_gid=$6
    unit_name_is_safe "$hook_unit" || fail 'unit name is unsafe'
    for hook_id in "$agent_uid" "$agent_gid" "$operator_gid" "$worker_uid" "$worker_gid"; do
        number_is_safe "$hook_id" || fail 'staged identity is invalid'
    done
    [ "$agent_uid" -eq "$agent_gid" ] || fail 'agent UID/GID are not paired'
    [ "$worker_uid" -eq "$worker_gid" ] || fail 'worker UID/GID are not paired'
    if [ "$agent_uid" -eq "$operator_gid" ] \
        || [ "$agent_uid" -eq "$worker_uid" ] \
        || [ "$operator_gid" -eq "$worker_gid" ]; then
        fail 'staged identities overlap'
    fi
    [ "$(stat -c '%F:%u:%g:%a' "$proof_directory" 2>/dev/null || true)" = \
        'directory:0:0:2700' ] || fail 'proof directory is unsafe'
    [ "$(stat -c '%F:%u:%g:%a:%h' "$probe" 2>/dev/null || true)" = \
        "regular file:0:$agent_gid:550:1" ] || fail 'probe executable is unsafe'

    hook_wait_attempt=0
    while [ ! -S "$helper_socket" ]; do
        hook_wait_attempt=$((hook_wait_attempt + 1))
        [ "$hook_wait_attempt" -lt 600 ] || fail 'production helper socket did not appear'
        sleep 0.05
    done
    validate_runtime_metadata "$agent_gid" || fail 'production runtime metadata is invalid'

    hook_socket_identity=$(capture_socket_identity "$agent_gid") \
        || fail 'production helper socket identity is unavailable'
    write_private_file "$proof_directory/socket.identity" "$hook_socket_identity" \
        || fail 'production helper socket identity could not be published'
    hook_lock_identity=$(capture_lock_identity "$agent_gid") \
        || fail 'ownership journal lock identity is unavailable'

    hook_identity=$(capture_running_identity "$hook_unit") \
        || fail 'production helper identity is unavailable'
    write_private_file "$proof_directory/unit.identity" "$hook_identity" \
        || fail 'production helper identity proof could not be published'

    if ! exec 8<>"$journal_lock"; then
        fail 'active ownership journal lock could not be opened'
    fi
    hook_active_lock_fd_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h' \
        /proc/self/fd/8 2>/dev/null) || fail 'active ownership journal lock FD is invalid'
    [ "$hook_active_lock_fd_identity" = "$hook_lock_identity" ] \
        || fail 'active ownership journal lock FD identity changed'
    hook_active_lock_path_before=$(capture_lock_identity "$agent_gid") \
        || fail 'active ownership journal lock path is unavailable'
    [ "$hook_active_lock_path_before" = "$hook_lock_identity" ] \
        || fail 'active ownership journal lock path was replaced while opened'
    if /usr/bin/flock -n -x -E 42 8; then
        hook_active_flock_status=0
    else
        hook_active_flock_status=$?
    fi
    [ "$hook_active_flock_status" -eq 42 ] \
        || fail 'active helper does not exclusively hold its ownership journal lock'
    running_identity_is_unchanged "$hook_unit" "$proof_directory/unit.identity" \
        || fail 'production helper identity changed during active lock proof'
    hook_active_lock_path_after=$(capture_lock_identity "$agent_gid") \
        || fail 'active ownership journal lock path changed during contention proof'
    [ "$hook_active_lock_path_after" = "$hook_lock_identity" ] \
        || fail 'active ownership journal lock path was replaced during contention proof'
    exec 8>&-
    hook_active_lock_path_after_close=$(capture_lock_identity "$agent_gid") \
        || fail 'active ownership journal lock path changed after contention proof'
    [ "$hook_active_lock_path_after_close" = "$hook_lock_identity" ] \
        || fail 'active ownership journal lock path was replaced after contention proof'
    running_identity_is_unchanged "$hook_unit" "$proof_directory/unit.identity" \
        || fail 'production helper identity changed after active lock proof'
    write_private_file "$proof_directory/lock.identity" "$hook_lock_identity" \
        || fail 'ownership journal lock identity could not be published'

    hook_journal_state=$(capture_journal_state "$agent_gid") \
        || fail 'initial journal state could not be captured'
    write_private_file "$proof_directory/journal.state" "$hook_journal_state" \
        || fail 'initial journal state could not be published'

    bind_pass=VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=pass
    frame_pass=VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass
    wire_pass=VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass
    unauthorised_pass=VOLPAROSSA_HELPER_V3_IPC_UNAUTHORISED_PEER_V1=pass
    identity_file=$proof_directory/unit.identity
    socket_identity_file=$proof_directory/socket.identity
    hook_expected_main_pid=$(sed -n '2p' "$identity_file") \
        || fail 'production helper MainPID could not be read'
    number_is_safe "$hook_expected_main_pid" \
        || fail 'production helper MainPID is invalid'

    run_probe bind-before bind-runtime "$agent_uid" "$agent_gid" "$operator_gid" \
        "$bind_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'initial authenticated runtime bind failed'
    run_probe frame-bounds reject-frame-bounds "$agent_uid" "$agent_gid" "$operator_gid" \
        "$frame_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'frame-bound rejection failed'
    run_probe wire-shapes reject-wire-shapes "$agent_uid" "$agent_gid" "$operator_gid" \
        "$wire_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'wire-shape rejection failed'
    run_probe wrong-uid expect-unauthorised-peer "$worker_uid" "$agent_gid" clear \
        "$unauthorised_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'wrong-UID rejection failed'
    run_probe wrong-gid expect-unauthorised-peer "$agent_uid" "$operator_gid" "$agent_gid" \
        "$unauthorised_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'wrong-GID rejection failed'
    run_probe root-peer expect-unauthorised-peer 0 "$agent_gid" clear \
        "$unauthorised_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'root-peer rejection failed'
    run_probe bind-after bind-runtime "$agent_uid" "$agent_gid" "$operator_gid" \
        "$bind_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'final authenticated runtime bind failed'

    hook_start_pass=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass')
    write_private_file "$proof_directory/start.pass" "$hook_start_pass" \
        || fail 'production IPC start proof could not be published'
}

stop_hook() {
    [ "$#" -eq 2 ] || fail 'stop hook argument count is invalid'
    hook_unit=$1
    hook_expected_agent_gid=$2
    unit_name_is_safe "$hook_unit" || fail 'unit name is unsafe'
    number_is_safe "$hook_expected_agent_gid" || fail 'expected agent GID is invalid'
    [ "${SERVICE_RESULT:-}" = success ] || fail 'service result is not successful'
    [ "${EXIT_CODE:-}" = exited ] || fail 'main process did not exit normally'
    [ "${EXIT_STATUS:-}" = 0 ] || fail 'main process exit status is nonzero'
    private_file_is_safe "$proof_directory/unit.identity" \
        || fail 'start identity proof is unavailable'
    hook_start_invocation=$(sed -n '1p' "$proof_directory/unit.identity") \
        || fail 'start invocation identity could not be read'
    invocation_id_is_safe "$hook_start_invocation" \
        || fail 'start invocation identity is invalid'
    hook_stop_invocation=$(unit_invocation_id "$hook_unit") \
        || fail 'stop invocation identity is unavailable'
    [ "$hook_stop_invocation" = "$hook_start_invocation" ] \
        || fail 'unit invocation changed before stop proof'
    if [ -e "$helper_socket" ] || [ -L "$helper_socket" ]; then
        fail 'production helper socket remained after main exit'
    fi
    if [ -e "$journal_next" ] || [ -L "$journal_next" ]; then
        fail 'temporary journal entry remained after main exit'
    fi
    private_file_is_safe "$proof_directory/journal.state" \
        || fail 'initial journal state proof is unavailable'
    hook_expected_journal_state=$(cat "$proof_directory/journal.state") \
        || fail 'initial journal state could not be read'
    hook_observed_journal_state=$(capture_journal_state "$hook_expected_agent_gid") \
        || fail 'settled journal state could not be captured'
    [ "$hook_observed_journal_state" = "$hook_expected_journal_state" ] \
        || fail 'journal changed during non-mutating IPC proof'
    private_file_is_safe "$proof_directory/lock.identity" \
        || fail 'initial lock identity proof is unavailable'
    hook_expected_lock_identity=$(cat "$proof_directory/lock.identity") \
        || fail 'initial lock identity could not be read'
    hook_lock_path_before=$(capture_lock_identity "$hook_expected_agent_gid") \
        || fail 'settled lock path identity is unavailable'
    [ "$hook_lock_path_before" = "$hook_expected_lock_identity" ] \
        || fail 'ownership journal lock path identity changed'
    if ! exec 9<>"$journal_lock"; then
        fail 'ownership journal lock could not be opened'
    fi
    hook_lock_fd_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h' \
        /proc/self/fd/9 2>/dev/null) || fail 'ownership journal lock FD is invalid'
    [ "$hook_lock_fd_identity" = "$hook_expected_lock_identity" ] \
        || fail 'ownership journal lock FD identity changed'
    hook_lock_path_after_open=$(capture_lock_identity "$hook_expected_agent_gid") \
        || fail 'ownership journal lock path changed while opened'
    [ "$hook_lock_path_after_open" = "$hook_expected_lock_identity" ] \
        || fail 'ownership journal lock path was replaced while opened'
    /usr/bin/flock -n 9 || fail 'ownership journal lock remained held after main exit'
    hook_lock_path_after_flock=$(capture_lock_identity "$hook_expected_agent_gid") \
        || fail 'ownership journal lock path changed while acquired'
    [ "$hook_lock_path_after_flock" = "$hook_expected_lock_identity" ] \
        || fail 'ownership journal lock path was replaced while acquired'
    exec 9>&-
    hook_fdstore_count=$(systemctl show --property=NFileDescriptorStore --value \
        "$hook_unit" 2>/dev/null) || fail 'descriptor-store count is unavailable'
    [ "$hook_fdstore_count" = 0 ] || fail 'descriptor store is not empty at stop'
    write_private_file "$proof_directory/stop.pass" \
        'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass' \
        || fail 'production IPC stop proof could not be published'
}

case ${1:-} in
    start)
        shift
        start_hook "$@"
        ;;
    stop)
        shift
        stop_hook "$@"
        ;;
    *) fail 'hook mode is invalid' ;;
esac
