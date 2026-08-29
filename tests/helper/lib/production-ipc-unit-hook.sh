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
functional_underlay=vpfu0
functional_underlay_alias=volparossa-proof-underlay-v1
functional_underlay_address=192.31.195.254
functional_underlay_gateway=192.31.195.1
functional_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready
functional_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass
functional_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_EXTERNAL_CLEANUP_V1=pass
functional_release_byte=G

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

functional_underlay_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_expected_ifindex=$1
    number_is_safe "$hook_expected_ifindex" || return 1
    /usr/sbin/ip -details -json link show dev "$functional_underlay" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$functional_underlay" \
            --arg alias "$functional_underlay_alias" \
            --argjson ifindex "$hook_expected_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].ifalias == $alias
              and .[0].linkinfo.info_kind == "dummy"
              and (.[0].flags | index("UP")) != null
            ' >/dev/null 2>&1 \
        || return 1
    /usr/sbin/ip -4 -json address show dev "$functional_underlay" 2>/dev/null \
        | /usr/bin/jq -e --arg address "$functional_underlay_address" '
              type == "array" and length == 1
              and ([.[0].addr_info[]
                    | select(.family == "inet"
                        and .local == $address
                        and .prefixlen == 24
                        and .scope == "global")] | length) == 1
            ' >/dev/null 2>&1 \
        || return 1
    /usr/sbin/ip -4 -json route show default dev "$functional_underlay" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg dev "$functional_underlay" \
            --arg gateway "$functional_underlay_gateway" \
            --arg source "$functional_underlay_address" '
              type == "array" and length == 1
              and .[0].dst == "default"
              and .[0].dev == $dev
              and .[0].gateway == $gateway
              and .[0].prefsrc == $source
            ' >/dev/null 2>&1
}

remove_functional_underlay() {
    [ "$#" -eq 1 ] || return 1
    hook_remove_ifindex=$1
    functional_underlay_is_exact "$hook_remove_ifindex" || return 1
    /usr/sbin/ip link delete dev "$functional_underlay" || return 1
    [ ! -e "/sys/class/net/$functional_underlay" ] \
        && [ ! -L "/sys/class/net/$functional_underlay" ]
}

direct_helper_child() {
    [ "$#" -eq 1 ] || return 1
    hook_parent_pid=$1
    number_is_safe "$hook_parent_pid" || return 1
    hook_children=$(
        for hook_children_file in /proc/"$hook_parent_pid"/task/*/children; do
            [ -f "$hook_children_file" ] || exit 1
            cat "$hook_children_file" || exit 1
            printf '\n'
        done \
            | tr ' ' '\n' \
            | sed '/^$/d' \
            | sort -u
    ) || return 1
    case $hook_children in
        ''|*[!0-9]*) return 1 ;;
    esac
    number_is_safe "$hook_children" || return 1
    printf '%s\n' "$hook_children"
}

helper_has_no_children() {
    [ "$#" -eq 1 ] || return 1
    hook_parent_pid=$1
    number_is_safe "$hook_parent_pid" || return 1
    for hook_children_file in /proc/"$hook_parent_pid"/task/*/children; do
        [ -f "$hook_children_file" ] || return 1
        hook_children_value=$(cat "$hook_children_file") || return 1
        [ -z "$hook_children_value" ] || return 1
    done
}

worker_identity_is_exact() {
    [ "$#" -eq 5 ] || return 1
    hook_worker_pid=$1
    hook_parent_pid=$2
    hook_worker_uid=$3
    hook_worker_gid=$4
    hook_expected_executable=$5
    for hook_number in \
        "$hook_worker_pid" "$hook_parent_pid" "$hook_worker_uid" "$hook_worker_gid"; do
        number_is_safe "$hook_number" || return 1
    done
    hook_worker_status=/proc/$hook_worker_pid/status
    [ -f "$hook_worker_status" ] || return 1
    [ "$(awk '$1 == "PPid:" { print $2 }' "$hook_worker_status")" = \
        "$hook_parent_pid" ] || return 1
    [ "$(awk '$1 == "Uid:" { print $2 ":" $3 ":" $4 ":" $5 }' \
        "$hook_worker_status")" = \
        "$hook_worker_uid:$hook_worker_uid:$hook_worker_uid:$hook_worker_uid" ] || return 1
    [ "$(awk '$1 == "Gid:" { print $2 ":" $3 ":" $4 ":" $5 }' \
        "$hook_worker_status")" = \
        "$hook_worker_gid:$hook_worker_gid:$hook_worker_gid:$hook_worker_gid" ] || return 1
    [ "$(awk '$1 == "Groups:" { print NF }' "$hook_worker_status")" = 1 ] \
        || return 1
    hook_worker_executable=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h' \
        "/proc/$hook_worker_pid/exe" 2>/dev/null) || return 1
    [ "$hook_worker_executable" = "$hook_expected_executable" ] || return 1
    hook_expected_cmdline=$proof_directory/worker.expected-cmdline
    [ ! -e "$hook_expected_cmdline" ] && [ ! -L "$hook_expected_cmdline" ] || return 1
    printf '/proc/self/exe\000--internal-worker-v3\000' >"$hook_expected_cmdline" \
        || return 1
    chmod 0600 "$hook_expected_cmdline" || return 1
    if ! private_file_is_safe "$hook_expected_cmdline" \
        || ! cmp -s "$hook_expected_cmdline" "/proc/$hook_worker_pid/cmdline"; then
        rm -f -- "$hook_expected_cmdline"
        return 1
    fi
    rm -f -- "$hook_expected_cmdline"
}

worker_wireguard_interface() {
    [ "$#" -eq 1 ] || return 1
    hook_namespace_fd=$1
    number_is_safe "$hook_namespace_fd" || return 1
    hook_interfaces=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show interfaces 2>/dev/null) || return 1
    case $hook_interfaces in
        ''|*[!A-Za-z0-9_.-]*|*' '*) return 1 ;;
    esac
    [ "${#hook_interfaces}" -le 15 ] || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/sbin/ip -details -json link show dev "$hook_interfaces" 2>/dev/null \
        | /usr/bin/jq -e --arg name "$hook_interfaces" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].linkinfo.info_kind == "wireguard"
              and (.[0].flags | index("UP")) != null
              and (.[0].ifalias | type) == "string"
              and (.[0].ifalias | startswith("volparossa:wireguard:ownership-v1:"))
            ' >/dev/null 2>&1 \
        || return 1
    hook_public_key=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interfaces" public-key 2>/dev/null) || return 1
    case $hook_public_key in
        ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
    esac
    [ "${#hook_public_key}" -eq 44 ] || return 1
    hook_listen_port=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interfaces" listen-port 2>/dev/null) || return 1
    case $hook_listen_port in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "$hook_listen_port" -le 65535 ] || return 1
    hook_firewall_mark=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interfaces" fwmark 2>/dev/null) || return 1
    [ "$hook_firewall_mark" = off ] || return 1
    hook_peers=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interfaces" peers 2>/dev/null) || return 1
    [ -z "$hook_peers" ] || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/sbin/ip -6 -json address show dev "$hook_interfaces" 2>/dev/null \
        | /usr/bin/jq -e '
              type == "array" and length == 1
              and ([.[0].addr_info[]
                    | select(.family == "inet6"
                        and .prefixlen == 128
                        and .scope == "global")] | length) == 1
            ' >/dev/null 2>&1 \
        || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/sbin/ip -details -json link show 2>/dev/null \
        | /usr/bin/jq -e --arg interface "$hook_interfaces" '
              type == "array" and length == 2
              and any(.[]; .ifname == "lo")
              and any(.[]; .ifname == $interface)
              and all(.[]; .ifname == "lo" or .ifname == $interface)
            ' >/dev/null 2>&1 \
        || return 1
    printf '%s\n' "$hook_interfaces"
}

worker_wireguard_is_absent() {
    [ "$#" -eq 1 ] || return 1
    hook_namespace_fd=$1
    number_is_safe "$hook_namespace_fd" || return 1
    hook_interfaces=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show interfaces 2>/dev/null) || return 1
    [ -z "$hook_interfaces" ] || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/sbin/ip -details -json link show 2>/dev/null \
        | /usr/bin/jq -e '
              type == "array"
              and all(.[].linkinfo.info_kind?; . != "wireguard")
              and all(.[].ifalias?;
                    (type != "string")
                    or (startswith("volparossa:wireguard:ownership-v1:") | not))
            ' >/dev/null 2>&1
}

private_network_is_pristine() {
    hook_private_namespace=$(stat -Lc '%d:%i' /proc/self/ns/net 2>/dev/null) \
        || return 1
    hook_pid1_namespace=$(stat -Lc '%d:%i' /proc/1/ns/net 2>/dev/null) \
        || return 1
    [ "$hook_private_namespace" != "$hook_pid1_namespace" ] || return 1
    /usr/sbin/ip -details -json link show 2>/dev/null \
        | /usr/bin/jq -e '
              type == "array" and length == 1
              and .[0].ifname == "lo"
              and all(.[].linkinfo.info_kind?; . != "wireguard")
              and all(.[].ifalias?;
                    (type != "string")
                    or (startswith("volparossa:wireguard:ownership-v1:") | not))
            ' >/dev/null 2>&1 \
        || return 1
    hook_private_ipv4_defaults=$(/usr/sbin/ip -json route show default 2>/dev/null) \
        || return 1
    [ "$hook_private_ipv4_defaults" = '[]' ] || return 1
    hook_private_ipv6_defaults=$(/usr/sbin/ip -6 -json route show default 2>/dev/null) \
        || return 1
    [ "$hook_private_ipv6_defaults" = '[]' ]
}

unit_fdstore_is_empty() {
    [ "$#" -eq 1 ] || return 1
    hook_fdstore_unit=$1
    unit_name_is_safe "$hook_fdstore_unit" || return 1
    hook_fdstore_count=$(systemctl show --property=NFileDescriptorStore --value \
        "$hook_fdstore_unit" 2>/dev/null) || return 1
    [ "$hook_fdstore_count" = 0 ]
}

helper_does_not_hold_namespace() {
    [ "$#" -eq 2 ] || return 1
    hook_namespace_helper_pid=$1
    hook_namespace_identity=$2
    number_is_safe "$hook_namespace_helper_pid" || return 1
    case $hook_namespace_identity in
        ''|*[!0-9:]*) return 1 ;;
    esac
    for hook_helper_fd in /proc/"$hook_namespace_helper_pid"/fd/*; do
        [ -e "$hook_helper_fd" ] || [ -L "$hook_helper_fd" ] || continue
        hook_helper_fd_identity=$(stat -Lc '%d:%i' "$hook_helper_fd" 2>/dev/null || true)
        [ "$hook_helper_fd_identity" != "$hook_namespace_identity" ] || return 1
    done
}

helper_holds_no_foreign_network_namespace() {
    [ "$#" -eq 1 ] || return 1
    hook_namespace_helper_pid=$1
    number_is_safe "$hook_namespace_helper_pid" || return 1
    hook_parent_network_namespace=$(readlink \
        "/proc/$hook_namespace_helper_pid/ns/net" 2>/dev/null) || return 1
    case $hook_parent_network_namespace in
        net:\[*\]) ;;
        *) return 1 ;;
    esac
    hook_parent_network_namespace_number=${hook_parent_network_namespace#net:[}
    hook_parent_network_namespace_number=${hook_parent_network_namespace_number%]}
    number_is_safe "$hook_parent_network_namespace_number" || return 1
    for hook_helper_fd in /proc/"$hook_namespace_helper_pid"/fd/*; do
        [ -e "$hook_helper_fd" ] || [ -L "$hook_helper_fd" ] || continue
        if hook_helper_fd_target=$(readlink "$hook_helper_fd" 2>/dev/null); then
            case $hook_helper_fd_target in
                net:\[*\])
                    [ "$hook_helper_fd_target" = "$hook_parent_network_namespace" ] \
                        || return 1
                    ;;
            esac
        elif [ -e "$hook_helper_fd" ] || [ -L "$hook_helper_fd" ]; then
            return 1
        fi
    done
}

functional_probe_output_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_functional_output=$1
    private_file_is_safe "$hook_functional_output" || return 1
    hook_functional_expected=$hook_functional_output.expected
    [ ! -e "$hook_functional_expected" ] && [ ! -L "$hook_functional_expected" ] \
        || return 1
    printf '%s\n%s\n' "$functional_ready_record" "$functional_pass_record" \
        >"$hook_functional_expected" || return 1
    chmod 0600 "$hook_functional_expected" || return 1
    if ! private_file_is_safe "$hook_functional_expected" \
        || ! cmp -s "$hook_functional_expected" "$hook_functional_output"; then
        rm -f -- "$hook_functional_expected"
        return 1
    fi
    rm -f -- "$hook_functional_expected"
}

run_functional_client_lease_probe() {
    [ "$#" -eq 8 ] || return 1
    hook_functional_unit=$1
    hook_functional_main_pid=$2
    hook_functional_agent_uid=$3
    hook_functional_agent_gid=$4
    hook_functional_operator_gid=$5
    hook_functional_worker_uid=$6
    hook_functional_worker_gid=$7
    hook_functional_expected_executable=$8
    unit_name_is_safe "$hook_functional_unit" || return 1
    for hook_functional_number in \
        "$hook_functional_main_pid" \
        "$hook_functional_agent_uid" \
        "$hook_functional_agent_gid" \
        "$hook_functional_operator_gid" \
        "$hook_functional_worker_uid" \
        "$hook_functional_worker_gid"; do
        number_is_safe "$hook_functional_number" || return 1
    done
    case $hook_functional_expected_executable in
        ''|*[!0-9:A-Za-z\ _-]*) return 1 ;;
    esac
    private_network_is_pristine || return 1
    [ ! -e "/sys/class/net/$functional_underlay" ] \
        && [ ! -L "/sys/class/net/$functional_underlay" ] || return 1

    /usr/sbin/ip link add name "$functional_underlay" type dummy || return 1
    /usr/sbin/ip link set dev "$functional_underlay" alias \
        "$functional_underlay_alias" || return 1
    /usr/sbin/ip link set dev "$functional_underlay" up || return 1
    /usr/sbin/ip address add "$functional_underlay_address/24" \
        broadcast 0.0.0.0 dev "$functional_underlay" || return 1
    /usr/sbin/ip route add default via "$functional_underlay_gateway" \
        dev "$functional_underlay" src "$functional_underlay_address" || return 1
    hook_functional_ifindex=$(cat "/sys/class/net/$functional_underlay/ifindex") \
        || return 1
    functional_underlay_is_exact "$hook_functional_ifindex" || return 1

    hook_functional_fifo=$proof_directory/functional-client-lease.release
    hook_functional_stdout=$proof_directory/functional-client-lease.stdout
    hook_functional_stderr=$proof_directory/functional-client-lease.stderr
    for hook_functional_path in \
        "$hook_functional_fifo" "$hook_functional_stdout" "$hook_functional_stderr"; do
        [ ! -e "$hook_functional_path" ] && [ ! -L "$hook_functional_path" ] || return 1
    done
    mkfifo -m 0600 "$hook_functional_fifo" || return 1
    [ "$(stat -Lc '%F:%u:%g:%a:%h' "$hook_functional_fifo" 2>/dev/null || true)" = \
        'fifo:0:0:600:1' ] || return 1
    install -o root -g root -m 0600 /dev/null \
        "$hook_functional_stdout" "$hook_functional_stderr" || return 1
    private_file_is_safe "$hook_functional_stdout" || return 1
    private_file_is_safe "$hook_functional_stderr" || return 1
    exec 6<>"$hook_functional_fifo" || return 1
    (
        exec 6>&-
        exec /usr/bin/setpriv \
            --reuid="$hook_functional_agent_uid" \
            --regid="$hook_functional_agent_gid" \
            --groups="$hook_functional_operator_gid" \
            --inh-caps=-all \
            --ambient-caps=-all \
            --bounding-set=-all \
            --no-new-privs \
            "$probe" functional-client-lease \
                "$hook_functional_main_pid" "$hook_functional_agent_gid" \
            <"$hook_functional_fifo"
    ) >"$hook_functional_stdout" 2>"$hook_functional_stderr" &
    hook_functional_probe_pid=$!
    number_is_safe "$hook_functional_probe_pid" || return 1

    hook_functional_wait_attempt=0
    while ! probe_output_is_exact \
        "$hook_functional_stdout" "$functional_ready_record"; do
        private_file_is_safe "$hook_functional_stderr" || return 1
        [ ! -s "$hook_functional_stderr" ] || return 1
        kill -0 "$hook_functional_probe_pid" 2>/dev/null || return 1
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 300 ] || return 1
        sleep 0.05
    done
    private_file_is_safe "$hook_functional_stderr" || return 1
    [ ! -s "$hook_functional_stderr" ] || return 1
    running_identity_is_unchanged \
        "$hook_functional_unit" "$proof_directory/unit.identity" || return 1
    socket_identity_is_unchanged \
        "$proof_directory/socket.identity" "$hook_functional_agent_gid" || return 1
    unit_fdstore_is_empty "$hook_functional_unit" || return 1

    hook_functional_worker_pid=$(direct_helper_child "$hook_functional_main_pid") \
        || return 1
    worker_identity_is_exact \
        "$hook_functional_worker_pid" \
        "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" \
        "$hook_functional_worker_gid" \
        "$hook_functional_expected_executable" || return 1
    hook_functional_parent_namespace=$(stat -Lc '%d:%i' \
        "/proc/$hook_functional_main_pid/ns/net" 2>/dev/null) || return 1
    hook_functional_worker_namespace=$(stat -Lc '%d:%i' \
        "/proc/$hook_functional_worker_pid/ns/net" 2>/dev/null) || return 1
    [ "$hook_functional_parent_namespace" != "$hook_functional_worker_namespace" ] \
        || return 1
    exec 7<"/proc/$hook_functional_worker_pid/ns/net" || return 1
    hook_functional_pinned_namespace=$(stat -Lc '%d:%i' \
        /proc/self/fd/7 2>/dev/null) || return 1
    [ "$hook_functional_pinned_namespace" = "$hook_functional_worker_namespace" ] \
        || return 1
    hook_functional_wireguard=$(worker_wireguard_interface 7) || return 1
    case $hook_functional_wireguard in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac

    rm -f -- "$hook_functional_fifo" || return 1
    [ ! -e "$hook_functional_fifo" ] && [ ! -L "$hook_functional_fifo" ] || return 1
    printf '%s' "$functional_release_byte" >&6 || return 1
    exec 6>&-
    if wait "$hook_functional_probe_pid"; then
        hook_functional_probe_status=0
    else
        hook_functional_probe_status=$?
    fi
    [ "$hook_functional_probe_status" -eq 0 ] || return 1
    functional_probe_output_is_exact "$hook_functional_stdout" || return 1
    private_file_is_safe "$hook_functional_stderr" || return 1
    [ ! -s "$hook_functional_stderr" ] || return 1
    rm -f -- "$hook_functional_stdout" "$hook_functional_stderr" || return 1

    running_identity_is_unchanged \
        "$hook_functional_unit" "$proof_directory/unit.identity" || return 1
    socket_identity_is_unchanged \
        "$proof_directory/socket.identity" "$hook_functional_agent_gid" || return 1
    unit_fdstore_is_empty "$hook_functional_unit" || return 1
    hook_functional_wait_attempt=0
    while ! helper_has_no_children "$hook_functional_main_pid"; do
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    worker_wireguard_is_absent 7 || return 1
    helper_does_not_hold_namespace \
        "$hook_functional_main_pid" "$hook_functional_worker_namespace" || return 1
    helper_holds_no_foreign_network_namespace \
        "$hook_functional_main_pid" || return 1
    exec 7>&-
    [ ! -e /proc/self/fd/7 ] && [ ! -L /proc/self/fd/7 ] || return 1

    remove_functional_underlay "$hook_functional_ifindex" || return 1
    private_network_is_pristine || return 1
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

    hook_expected_executable=$(sed -n '3p' "$identity_file") \
        || fail 'production helper executable identity could not be read'
    run_functional_client_lease_probe \
        "$hook_unit" \
        "$hook_expected_main_pid" \
        "$agent_uid" \
        "$agent_gid" \
        "$operator_gid" \
        "$worker_uid" \
        "$worker_gid" \
        "$hook_expected_executable" \
        || fail 'functional client lease live proof failed'

    hook_start_pass=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
        "$functional_ready_record" \
        "$functional_pass_record" \
        "$functional_cleanup_record")
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
