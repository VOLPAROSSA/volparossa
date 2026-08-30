#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed start/stop proof hook for the live production helper IPC phase.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

system_bus_address=unix:path=/run/dbus/system_bus_socket
runtime_directory=/run/volparossa
helper_socket=$runtime_directory/helper.sock
cleanup_token=$runtime_directory/helper.cleanup-token
journal=$runtime_directory/helper.ownership-v3
journal_lock=$runtime_directory/helper.ownership-v3.lock
journal_next=$runtime_directory/helper.ownership-v3.next
proof_directory=/run/volparossa-helper-production-proof
host_network_identity_record=/run/volparossa-helper-production-host-network.identity
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
helper_bootstrap_capability_mask=00000000002031e0
start_failure_record=$proof_directory/start.failure
start_failure_stage=
start_failure_armed=no
start_failure_published=no

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

fd_number_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        0) return 0 ;;
        ''|0*|*[!0-9]*) return 1 ;;
        *) [ "${#1}" -le 10 ] && [ "$1" -le 4294967294 ] ;;
    esac
}

kernel_object_number_is_safe() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|0|0*|*[!0-9]*) return 1 ;;
        *) [ "${#1}" -le 20 ] ;;
    esac
}

kernel_object_identity_is_safe() {
    [ "$#" -eq 1 ] || return 1
    hook_kernel_device=${1%%:*}
    hook_kernel_inode=${1#*:}
    [ "$1" = "$hook_kernel_device:$hook_kernel_inode" ] || return 1
    kernel_object_number_is_safe "$hook_kernel_device" \
        && kernel_object_number_is_safe "$hook_kernel_inode"
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

start_failure_stage_is_safe() {
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
        functional-probe-finish|\
        functional-cleanup|\
        publication)
            return 0
            ;;
        *) return 1 ;;
    esac
}

advance_start_failure_stage() {
    [ "$#" -eq 1 ] || return 1
    case "$start_failure_stage:$1" in
        preflight-runtime:identity-socket|\
        identity-socket:identity-lock|\
        identity-lock:identity-manager|\
        identity-manager:identity-launch|\
        identity-launch:identity-birth|\
        identity-birth:identity-process|\
        identity-process:identity-stability|\
        identity-stability:identity-publication|\
        identity-publication:active-lock|\
        active-lock:protocol-bind-before|\
        protocol-bind-before:protocol-frame-bounds|\
        protocol-frame-bounds:protocol-wire-shapes|\
        protocol-wire-shapes:protocol-wrong-uid|\
        protocol-wrong-uid:protocol-wrong-gid|\
        protocol-wrong-gid:protocol-root-peer|\
        protocol-root-peer:protocol-bind-after|\
        protocol-bind-after:functional-underlay|\
        functional-underlay:functional-underlay-parent-contract|\
        functional-underlay-parent-contract:functional-underlay-pristine-namespace|\
        functional-underlay-pristine-namespace:functional-underlay-pristine-link|\
        functional-underlay-pristine-link:functional-underlay-pristine-ipv-four|\
        functional-underlay-pristine-ipv-four:functional-underlay-pristine-ipv-six|\
        functional-underlay-pristine-ipv-six:functional-underlay-absent|\
        functional-underlay-absent:functional-underlay-link|\
        functional-underlay-link:functional-underlay-address|\
        functional-underlay-address:functional-underlay-route|\
        functional-underlay-route:functional-underlay-ifindex|\
        functional-underlay-ifindex:functional-underlay-readback-link|\
        functional-underlay-readback-link:functional-underlay-readback-address|\
        functional-underlay-readback-address:functional-underlay-readback-route|\
        functional-underlay-readback-route:functional-probe-ready|\
        functional-probe-ready:functional-probe-fixture|\
        functional-probe-fixture:functional-probe-launch|\
        functional-probe-launch:functional-probe-wait|\
        functional-probe-wait:functional-probe-identity|\
        functional-probe-identity:functional-probe-socket|\
        functional-probe-socket:functional-probe-fdstore|\
        functional-probe-fdstore:functional-worker-observation|\
        functional-worker-observation:functional-probe-finish|\
        functional-probe-finish:functional-cleanup|\
        functional-cleanup:publication)
            start_failure_stage=$1
            ;;
        *) return 1 ;;
    esac
}

publish_start_failure() {
    [ "$start_failure_armed" = yes ] || return 1
    [ "$start_failure_published" = no ] || return 1
    start_failure_stage_is_safe "$start_failure_stage" || return 1
    write_private_file "$start_failure_record" \
        "VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=$start_failure_stage" \
        || return 1
    start_failure_published=yes
}

start_failure_exit() {
    start_failure_status=$?
    trap - EXIT
    if [ "$start_failure_status" -ne 0 ] \
        && [ "$start_failure_armed" = yes ] \
        && [ "$start_failure_published" = no ]; then
        publish_start_failure || :
    fi
    exit "$start_failure_status"
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

capture_launch_image_metadata() {
    [ "$#" -eq 1 ] || return 1
    hook_image_path=$1
    [ "$hook_image_path" = "$production_helper" ] || return 1
    [ -f "$hook_image_path" ] && [ ! -L "$hook_image_path" ] || return 1
    hook_image_stat=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h:%s' \
        "$hook_image_path" 2>/dev/null) || return 1
    [ "${#hook_image_stat}" -le 256 ] || return 1
    printf '%s\n' "$hook_image_stat" | /usr/bin/awk -F: '
        function canonical_positive(value) {
            return value ~ /^[1-9][0-9]*$/ && length(value) <= 20
        }
        NR != 1 { invalid = 1; next }
        {
            if (NF != 8 || !canonical_positive($1) \
                || !canonical_positive($2) || $3 != "regular file" \
                || $4 != 0 || $5 != 0 || $6 != 500 || $7 != 1 \
                || !canonical_positive($8) || length($8) > 9 \
                || $8 > 134217728) {
                invalid = 1
                next
            }
            record = "launch-image-v1=device:" $1 ";inode:" $2 \
                ";size:" $8
            accepted++
        }
        END {
            if (invalid || NR != 1 || accepted != 1) exit 1
            print record
        }
    '
}

capture_launch_image_identity() {
    [ "$#" -eq 1 ] || return 1
    hook_image_metadata=$(capture_launch_image_metadata "$1") || return 1
    hook_image_digest=$(checksum_file "$1") || return 1
    printf '%s;sha256:%s\n' "$hook_image_metadata" "$hook_image_digest"
}

launch_image_matches_identity() {
    [ "$#" -eq 2 ] || return 1
    hook_image_path=$1
    hook_expected_image=$2
    hook_expected_image_metadata=${hook_expected_image%;sha256:*}
    hook_expected_image_digest=${hook_expected_image#"$hook_expected_image_metadata;sha256:"}
    [ "$hook_expected_image" = \
        "$hook_expected_image_metadata;sha256:$hook_expected_image_digest" ] || return 1
    [ "${#hook_expected_image_digest}" -eq 64 ] || return 1
    case $hook_expected_image_digest in
        *[!0-9a-f]*) return 1 ;;
    esac
    [ "$(capture_launch_image_metadata "$hook_image_path")" = \
        "$hook_expected_image_metadata" ]
}

unit_object_path() {
    [ "$#" -eq 1 ] || return 1
    unit_name_is_safe "$1" || return 1
    hook_object_json=$(/usr/bin/busctl \
        --address="$system_bus_address" \
        --json=short \
        call \
        org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager \
        GetUnit s "$1" 2>/dev/null) \
        || return 1
    [ "${#hook_object_json}" -le 512 ] || return 1
    hook_object_path=$(printf '%s' "$hook_object_json" | /usr/bin/jq -ers '
        if length == 1
            and (.[0] | keys) == ["data", "type"]
            and .[0].type == "o"
            and (.[0].data | type) == "array"
            and (.[0].data | length) == 1
            and (.[0].data[0] | type) == "string"
        then .[0].data[0]
        else empty
        end
    ') || return 1
    hook_expected_object=$(printf '%s' "$1" \
        | /usr/bin/sed -e 's/-/_2d/g' -e 's/\./_2e/g') || return 1
    [ "$hook_object_path" = \
        "/org/freedesktop/systemd1/unit/$hook_expected_object" ] || return 1
    printf '%s\n' "$hook_object_path"
}

unit_invocation_id() {
    [ "$#" -eq 1 ] || return 1
    hook_invocation_object=$(unit_object_path "$1") || return 1
    hook_invocation_json=$(/usr/bin/busctl \
        --address="$system_bus_address" \
        --json=short \
        get-property \
        org.freedesktop.systemd1 \
        "$hook_invocation_object" \
        org.freedesktop.systemd1.Unit \
        InvocationID 2>/dev/null) || return 1
    [ "${#hook_invocation_json}" -le 512 ] || return 1
    hook_invocation_octets=$(printf '%s' "$hook_invocation_json" | /usr/bin/jq -ers '
        if length == 1
            and (.[0] | keys) == ["data", "type"]
            and .[0].type == "ay"
            and (.[0].data | type) == "array"
            and (.[0].data | length) == 16
            and all(.[0].data[];
                (type == "number") and . >= 0 and . <= 255 and floor == .)
        then .[0].data | @tsv
        else empty
        end
    ') || return 1
    hook_invocation=$(printf '%s\n' "$hook_invocation_octets" | /usr/bin/awk -F '\t' '
        NF == 16 {
            for (field = 1; field <= NF; field++) {
                if ($field !~ /^(0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9])$/ \
                    || $field < 0 || $field > 255) exit 1
                printf "%02x", $field
            }
            accepted = 1
        }
        END { if (!accepted) exit 1 }
    ') || return 1
    invocation_id_is_safe "$hook_invocation" || return 1
    printf '%s\n' "$hook_invocation"
}

unit_u32_property() {
    [ "$#" -eq 3 ] || return 1
    hook_property_object=$(unit_object_path "$1") || return 1
    [ "$2" = org.freedesktop.systemd1.Service ] || return 1
    case $3 in
        MainPID|NFileDescriptorStore) ;;
        *) return 1 ;;
    esac
    hook_property_json=$(/usr/bin/busctl \
        --address="$system_bus_address" \
        --json=short \
        get-property \
        org.freedesktop.systemd1 \
        "$hook_property_object" \
        "$2" "$3" 2>/dev/null) || return 1
    [ "${#hook_property_json}" -le 128 ] || return 1
    hook_property_value=$(printf '%s' "$hook_property_json" | /usr/bin/jq -ers '
        if length == 1
            and (.[0] | keys) == ["data", "type"]
            and .[0].type == "u"
            and (.[0].data | type) == "number"
            and .[0].data >= 0
            and .[0].data <= 4294967295
            and (.[0].data | floor) == .[0].data
        then .[0].data
        else empty
        end
    ') || return 1
    case $hook_property_value in
        0|[1-9]|[1-9][0-9]*) ;;
        *) return 1 ;;
    esac
    [ "${#hook_property_value}" -le 10 ] || return 1
    printf '%s\n' "$hook_property_value"
}

unit_main_pid() {
    [ "$#" -eq 1 ] || return 1
    hook_main_pid=$(unit_u32_property \
        "$1" org.freedesktop.systemd1.Service MainPID) || return 1
    number_is_safe "$hook_main_pid" || return 1
    printf '%s\n' "$hook_main_pid"
}

systemd_exec_record_from_json() {
    [ "$#" -eq 5 ] || return 1
    hook_exec_json=$1
    hook_exec_kind=$2
    hook_exec_pid=$3
    hook_exec_gid=$4
    hook_exec_expected_type=$5
    number_is_safe "$hook_exec_pid" || return 1
    number_is_safe "$hook_exec_gid" || return 1
    case $hook_exec_kind:$hook_exec_expected_type in
        basic:'a(sasbttttuii)'|extended:'a(sasasttttuii)') ;;
        *) return 1 ;;
    esac
    printf '%s' "$hook_exec_json" | /usr/bin/jq -ers \
        --arg expected_kind "$hook_exec_kind" \
        --arg expected_type "$hook_exec_expected_type" \
        --arg expected_path /usr/bin/setpriv \
        --arg expected_regid "--regid=$hook_exec_gid" \
        --arg expected_groups "--groups=$hook_exec_gid" \
        --arg expected_helper "$production_helper" \
        --arg expected_gid "$hook_exec_gid" \
        --argjson expected_pid "$hook_exec_pid" '
        def exact_u53:
            type == "number"
            and . >= 0
            and . <= 9007199254740991
            and floor == .;
        if length == 1
            and (.[0] | keys) == ["data", "type"]
            and .[0].type == $expected_type
            and (.[0].data | type) == "array"
            and (.[0].data | length) == 1
            and (.[0].data[0] | type) == "array"
            and (.[0].data[0] | length) == 10
            and .[0].data[0][0] == $expected_path
            and .[0].data[0][1] == [
                $expected_path,
                $expected_regid,
                $expected_groups,
                "--",
                $expected_helper
            ]
            and (if $expected_kind == "basic"
                then .[0].data[0][2] == false
                else .[0].data[0][2] == []
                end)
            and (.[0].data[0][3] | exact_u53 and . > 0)
            and (.[0].data[0][4] | exact_u53 and . > 0)
            and .[0].data[0][5] == 0
            and .[0].data[0][6] == 0
            and .[0].data[0][7] == $expected_pid
            and .[0].data[0][8] == 0
            and .[0].data[0][9] == 0
        then .[0].data[0] as $entry
            | "systemd-launch-v1=pid:\($entry[7]);gid:\($expected_gid);start-realtime:\($entry[3]);start-monotonic:\($entry[4])"
        else empty
        end
    '
}

capture_systemd_launch_contract() {
    [ "$#" -eq 3 ] || return 1
    hook_launch_unit=$1
    hook_launch_pid=$2
    hook_launch_gid=$3
    unit_name_is_safe "$hook_launch_unit" || return 1
    number_is_safe "$hook_launch_pid" || return 1
    number_is_safe "$hook_launch_gid" || return 1
    hook_launch_object=$(unit_object_path "$hook_launch_unit") || return 1
    hook_exec_start_json=$(/usr/bin/busctl \
        --address="$system_bus_address" \
        --json=short \
        get-property \
        org.freedesktop.systemd1 \
        "$hook_launch_object" \
        org.freedesktop.systemd1.Service \
        ExecStart 2>/dev/null) || return 1
    hook_exec_start_ex_json=$(/usr/bin/busctl \
        --address="$system_bus_address" \
        --json=short \
        get-property \
        org.freedesktop.systemd1 \
        "$hook_launch_object" \
        org.freedesktop.systemd1.Service \
        ExecStartEx 2>/dev/null) || return 1
    [ "${#hook_exec_start_json}" -le 2048 ] || return 1
    [ "${#hook_exec_start_ex_json}" -le 2048 ] || return 1
    hook_exec_start_record=$(systemd_exec_record_from_json \
        "$hook_exec_start_json" basic "$hook_launch_pid" "$hook_launch_gid" \
        'a(sasbttttuii)') || return 1
    hook_exec_start_ex_record=$(systemd_exec_record_from_json \
        "$hook_exec_start_ex_json" extended "$hook_launch_pid" "$hook_launch_gid" \
        'a(sasasttttuii)') || return 1
    [ "$hook_exec_start_record" = "$hook_exec_start_ex_record" ] || return 1
    printf '%s\n' "$hook_exec_start_record"
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

process_starttime_from_stat() {
    [ "$#" -eq 2 ] || return 1
    hook_starttime_line=$1
    hook_starttime_pid=$2
    number_is_safe "$hook_starttime_pid" || return 1
    [ "${#hook_starttime_line}" -le 4096 ] || return 1
    printf '%s\n' "$hook_starttime_line" | /usr/bin/awk \
        -v expected_pid="$hook_starttime_pid" '
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
    hook_starttime_pid=$1
    number_is_safe "$hook_starttime_pid" || return 1
    hook_starttime_path=/proc/$hook_starttime_pid/stat
    [ -f "$hook_starttime_path" ] && [ ! -L "$hook_starttime_path" ] || return 1
    hook_starttime_line=$(cat "$hook_starttime_path") || return 1
    process_starttime_from_stat "$hook_starttime_line" "$hook_starttime_pid"
}

capture_helper_process_contract() {
    [ "$#" -eq 2 ] || return 1
    hook_contract_pid=$1
    hook_contract_gid=$2
    number_is_safe "$hook_contract_pid" || return 1
    number_is_safe "$hook_contract_gid" || return 1
    hook_contract_status=/proc/$hook_contract_pid/status
    [ -f "$hook_contract_status" ] && [ ! -L "$hook_contract_status" ] || return 1
    awk \
        -v expected_pid="$hook_contract_pid" \
        -v expected_gid="$hook_contract_gid" \
        -v expected_caps="$helper_bootstrap_capability_mask" '
        $1 == "Pid:" {
            pid_count++
            if (NF != 2 || $2 != expected_pid) invalid = 1
            next
        }
        $1 == "Uid:" {
            uid_count++
            if (NF != 5 || $2 != 0 || $3 != 0 || $4 != 0 || $5 != 0) invalid = 1
            next
        }
        $1 == "Gid:" {
            gid_count++
            if (NF != 5 || $2 != expected_gid || $3 != expected_gid \
                || $4 != expected_gid || $5 != expected_gid) invalid = 1
            next
        }
        $1 == "Groups:" {
            groups_count++
            if (NF != 2 || $2 != expected_gid) invalid = 1
            next
        }
        $1 == "NoNewPrivs:" {
            nnp_count++
            if (NF != 2 || $2 != 1) invalid = 1
            next
        }
        $1 == "Seccomp:" {
            seccomp_count++
            if (NF != 2 || $2 != 2) invalid = 1
            next
        }
        $1 == "Seccomp_filters:" {
            filter_count++
            filters = $2
            if (NF != 2 || filters !~ /^[1-9][0-9]*$/ \
                || length(filters) > 10 || filters > 1024) invalid = 1
            next
        }
        $1 == "CapInh:" {
            inherited_count++
            if (NF != 2 || $2 != expected_caps) invalid = 1
            next
        }
        $1 == "CapPrm:" {
            permitted_count++
            if (NF != 2 || $2 != expected_caps) invalid = 1
            next
        }
        $1 == "CapEff:" {
            effective_count++
            if (NF != 2 || $2 != expected_caps) invalid = 1
            next
        }
        $1 == "CapBnd:" {
            bounding_count++
            if (NF != 2 || $2 != expected_caps) invalid = 1
            next
        }
        $1 == "CapAmb:" {
            ambient_count++
            if (NF != 2 || $2 != expected_caps) invalid = 1
            next
        }
        END {
            valid = !invalid && pid_count == 1 && uid_count == 1 && gid_count == 1
            valid = valid && groups_count == 1 && nnp_count == 1
            valid = valid && seccomp_count == 1 && filter_count == 1
            valid = valid && inherited_count == 1 && permitted_count == 1
            valid = valid && effective_count == 1 && bounding_count == 1
            valid = valid && ambient_count == 1
            if (!valid) exit 1
            printf "process-status-v1=uid:0:0:0:0;gid:%s:%s:%s:%s;groups:%s;nnp:1;seccomp:2;caps:%s;filters:%s\n", \
                expected_gid, expected_gid, expected_gid, expected_gid, \
                expected_gid, expected_caps, filters
        }
    ' "$hook_contract_status" 2>/dev/null
}

hook_entry_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_entry_gid=$1
    number_is_safe "$hook_entry_gid" || return 1
    hook_entry_status=$(capture_helper_process_contract "$$" "$hook_entry_gid") \
        || return 1
    [ -n "$hook_entry_status" ]
}

process_contract_filter_count() {
    [ "$#" -eq 2 ] || return 1
    hook_filter_contract=$1
    hook_filter_gid=$2
    number_is_safe "$hook_filter_gid" || return 1
    hook_filter_prefix="process-status-v1=uid:0:0:0:0;gid:$hook_filter_gid:$hook_filter_gid:$hook_filter_gid:$hook_filter_gid;groups:$hook_filter_gid;nnp:1;seccomp:2;caps:$helper_bootstrap_capability_mask;filters:"
    case $hook_filter_contract in
        "$hook_filter_prefix"*)
            hook_filter_count=${hook_filter_contract#"$hook_filter_prefix"}
            ;;
        *) return 1 ;;
    esac
    case $hook_filter_count in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#hook_filter_count}" -le 4 ] \
        && [ "$hook_filter_count" -le 1024 ] || return 1
    printf '%s\n' "$hook_filter_count"
}

capture_running_identity() {
    [ "$#" -eq 3 ] || return 1
    case $3 in
        initial)
            hook_initial_identity=yes
            hook_expected_launch_image=
            ;;
        launch-image-v1=*)
            hook_initial_identity=no
            hook_expected_launch_image=$3
            ;;
        *) return 1 ;;
    esac
    hook_identity_unit=$1
    hook_identity_gid=$2
    number_is_safe "$hook_identity_gid" || return 1
    if [ "$hook_initial_identity" = yes ]; then
        advance_start_failure_stage identity-manager || return 1
    fi
    hook_identity_invocation=$(unit_invocation_id "$hook_identity_unit") || return 1
    hook_identity_pid=$(unit_main_pid "$hook_identity_unit") || return 1
    if [ "$hook_initial_identity" = yes ]; then
        advance_start_failure_stage identity-launch || return 1
    fi
    hook_launch_contract=$(capture_systemd_launch_contract \
        "$hook_identity_unit" "$hook_identity_pid" "$hook_identity_gid") || return 1
    if [ "$hook_initial_identity" = yes ]; then
        advance_start_failure_stage identity-birth || return 1
    fi
    if [ "$hook_initial_identity" = yes ]; then
        hook_launch_image=$(capture_launch_image_identity "$production_helper") \
            || return 1
    else
        launch_image_matches_identity \
            "$production_helper" "$hook_expected_launch_image" || return 1
        hook_launch_image=$hook_expected_launch_image
    fi
    hook_process_starttime=$(capture_process_starttime "$hook_identity_pid") || return 1
    hook_process_birth=process-starttime-v1=$hook_process_starttime
    if [ "$hook_initial_identity" = yes ]; then
        advance_start_failure_stage identity-process || return 1
    fi
    hook_process_contract=$(capture_helper_process_contract \
        "$hook_identity_pid" "$hook_identity_gid") || return 1
    if [ "$hook_initial_identity" = yes ]; then
        advance_start_failure_stage identity-stability || return 1
    fi
    [ "$(capture_process_starttime "$hook_identity_pid")" = \
        "$hook_process_starttime" ] || return 1
    launch_image_matches_identity "$production_helper" "$hook_launch_image" || return 1
    [ "$(unit_main_pid "$hook_identity_unit")" = "$hook_identity_pid" ] || return 1
    [ "$(unit_invocation_id "$hook_identity_unit")" = "$hook_identity_invocation" ] \
        || return 1
    hook_captured_running_identity=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$hook_identity_invocation" \
        "$hook_identity_pid" \
        "$hook_launch_contract" \
        "$hook_launch_image" \
        "$hook_process_birth" \
        "$hook_process_contract") || return 1
    if [ "$hook_initial_identity" = yes ]; then
        return 0
    fi
    printf '%s\n' "$hook_captured_running_identity"
}

running_identity_is_unchanged() {
    [ "$#" -eq 3 ] || return 1
    hook_identity_unit=$1
    hook_identity_file=$2
    hook_identity_gid=$3
    number_is_safe "$hook_identity_gid" || return 1
    private_file_is_safe "$hook_identity_file" || return 1
    hook_expected_identity=$(cat "$hook_identity_file") || return 1
    hook_expected_launch_image=$(sed -n '4p' "$hook_identity_file") || return 1
    hook_observed_identity=$(capture_running_identity \
        "$hook_identity_unit" "$hook_identity_gid" \
        "$hook_expected_launch_image") || return 1
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
    running_identity_is_unchanged \
        "$hook_probe_unit" "$hook_probe_identity" "$hook_expected_agent_gid" || return 1
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
    running_identity_is_unchanged \
        "$hook_probe_unit" "$hook_probe_identity" "$hook_expected_agent_gid" || return 1
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
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || return 1
    hook_expected_ifindex=$1
    hook_underlay_staged=${2:-no}
    number_is_safe "$hook_expected_ifindex" || return 1
    case $hook_underlay_staged in
        no) ;;
        yes)
            advance_start_failure_stage functional-underlay-readback-link \
                || return 1
            ;;
        *) return 1 ;;
    esac
    hook_underlay_link_json=$(
        /usr/sbin/ip -details -json link show dev "$functional_underlay" 2>/dev/null
    ) || return 1
    /usr/bin/jq -en \
        --argjson observed "$hook_underlay_link_json" \
        --arg name "$functional_underlay" \
        --arg alias "$functional_underlay_alias" \
        --argjson ifindex "$hook_expected_ifindex" '
          $observed
          | type == "array" and length == 1
          and .[0].ifname == $name
          and .[0].ifindex == $ifindex
          and .[0].ifalias == $alias
          and .[0].linkinfo.info_kind == "dummy"
          and (.[0].flags | index("UP")) != null
        ' >/dev/null 2>&1 \
        || return 1
    if [ "$hook_underlay_staged" = yes ]; then
        advance_start_failure_stage functional-underlay-readback-address \
            || return 1
    fi
    hook_underlay_address_json=$(
        /usr/sbin/ip -4 -json address show dev "$functional_underlay" 2>/dev/null
    ) || return 1
    /usr/bin/jq -en \
        --argjson observed "$hook_underlay_address_json" \
        --arg address "$functional_underlay_address" '
          $observed
          | type == "array" and length == 1
          and ([.[0].addr_info[]
                | select(.family == "inet"
                    and .local == $address
                    and .prefixlen == 24
                    and .scope == "global")] | length) == 1
        ' >/dev/null 2>&1 \
        || return 1
    if [ "$hook_underlay_staged" = yes ]; then
        advance_start_failure_stage functional-underlay-readback-route \
            || return 1
    fi
    # Filtering by `dev` makes recent iproute2 omit that already-filtered field
    # from JSON. Query the main-table default set so the device remains part of
    # the independently checked kernel readback.
    hook_underlay_route_json=$(
        /usr/sbin/ip -4 -json route show table main default 2>/dev/null
    ) || return 1
    /usr/bin/jq -en \
        --argjson observed "$hook_underlay_route_json" \
        --arg dev "$functional_underlay" \
        --arg gateway "$functional_underlay_gateway" \
        --arg source "$functional_underlay_address" '
          $observed
          | type == "array" and length == 1
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
    hook_children_raw=$(
        for hook_children_file in /proc/"$hook_parent_pid"/task/*/children; do
            [ -f "$hook_children_file" ] || exit 1
            cat "$hook_children_file" || exit 1
            printf '\n'
        done
    ) || return 1
    hook_children_lines=$(tr ' ' '\n' <<EOF
$hook_children_raw
EOF
    ) || return 1
    hook_children_nonempty=$(sed '/^$/d' <<EOF
$hook_children_lines
EOF
    ) || return 1
    hook_children=$(sort -u <<EOF
$hook_children_nonempty
EOF
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

worker_status_from_process_fd_is_exact() {
    [ "$#" -eq 6 ] || return 1
    hook_worker_process_fd=$1
    hook_worker_pid=$2
    hook_parent_pid=$3
    hook_worker_uid=$4
    hook_worker_gid=$5
    hook_worker_parent_filters=$6
    fd_number_is_safe "$hook_worker_process_fd" || return 1
    for hook_number in \
        "$hook_worker_pid" "$hook_parent_pid" "$hook_worker_uid" \
        "$hook_worker_gid" "$hook_worker_parent_filters"; do
        number_is_safe "$hook_number" || return 1
    done
    [ "$hook_worker_parent_filters" -le 1024 ] || return 1
    hook_worker_expected_filters=$((hook_worker_parent_filters + 1))
    hook_worker_status=/proc/self/fd/$hook_worker_process_fd/status
    [ -f "$hook_worker_status" ] && [ ! -L "$hook_worker_status" ] || return 1
    /usr/bin/awk \
        -v expected_pid="$hook_worker_pid" \
        -v expected_parent="$hook_parent_pid" \
        -v expected_uid="$hook_worker_uid" \
        -v expected_gid="$hook_worker_gid" \
        -v expected_filters="$hook_worker_expected_filters" '
        $1 == "State:" {
            state_count++
            if (NF < 2 || $2 !~ /^(R|S|D)$/) invalid = 1
            next
        }
        $1 == "Pid:" {
            pid_count++
            if (NF != 2 || $2 != expected_pid) invalid = 1
            next
        }
        $1 == "PPid:" {
            parent_count++
            if (NF != 2 || $2 != expected_parent) invalid = 1
            next
        }
        $1 == "NSpid:" {
            namespace_pid_count++
            if (NF != 2 || $2 != expected_pid) invalid = 1
            next
        }
        $1 == "Uid:" {
            uid_count++
            if (NF != 5 || $2 != expected_uid || $3 != expected_uid \
                || $4 != expected_uid || $5 != expected_uid) invalid = 1
            next
        }
        $1 == "Gid:" {
            gid_count++
            if (NF != 5 || $2 != expected_gid || $3 != expected_gid \
                || $4 != expected_gid || $5 != expected_gid) invalid = 1
            next
        }
        $1 == "Groups:" {
            groups_count++
            if (NF != 1) invalid = 1
            next
        }
        $1 == "Threads:" {
            thread_count++
            if (NF != 2 || $2 != 1) invalid = 1
            next
        }
        $1 == "NoNewPrivs:" {
            nnp_count++
            if (NF != 2 || $2 != 1) invalid = 1
            next
        }
        $1 == "Seccomp:" {
            seccomp_count++
            if (NF != 2 || $2 != 2) invalid = 1
            next
        }
        $1 == "Seccomp_filters:" {
            filter_count++
            if (NF != 2 || $2 != expected_filters) invalid = 1
            next
        }
        $1 == "CapInh:" {
            inherited_count++
            if (NF != 2 || $2 != "0000000000000000") invalid = 1
            next
        }
        $1 == "CapPrm:" {
            permitted_count++
            if (NF != 2 || $2 != "0000000000001000") invalid = 1
            next
        }
        $1 == "CapEff:" {
            effective_count++
            if (NF != 2 || $2 != "0000000000001000") invalid = 1
            next
        }
        $1 == "CapBnd:" {
            bounding_count++
            if (NF != 2 || $2 != "0000000000001000") invalid = 1
            next
        }
        $1 == "CapAmb:" {
            ambient_count++
            if (NF != 2 || $2 != "0000000000000000") invalid = 1
            next
        }
        END {
            if (invalid || state_count != 1 || pid_count != 1 \
                || parent_count != 1 || namespace_pid_count != 1 \
                || uid_count != 1 || gid_count != 1 || groups_count != 1 \
                || thread_count != 1 || nnp_count != 1 || seccomp_count != 1 \
                || filter_count != 1 || inherited_count != 1 \
                || permitted_count != 1 || effective_count != 1 \
                || bounding_count != 1 || ambient_count != 1) exit 1
        }
    ' "$hook_worker_status"
}

capture_process_starttime_from_fd() {
    [ "$#" -eq 2 ] || return 1
    hook_worker_process_fd=$1
    hook_worker_pid=$2
    fd_number_is_safe "$hook_worker_process_fd" || return 1
    number_is_safe "$hook_worker_pid" || return 1
    hook_worker_stat=/proc/self/fd/$hook_worker_process_fd/stat
    [ -f "$hook_worker_stat" ] && [ ! -L "$hook_worker_stat" ] || return 1
    hook_worker_stat_line=$(cat "$hook_worker_stat") || return 1
    process_starttime_from_stat "$hook_worker_stat_line" "$hook_worker_pid"
}

worker_identity_from_process_fd() {
    # The exact parent executable and argv are anchored independently through
    # PID 1. Inside that launched helper, worker construction owns a pidfd and
    # pinned process/netns descriptors across its credential-authenticated
    # parent/child handshake. This external observation joins the one direct
    # child to that held functional exchange through a duplicated parent-owned
    # process-directory FD. It does not inspect the non-dumpable worker through
    # ptrace-gated /proc/<pid> magic links.
    [ "$#" -eq 6 ] || return 1
    hook_worker_process_fd=$1
    hook_worker_pid=$2
    hook_parent_pid=$3
    hook_worker_uid=$4
    hook_worker_gid=$5
    hook_worker_parent_filters=$6
    hook_worker_starttime=$(capture_process_starttime_from_fd \
        "$hook_worker_process_fd" "$hook_worker_pid") || return 1
    worker_status_from_process_fd_is_exact \
        "$hook_worker_process_fd" "$hook_worker_pid" "$hook_parent_pid" \
        "$hook_worker_uid" "$hook_worker_gid" \
        "$hook_worker_parent_filters" || return 1
    [ "$(capture_process_starttime_from_fd \
        "$hook_worker_process_fd" "$hook_worker_pid")" = \
        "$hook_worker_starttime" ] || return 1
    worker_status_from_process_fd_is_exact \
        "$hook_worker_process_fd" "$hook_worker_pid" "$hook_parent_pid" \
        "$hook_worker_uid" "$hook_worker_gid" \
        "$hook_worker_parent_filters" || return 1
    printf '%s\n' "$hook_worker_starttime"
}

pidfd_record_from_fdinfo() {
    [ "$#" -eq 3 ] || return 1
    hook_pidfd_info=$1
    hook_pidfd_number=$2
    hook_pidfd_worker=$3
    fd_number_is_safe "$hook_pidfd_number" || return 1
    number_is_safe "$hook_pidfd_worker" || return 1
    [ "${#hook_pidfd_info}" -le 4096 ] || return 1
    printf '%s\n' "$hook_pidfd_info" | /usr/bin/awk \
        -v expected_pid="$hook_pidfd_worker" \
        -v expected_fd="$hook_pidfd_number" '
        $1 == "Pid:" {
            pid_count++
            if (NF != 2 || $2 != expected_pid) invalid = 1
            next
        }
        $1 == "NSpid:" {
            namespace_pid_count++
            if (NF != 2 || $2 != expected_pid) invalid = 1
            next
        }
        END {
            if (invalid || pid_count != 1 || namespace_pid_count != 1) exit 1
            printf "pidfd-v1=fd:%s;pid:%s\n", expected_fd, expected_pid
        }
    '
}

capture_parent_pidfd_record() {
    [ "$#" -eq 3 ] || return 1
    hook_custody_parent_pid=$1
    hook_custody_fd=$2
    hook_custody_worker_pid=$3
    number_is_safe "$hook_custody_parent_pid" || return 1
    fd_number_is_safe "$hook_custody_fd" || return 1
    number_is_safe "$hook_custody_worker_pid" || return 1
    hook_custody_fd_path=/proc/$hook_custody_parent_pid/fd/$hook_custody_fd
    [ "$(readlink "$hook_custody_fd_path" 2>/dev/null)" = \
        'anon_inode:[pidfd]' ] || return 1
    hook_custody_fdinfo=/proc/$hook_custody_parent_pid/fdinfo/$hook_custody_fd
    [ -f "$hook_custody_fdinfo" ] && [ ! -L "$hook_custody_fdinfo" ] || return 1
    hook_custody_fdinfo_value=$(cat "$hook_custody_fdinfo") || return 1
    pidfd_record_from_fdinfo \
        "$hook_custody_fdinfo_value" "$hook_custody_fd" \
        "$hook_custody_worker_pid" >/dev/null || return 1
    hook_custody_identity=$(stat -Lc '%d:%i' \
        "$hook_custody_fd_path" 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_custody_identity" || return 1
    printf '%s\n' "$hook_custody_identity"
}

namespace_number_from_target() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        net:\[[1-9][0-9]*\]) ;;
        *) return 1 ;;
    esac
    hook_namespace_number=${1#net:[}
    hook_namespace_number=${hook_namespace_number%]}
    kernel_object_number_is_safe "$hook_namespace_number" || return 1
    printf '%s\n' "$hook_namespace_number"
}

capture_parent_namespace_fd_identity() {
    [ "$#" -eq 2 ] || return 1
    hook_custody_parent_pid=$1
    hook_custody_fd=$2
    number_is_safe "$hook_custody_parent_pid" || return 1
    fd_number_is_safe "$hook_custody_fd" || return 1
    hook_custody_fd_path=/proc/$hook_custody_parent_pid/fd/$hook_custody_fd
    hook_custody_target=$(readlink "$hook_custody_fd_path" 2>/dev/null) || return 1
    hook_custody_namespace_number=$(namespace_number_from_target \
        "$hook_custody_target") || return 1
    hook_custody_identity=$(stat -Lc '%d:%i' \
        "$hook_custody_fd_path" 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_custody_identity" || return 1
    [ "${hook_custody_identity#*:}" = "$hook_custody_namespace_number" ] || return 1
    printf '%s\n' "$hook_custody_identity"
}

capture_parent_process_fd_identity() {
    [ "$#" -eq 3 ] || return 1
    hook_custody_parent_pid=$1
    hook_custody_fd=$2
    hook_custody_worker_pid=$3
    number_is_safe "$hook_custody_parent_pid" || return 1
    fd_number_is_safe "$hook_custody_fd" || return 1
    number_is_safe "$hook_custody_worker_pid" || return 1
    hook_custody_fd_path=/proc/$hook_custody_parent_pid/fd/$hook_custody_fd
    [ "$(readlink "$hook_custody_fd_path" 2>/dev/null)" = \
        "/proc/$hook_custody_worker_pid" ] || return 1
    hook_custody_identity=$(stat -Lc '%d:%i' \
        "$hook_custody_fd_path" 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_custody_identity" || return 1
    printf '%s\n' "$hook_custody_identity"
}

capture_parent_worker_custody() {
    [ "$#" -eq 2 ] || return 1
    hook_custody_parent_pid=$1
    hook_custody_worker_pid=$2
    number_is_safe "$hook_custody_parent_pid" || return 1
    number_is_safe "$hook_custody_worker_pid" || return 1
    hook_custody_parent_namespace=$(stat -Lc '%d:%i' \
        /proc/self/ns/net 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_custody_parent_namespace" || return 1
    hook_custody_fd_unsorted=$(
        hook_custody_count=0
        for hook_custody_path in /proc/"$hook_custody_parent_pid"/fd/*; do
            [ -L "$hook_custody_path" ] || exit 1
            hook_custody_fd=${hook_custody_path##*/}
            fd_number_is_safe "$hook_custody_fd" || exit 1
            hook_custody_count=$((hook_custody_count + 1))
            [ "$hook_custody_count" -le 512 ] || exit 1
            printf '%s\n' "$hook_custody_fd"
        done
    ) || return 1
    hook_custody_fd_numbers=$(sort -n <<EOF
$hook_custody_fd_unsorted
EOF
    ) || return 1
    [ -n "$hook_custody_fd_numbers" ] || return 1
    hook_custody_pidfd_count=0
    hook_custody_process_count=0
    hook_custody_namespace_count=0
    hook_custody_pidfd_identity=
    hook_custody_process_fd=
    hook_custody_process_identity=
    hook_custody_namespace_fd=
    hook_custody_namespace_identity=
    while IFS= read -r hook_custody_fd; do
        hook_custody_fd_path=/proc/$hook_custody_parent_pid/fd/$hook_custody_fd
        hook_custody_target=$(readlink "$hook_custody_fd_path" 2>/dev/null) \
            || return 1
        case $hook_custody_target in
            'anon_inode:[pidfd]')
                hook_custody_observed_identity=$(capture_parent_pidfd_record \
                    "$hook_custody_parent_pid" "$hook_custody_fd" \
                    "$hook_custody_worker_pid") || return 1
                if [ -z "$hook_custody_pidfd_identity" ]; then
                    hook_custody_pidfd_identity=$hook_custody_observed_identity
                else
                    [ "$hook_custody_observed_identity" = \
                        "$hook_custody_pidfd_identity" ] || return 1
                fi
                hook_custody_pidfd_count=$((hook_custody_pidfd_count + 1))
                ;;
            /proc/[1-9][0-9]*)
                [ "$hook_custody_target" = "/proc/$hook_custody_worker_pid" ] \
                    || return 1
                hook_custody_observed_identity=$(capture_parent_process_fd_identity \
                    "$hook_custody_parent_pid" "$hook_custody_fd" \
                    "$hook_custody_worker_pid") || return 1
                if [ -z "$hook_custody_process_identity" ]; then
                    hook_custody_process_fd=$hook_custody_fd
                    hook_custody_process_identity=$hook_custody_observed_identity
                else
                    [ "$hook_custody_observed_identity" = \
                        "$hook_custody_process_identity" ] || return 1
                fi
                hook_custody_process_count=$((hook_custody_process_count + 1))
                ;;
            net:\[[1-9][0-9]*\])
                hook_custody_observed_identity=$(capture_parent_namespace_fd_identity \
                    "$hook_custody_parent_pid" "$hook_custody_fd") || return 1
                if [ "$hook_custody_observed_identity" != \
                    "$hook_custody_parent_namespace" ]; then
                    if [ -z "$hook_custody_namespace_identity" ]; then
                        hook_custody_namespace_fd=$hook_custody_fd
                        hook_custody_namespace_identity=$hook_custody_observed_identity
                    else
                        [ "$hook_custody_observed_identity" = \
                            "$hook_custody_namespace_identity" ] || return 1
                    fi
                    hook_custody_namespace_count=$((hook_custody_namespace_count + 1))
                fi
                ;;
        esac
    done <<EOF
$hook_custody_fd_numbers
EOF
    [ "$hook_custody_pidfd_count" -ge 1 ] \
        && [ "$hook_custody_process_count" -ge 1 ] \
        && [ "$hook_custody_namespace_count" -ge 1 ]
}

worker_wireguard_interface() {
    [ "$#" -eq 1 ] || return 1
    hook_namespace_fd=$1
    fd_number_is_safe "$hook_namespace_fd" || return 1
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
    fd_number_is_safe "$hook_namespace_fd" || return 1
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
    [ "$#" -le 1 ] || return 1
    hook_pristine_staged=${1:-no}
    case $hook_pristine_staged in
        no) ;;
        yes)
            advance_start_failure_stage functional-underlay-pristine-namespace \
                || return 1
            ;;
        *) return 1 ;;
    esac
    private_file_is_safe "$host_network_identity_record" || return 1
    hook_host_namespace=$(cat "$host_network_identity_record") || return 1
    kernel_object_identity_is_safe "$hook_host_namespace" || return 1
    hook_private_namespace=$(stat -Lc '%d:%i' /proc/self/ns/net 2>/dev/null) \
        || return 1
    kernel_object_identity_is_safe "$hook_private_namespace" || return 1
    [ "$hook_private_namespace" != "$hook_host_namespace" ] || return 1
    private_file_is_safe "$host_network_identity_record" || return 1
    [ "$(cat "$host_network_identity_record")" = "$hook_host_namespace" ] \
        || return 1
    if [ "$hook_pristine_staged" = yes ]; then
        advance_start_failure_stage functional-underlay-pristine-link \
            || return 1
    fi
    hook_private_links=$(
        /usr/sbin/ip -details -json link show 2>/dev/null
    ) || return 1
    /usr/bin/jq -en --argjson observed "$hook_private_links" '
          $observed
          | type == "array" and length == 1
          and .[0].ifname == "lo"
          and all(.[].linkinfo.info_kind?; . != "wireguard")
          and all(.[].ifalias?;
                (type != "string")
                or (startswith("volparossa:wireguard:ownership-v1:") | not))
        ' >/dev/null 2>&1 \
        || return 1
    if [ "$hook_pristine_staged" = yes ]; then
        advance_start_failure_stage functional-underlay-pristine-ipv-four \
            || return 1
    fi
    hook_private_ipv4_defaults=$(/usr/sbin/ip -json route show default 2>/dev/null) \
        || return 1
    [ "$hook_private_ipv4_defaults" = '[]' ] || return 1
    if [ "$hook_pristine_staged" = yes ]; then
        advance_start_failure_stage functional-underlay-pristine-ipv-six \
            || return 1
    fi
    hook_private_ipv6_defaults=$(/usr/sbin/ip -6 -json route show default 2>/dev/null) \
        || return 1
    [ "$hook_private_ipv6_defaults" = '[]' ]
}

unit_fdstore_is_empty() {
    [ "$#" -eq 1 ] || return 1
    hook_fdstore_unit=$1
    unit_name_is_safe "$hook_fdstore_unit" || return 1
    hook_fdstore_count=$(unit_u32_property \
        "$hook_fdstore_unit" \
        org.freedesktop.systemd1.Service \
        NFileDescriptorStore) || return 1
    [ "$hook_fdstore_count" = 0 ]
}

helper_holds_no_worker_custody() {
    [ "$#" -eq 1 ] || return 1
    hook_custody_parent_pid=$1
    number_is_safe "$hook_custody_parent_pid" || return 1
    hook_custody_parent_namespace=$(stat -Lc '%d:%i' \
        /proc/self/ns/net 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_custody_parent_namespace" || return 1
    hook_custody_count=0
    for hook_custody_path in /proc/"$hook_custody_parent_pid"/fd/*; do
        [ -L "$hook_custody_path" ] || return 1
        hook_custody_fd=${hook_custody_path##*/}
        fd_number_is_safe "$hook_custody_fd" || return 1
        hook_custody_count=$((hook_custody_count + 1))
        [ "$hook_custody_count" -le 512 ] || return 1
        hook_custody_target=$(readlink "$hook_custody_path" 2>/dev/null) || return 1
        case $hook_custody_target in
            'anon_inode:[pidfd]'|/proc/[1-9][0-9]*) return 1 ;;
            net:\[[1-9][0-9]*\])
                hook_custody_observed_identity=$(capture_parent_namespace_fd_identity \
                    "$hook_custody_parent_pid" "$hook_custody_fd") || return 1
                [ "$hook_custody_observed_identity" = \
                    "$hook_custody_parent_namespace" ] || return 1
                ;;
        esac
    done
    [ "$hook_custody_count" -ge 1 ]
}

worker_process_fd_is_retired() {
    [ "$#" -eq 1 ] || return 1
    hook_worker_process_fd=$1
    fd_number_is_safe "$hook_worker_process_fd" || return 1
    if cat "/proc/self/fd/$hook_worker_process_fd/stat" \
        >/dev/null 2>&1; then
        return 1
    fi
    if cat "/proc/self/fd/$hook_worker_process_fd/status" \
        >/dev/null 2>&1; then
        return 1
    fi
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
    [ "$#" -eq 7 ] || return 1
    hook_functional_unit=$1
    hook_functional_main_pid=$2
    hook_functional_agent_uid=$3
    hook_functional_agent_gid=$4
    hook_functional_operator_gid=$5
    hook_functional_worker_uid=$6
    hook_functional_worker_gid=$7
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
    advance_start_failure_stage functional-underlay-parent-contract || return 1
    hook_functional_parent_contract=$(sed -n '6p' \
        "$proof_directory/unit.identity") || return 1
    hook_functional_parent_filters=$(process_contract_filter_count \
        "$hook_functional_parent_contract" "$hook_functional_agent_gid") || return 1
    private_network_is_pristine yes || return 1
    advance_start_failure_stage functional-underlay-absent || return 1
    [ ! -e "/sys/class/net/$functional_underlay" ] \
        && [ ! -L "/sys/class/net/$functional_underlay" ] || return 1

    advance_start_failure_stage functional-underlay-link || return 1
    /usr/sbin/ip link add name "$functional_underlay" type dummy || return 1
    /usr/sbin/ip link set dev "$functional_underlay" alias \
        "$functional_underlay_alias" || return 1
    /usr/sbin/ip link set dev "$functional_underlay" up || return 1
    advance_start_failure_stage functional-underlay-address || return 1
    /usr/sbin/ip address add "$functional_underlay_address/24" \
        broadcast 0.0.0.0 dev "$functional_underlay" || return 1
    advance_start_failure_stage functional-underlay-route || return 1
    /usr/sbin/ip route add default via "$functional_underlay_gateway" \
        dev "$functional_underlay" src "$functional_underlay_address" || return 1
    advance_start_failure_stage functional-underlay-ifindex || return 1
    hook_functional_ifindex=$(cat "/sys/class/net/$functional_underlay/ifindex") \
        || return 1
    functional_underlay_is_exact "$hook_functional_ifindex" yes || return 1

    advance_start_failure_stage functional-probe-ready || return 1

    advance_start_failure_stage functional-probe-fixture || return 1
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
    # The hook intentionally has the agent GID and no CAP_CHOWN. The setgid,
    # root-owned proof directory supplies group root at creation time; umask
    # 077 supplies mode 0600 without a privileged ownership rewrite.
    printf '%s' '' >"$hook_functional_stdout" || return 1
    printf '%s' '' >"$hook_functional_stderr" || return 1
    private_file_is_safe "$hook_functional_stdout" || return 1
    private_file_is_safe "$hook_functional_stderr" || return 1
    command exec 6<>"$hook_functional_fifo" || return 1
    advance_start_failure_stage functional-probe-launch || return 1
    (
        command exec 6>&- || exit 1
        command exec /usr/bin/setpriv \
            --reuid="$hook_functional_agent_uid" \
            --regid="$hook_functional_agent_gid" \
            --groups="$hook_functional_operator_gid" \
            --inh-caps=-all \
            --ambient-caps=-all \
            --bounding-set=-all \
            --no-new-privs \
            "$probe" functional-client-lease \
                "$hook_functional_main_pid" "$hook_functional_agent_gid" \
            <"$hook_functional_fifo" || exit 1
    ) >"$hook_functional_stdout" 2>"$hook_functional_stderr" &
    hook_functional_probe_pid=$!
    number_is_safe "$hook_functional_probe_pid" || return 1

    advance_start_failure_stage functional-probe-wait || return 1
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
    advance_start_failure_stage functional-probe-identity || return 1
    running_identity_is_unchanged \
        "$hook_functional_unit" \
        "$proof_directory/unit.identity" \
        "$hook_functional_agent_gid" || return 1
    advance_start_failure_stage functional-probe-socket || return 1
    socket_identity_is_unchanged \
        "$proof_directory/socket.identity" "$hook_functional_agent_gid" || return 1
    advance_start_failure_stage functional-probe-fdstore || return 1
    unit_fdstore_is_empty "$hook_functional_unit" || return 1

    advance_start_failure_stage functional-worker-observation || return 1

    hook_functional_worker_pid=$(direct_helper_child "$hook_functional_main_pid") \
        || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_worker_pid" || return 1
    hook_functional_pidfd_count=$hook_custody_pidfd_count
    hook_functional_pidfd_identity=$hook_custody_pidfd_identity
    hook_functional_process_count=$hook_custody_process_count
    hook_functional_namespace_count=$hook_custody_namespace_count
    hook_functional_parent_namespace=$hook_custody_parent_namespace
    hook_functional_process_parent_fd=$hook_custody_process_fd
    hook_functional_process_identity=$hook_custody_process_identity
    hook_functional_namespace_parent_fd=$hook_custody_namespace_fd
    hook_functional_worker_namespace=$hook_custody_namespace_identity
    [ "$hook_functional_parent_namespace" != "$hook_functional_worker_namespace" ] \
        || return 1
    hook_functional_parent_process_path=/proc/$hook_functional_main_pid/fd/$hook_functional_process_parent_fd
    hook_functional_parent_namespace_path=/proc/$hook_functional_main_pid/fd/$hook_functional_namespace_parent_fd
    [ "$(capture_parent_process_fd_identity \
        "$hook_functional_main_pid" "$hook_functional_process_parent_fd" \
        "$hook_functional_worker_pid")" = "$hook_functional_process_identity" ] \
        || return 1
    [ "$(capture_parent_namespace_fd_identity \
        "$hook_functional_main_pid" "$hook_functional_namespace_parent_fd")" = \
        "$hook_functional_worker_namespace" ] || return 1
    command exec 7<"$hook_functional_parent_namespace_path" || return 1
    command exec 8<"$hook_functional_parent_process_path" || return 1
    hook_functional_pinned_namespace=$(stat -Lc '%d:%i' \
        /proc/self/fd/7 2>/dev/null) || return 1
    [ "$hook_functional_pinned_namespace" = "$hook_functional_worker_namespace" ] \
        || return 1
    hook_functional_pinned_process=$(stat -Lc '%d:%i' \
        /proc/self/fd/8 2>/dev/null) || return 1
    [ "$hook_functional_pinned_process" = "$hook_functional_process_identity" ] \
        || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_worker_pid" || return 1
    [ "$hook_custody_pidfd_count" = "$hook_functional_pidfd_count" ] \
        && [ "$hook_custody_pidfd_identity" = \
            "$hook_functional_pidfd_identity" ] \
        && [ "$hook_custody_process_count" = "$hook_functional_process_count" ] \
        && [ "$hook_custody_namespace_count" = "$hook_functional_namespace_count" ] \
        && [ "$hook_custody_process_fd" = "$hook_functional_process_parent_fd" ] \
        && [ "$hook_custody_process_identity" = "$hook_functional_process_identity" ] \
        && [ "$hook_custody_namespace_fd" = "$hook_functional_namespace_parent_fd" ] \
        && [ "$hook_custody_namespace_identity" = \
            "$hook_functional_worker_namespace" ] || return 1
    hook_functional_worker_starttime=$(worker_identity_from_process_fd \
        8 "$hook_functional_worker_pid" "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" "$hook_functional_worker_gid" \
        "$hook_functional_parent_filters") || return 1
    running_identity_is_unchanged \
        "$hook_functional_unit" \
        "$proof_directory/unit.identity" \
        "$hook_functional_agent_gid" || return 1
    hook_functional_wireguard=$(worker_wireguard_interface 7) || return 1
    case $hook_functional_wireguard in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "$(worker_identity_from_process_fd \
        8 "$hook_functional_worker_pid" "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" "$hook_functional_worker_gid" \
        "$hook_functional_parent_filters")" = \
        "$hook_functional_worker_starttime" ] || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_worker_pid" || return 1
    [ "$hook_custody_pidfd_count" = "$hook_functional_pidfd_count" ] \
        && [ "$hook_custody_pidfd_identity" = \
            "$hook_functional_pidfd_identity" ] \
        && [ "$hook_custody_process_count" = "$hook_functional_process_count" ] \
        && [ "$hook_custody_namespace_count" = "$hook_functional_namespace_count" ] \
        && [ "$hook_custody_process_fd" = "$hook_functional_process_parent_fd" ] \
        && [ "$hook_custody_process_identity" = "$hook_functional_process_identity" ] \
        && [ "$hook_custody_namespace_fd" = "$hook_functional_namespace_parent_fd" ] \
        && [ "$hook_custody_namespace_identity" = \
            "$hook_functional_worker_namespace" ] || return 1
    running_identity_is_unchanged \
        "$hook_functional_unit" \
        "$proof_directory/unit.identity" \
        "$hook_functional_agent_gid" || return 1

    advance_start_failure_stage functional-probe-finish || return 1

    rm -f -- "$hook_functional_fifo" || return 1
    [ ! -e "$hook_functional_fifo" ] && [ ! -L "$hook_functional_fifo" ] || return 1
    printf '%s' "$functional_release_byte" >&6 || return 1
    command exec 6>&- || return 1
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

    advance_start_failure_stage functional-cleanup || return 1

    running_identity_is_unchanged \
        "$hook_functional_unit" \
        "$proof_directory/unit.identity" \
        "$hook_functional_agent_gid" || return 1
    socket_identity_is_unchanged \
        "$proof_directory/socket.identity" "$hook_functional_agent_gid" || return 1
    unit_fdstore_is_empty "$hook_functional_unit" || return 1
    hook_functional_wait_attempt=0
    while ! helper_has_no_children "$hook_functional_main_pid"; do
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    worker_process_fd_is_retired 8 || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" = \
        "$hook_functional_process_identity" ] || return 1
    helper_holds_no_worker_custody "$hook_functional_main_pid" || return 1
    worker_wireguard_is_absent 7 || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/7 2>/dev/null)" = \
        "$hook_functional_worker_namespace" ] || return 1
    command exec 8>&- || return 1
    [ ! -e /proc/self/fd/8 ] && [ ! -L /proc/self/fd/8 ] || return 1
    command exec 7>&- || return 1
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
    hook_entry_contract_is_exact "$agent_gid" \
        || fail 'start hook process contract is invalid'
    [ "$(stat -c '%F:%u:%g:%a' "$proof_directory" 2>/dev/null || true)" = \
        'directory:0:0:2700' ] || fail 'proof directory is unsafe'
    [ "$(stat -c '%F:%u:%g:%a:%h' "$probe" 2>/dev/null || true)" = \
        "regular file:0:$agent_gid:550:1" ] || fail 'probe executable is unsafe'
    if [ -e "$start_failure_record" ] || [ -L "$start_failure_record" ] \
        || [ -e "$start_failure_record.next" ] \
        || [ -L "$start_failure_record.next" ]; then
        fail 'start failure record path is unsafe'
    fi

    hook_wait_attempt=0
    while [ ! -S "$helper_socket" ]; do
        hook_wait_attempt=$((hook_wait_attempt + 1))
        [ "$hook_wait_attempt" -lt 600 ] || fail 'production helper socket did not appear'
        sleep 0.05
    done
    validate_runtime_metadata "$agent_gid" || fail 'production runtime metadata is invalid'

    advance_start_failure_stage identity-socket \
        || fail 'start failure stage transition is invalid'
    hook_socket_identity=$(capture_socket_identity "$agent_gid") \
        || fail 'production helper socket identity is unavailable'
    write_private_file "$proof_directory/socket.identity" "$hook_socket_identity" \
        || fail 'production helper socket identity could not be published'
    advance_start_failure_stage identity-lock \
        || fail 'start failure stage transition is invalid'
    hook_lock_identity=$(capture_lock_identity "$agent_gid") \
        || fail 'ownership journal lock identity is unavailable'

    capture_running_identity "$hook_unit" "$agent_gid" initial \
        || fail 'production helper identity is unavailable'
    hook_identity=$hook_captured_running_identity
    advance_start_failure_stage identity-publication \
        || fail 'start failure stage transition is invalid'
    write_private_file "$proof_directory/unit.identity" "$hook_identity" \
        || fail 'production helper identity proof could not be published'

    advance_start_failure_stage active-lock \
        || fail 'start failure stage transition is invalid'
    if ! command exec 8<>"$journal_lock"; then
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
    running_identity_is_unchanged "$hook_unit" \
        "$proof_directory/unit.identity" "$agent_gid" \
        || fail 'production helper identity changed during active lock proof'
    hook_active_lock_path_after=$(capture_lock_identity "$agent_gid") \
        || fail 'active ownership journal lock path changed during contention proof'
    [ "$hook_active_lock_path_after" = "$hook_lock_identity" ] \
        || fail 'active ownership journal lock path was replaced during contention proof'
    command exec 8>&- || fail 'active ownership journal lock FD could not be closed'
    hook_active_lock_path_after_close=$(capture_lock_identity "$agent_gid") \
        || fail 'active ownership journal lock path changed after contention proof'
    [ "$hook_active_lock_path_after_close" = "$hook_lock_identity" ] \
        || fail 'active ownership journal lock path was replaced after contention proof'
    running_identity_is_unchanged "$hook_unit" \
        "$proof_directory/unit.identity" "$agent_gid" \
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

    advance_start_failure_stage protocol-bind-before \
        || fail 'start failure stage transition is invalid'
    run_probe bind-before bind-runtime "$agent_uid" "$agent_gid" "$operator_gid" \
        "$bind_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'initial authenticated runtime bind failed'
    advance_start_failure_stage protocol-frame-bounds \
        || fail 'start failure stage transition is invalid'
    run_probe frame-bounds reject-frame-bounds "$agent_uid" "$agent_gid" "$operator_gid" \
        "$frame_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'frame-bound rejection failed'
    advance_start_failure_stage protocol-wire-shapes \
        || fail 'start failure stage transition is invalid'
    run_probe wire-shapes reject-wire-shapes "$agent_uid" "$agent_gid" "$operator_gid" \
        "$wire_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'wire-shape rejection failed'
    advance_start_failure_stage protocol-wrong-uid \
        || fail 'start failure stage transition is invalid'
    run_probe wrong-uid expect-unauthorised-peer "$worker_uid" "$agent_gid" clear \
        "$unauthorised_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'wrong-UID rejection failed'
    advance_start_failure_stage protocol-wrong-gid \
        || fail 'start failure stage transition is invalid'
    run_probe wrong-gid expect-unauthorised-peer "$agent_uid" "$operator_gid" "$agent_gid" \
        "$unauthorised_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'wrong-GID rejection failed'
    advance_start_failure_stage protocol-root-peer \
        || fail 'start failure stage transition is invalid'
    run_probe root-peer expect-unauthorised-peer 0 "$agent_gid" clear \
        "$unauthorised_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'root-peer rejection failed'
    advance_start_failure_stage protocol-bind-after \
        || fail 'start failure stage transition is invalid'
    run_probe bind-after bind-runtime "$agent_uid" "$agent_gid" "$operator_gid" \
        "$bind_pass" "$hook_unit" "$identity_file" "$socket_identity_file" \
        "$hook_expected_main_pid" "$agent_gid" \
        || fail 'final authenticated runtime bind failed'

    advance_start_failure_stage functional-underlay \
        || fail 'start failure stage transition is invalid'
    run_functional_client_lease_probe \
        "$hook_unit" \
        "$hook_expected_main_pid" \
        "$agent_uid" \
        "$agent_gid" \
        "$operator_gid" \
        "$worker_uid" \
        "$worker_gid" \
        || fail 'functional client lease live proof failed'

    advance_start_failure_stage publication \
        || fail 'start failure stage transition is invalid'
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
    hook_entry_contract_is_exact "$hook_expected_agent_gid" \
        || fail 'stop hook process contract is invalid'
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
    if ! command exec 9<>"$journal_lock"; then
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
    command exec 9>&- || fail 'ownership journal lock FD could not be closed'
    hook_fdstore_count=$(unit_u32_property \
        "$hook_unit" \
        org.freedesktop.systemd1.Service \
        NFileDescriptorStore) || fail 'descriptor-store count is unavailable'
    [ "$hook_fdstore_count" = 0 ] || fail 'descriptor store is not empty at stop'
    write_private_file "$proof_directory/stop.pass" \
        'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass' \
        || fail 'production IPC stop proof could not be published'
}

case ${1:-} in
    start)
        shift
        start_failure_stage=preflight-runtime
        start_failure_armed=yes
        trap start_failure_exit EXIT
        start_hook "$@"
        start_failure_armed=no
        trap - EXIT
        ;;
    stop)
        shift
        stop_hook "$@"
        ;;
    *) fail 'hook mode is invalid' ;;
esac
