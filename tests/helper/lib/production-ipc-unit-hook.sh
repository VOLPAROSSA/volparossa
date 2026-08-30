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
functional_relay=vprl0
functional_relay_alias=volparossa-proof-relay-v1
functional_relay_listen_port=10000
functional_relay_public_key=MdSras7slhE3kXA3k25gcW+sVzr+lNnahKgCBEjfwRI=
functional_exit_relay=vpre0
functional_exit_relay_alias=volparossa-proof-relay-exit-v1
functional_exit_relay_listen_port=10001
functional_exit_relay_public_key=c7LYt2qptTZgAyvI9di+46OuTjs6f9Sa3oH3NHo0qmg=
functional_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready
functional_exit_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=ready
functional_relay_pair_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=ready
functional_activated_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_ACTIVATED_KERNEL_V1=pass
functional_committed_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_COMMITTED_KERNEL_V1=pass
functional_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass
functional_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_EXTERNAL_CLEANUP_V1=pass
functional_exit_activated_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_ACTIVATED_KERNEL_V1=pass
functional_exit_committed_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_COMMITTED_KERNEL_V1=pass
functional_exit_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=pass
functional_exit_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_EXTERNAL_CLEANUP_V1=pass
functional_relay_pair_activated_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_ACTIVATED_KERNEL_V1=pass
functional_relay_pair_committed_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_COMMITTED_KERNEL_V1=pass
functional_relay_pair_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=pass
functional_relay_pair_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_EXTERNAL_CLEANUP_V1=pass
functional_failure_prefix=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=
functional_failure_record=$proof_directory/functional-client-lease.failure
functional_peer_public_key=$functional_relay_public_key
functional_peer_endpoint=$functional_underlay_address:$functional_relay_listen_port
functional_exit_peer_public_key=$functional_exit_relay_public_key
functional_exit_peer_endpoint=$functional_underlay_address:$functional_exit_relay_listen_port
functional_peer_keepalive=25
functional_release_byte=G
helper_bootstrap_capability_mask=00000000002031e0
start_failure_record=$proof_directory/start.failure
start_failure_stage=
start_failure_armed=no
start_failure_published=no
functional_relay_state=absent
functional_relay_ifindex=
functional_relay_client_address=
functional_exit_relay_state=absent
functional_exit_relay_ifindex=
functional_exit_relay_exit_address=
functional_fixture_shape=single
functional_pair_client_keeper_state=absent
functional_pair_client_keeper_pid=
functional_pair_client_keeper_starttime=
functional_pair_client_namespace_identity=
functional_pair_client_link_state=absent
functional_pair_client_ifindex=
functional_pair_client_public_key=
functional_pair_client_listen_port=
functional_pair_client_worker_address=
functional_pair_client_peer_address=
functional_pair_exit_keeper_state=absent
functional_pair_exit_keeper_pid=
functional_pair_exit_keeper_starttime=
functional_pair_exit_namespace_identity=
functional_pair_exit_link_state=absent
functional_pair_exit_ifindex=
functional_pair_exit_public_key=
functional_pair_exit_listen_port=
functional_pair_exit_worker_address=
functional_pair_exit_peer_address=

fail() {
    printf 'production IPC unit hook failed: %s\n' "$1" >&2
    exit 1
}

emit_functional_relay_private_key() {
    # Produce the public, deterministic test fixture [8; 32] only in this private pipe. The
    # Base64 private key never appears in source, argv, an environment variable, a file or output.
    /usr/bin/awk 'BEGIN { for (position = 1; position <= 32; position++) printf "%c", 8 }' \
        | /usr/bin/base64 -w 0 || return 1
    printf '\n'
}

emit_functional_exit_relay_private_key() {
    # Produce the second public, deterministic test fixture [11; 32] only in this private pipe.
    # Its Base64 private key never appears in source, argv, an environment variable, a file or output.
    /usr/bin/awk 'BEGIN { for (position = 1; position <= 32; position++) printf "%c", 11 }' \
        | /usr/bin/base64 -w 0 || return 1
    printf '\n'
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
        functional-worker-observation:functional-relay-fixture|\
        functional-relay-fixture:functional-relay-traffic|\
        functional-relay-traffic:functional-relay-cleanup|\
        functional-relay-cleanup:functional-client-release|\
        functional-client-release:functional-client-cleanup|\
        functional-client-cleanup:functional-exit-ready|\
        functional-exit-ready:functional-exit-worker-observation|\
        functional-exit-worker-observation:functional-exit-relay-fixture|\
        functional-exit-relay-fixture:functional-exit-relay-traffic|\
        functional-exit-relay-traffic:functional-exit-relay-cleanup|\
        functional-exit-relay-cleanup:functional-exit-release|\
        functional-exit-release:functional-exit-cleanup|\
        functional-exit-cleanup:functional-relay-pair-ready|\
        functional-relay-pair-ready:functional-relay-pair-worker-observation|\
        functional-relay-pair-worker-observation:functional-relay-pair-fixtures|\
        functional-relay-pair-fixtures:functional-relay-pair-traffic|\
        functional-relay-pair-traffic:functional-relay-pair-cleanup|\
        functional-relay-pair-cleanup:functional-probe-finish|\
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
    case $functional_fixture_shape in
        pair)
            if ! remove_functional_relay_pair_fixtures; then
                start_failure_status=1
            fi
            ;;
        single)
            if [ "$functional_exit_relay_state" != absent ]; then
                if ! remove_functional_exit_relay_fixture; then
                    start_failure_status=1
                fi
            fi
            if [ "$functional_relay_state" != absent ]; then
                if ! remove_functional_relay_fixture; then
                    start_failure_status=1
                fi
            fi
            ;;
        *) start_failure_status=1 ;;
    esac
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
    [ "$hook_public_key" != "$functional_peer_public_key" ] \
        && [ "$hook_public_key" != "$functional_exit_peer_public_key" ] || return 1
    hook_listen_port=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interfaces" listen-port 2>/dev/null) || return 1
    case $hook_listen_port in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    [ "$hook_listen_port" -le 65535 ] || return 1
    hook_firewall_mark=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interfaces" fwmark 2>/dev/null) || return 1
    [ "$hook_firewall_mark" = off ] || return 1
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

worker_relay_pair_interfaces() {
    [ "$#" -eq 1 ] || return 1
    hook_namespace_fd=$1
    fd_number_is_safe "$hook_namespace_fd" || return 1
    hook_pair_interfaces=$(/usr/bin/nsenter \
        --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show interfaces 2>/dev/null) || return 1
    case $hook_pair_interfaces in
        ''|*[!A-Za-z0-9_.\ -]*) return 1 ;;
    esac
    # The allowlist above excludes glob metacharacters; splitting the one kernel
    # `wg show interfaces` record is intentional and must yield exactly two names.
    # shellcheck disable=SC2086
    set -- $hook_pair_interfaces
    [ "$#" -eq 2 ] || return 1
    hook_relay_client_interface=
    hook_relay_exit_interface=
    for hook_pair_interface in "$@"; do
        [ "${#hook_pair_interface}" -le 15 ] || return 1
        case $hook_pair_interface in
            vpr1????????)
                [ -z "$hook_relay_client_interface" ] || return 1
                hook_relay_client_interface=$hook_pair_interface
                hook_pair_tail=${hook_pair_interface#vpr}
                ;;
            vps1????????)
                [ -z "$hook_relay_exit_interface" ] || return 1
                hook_relay_exit_interface=$hook_pair_interface
                hook_pair_tail=${hook_pair_interface#vps}
                ;;
            *) return 1 ;;
        esac
        case $hook_pair_tail in
            1????????) ;;
            *) return 1 ;;
        esac
        case $hook_pair_tail in
            *[!0-9a-f]*) return 1 ;;
        esac
    done
    [ -n "$hook_relay_client_interface" ] \
        && [ -n "$hook_relay_exit_interface" ] || return 1
    [ "${hook_relay_client_interface#vpr}" = \
        "${hook_relay_exit_interface#vps}" ] || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/sbin/ip -details -json link show 2>/dev/null \
        | /usr/bin/jq -e \
            --arg relay_client "$hook_relay_client_interface" \
            --arg relay_exit "$hook_relay_exit_interface" '
              type == "array" and length == 3
              and any(.[]; .ifname == "lo")
              and any(.[];
                    .ifname == $relay_client
                    and .linkinfo.info_kind == "wireguard"
                    and (.flags | index("UP")) != null
                    and (.["ifalias"] | type) == "string"
                    and (.["ifalias"]
                        | test("^volparossa:wireguard:ownership-v1:"
                            + $relay_client + ":[0-9a-f]{64}$")))
              and any(.[];
                    .ifname == $relay_exit
                    and .linkinfo.info_kind == "wireguard"
                    and (.flags | index("UP")) != null
                    and (.["ifalias"] | type) == "string"
                    and (.["ifalias"]
                        | test("^volparossa:wireguard:ownership-v1:"
                            + $relay_exit + ":[0-9a-f]{64}$")))
              and all(.[];
                    .ifname == "lo"
                    or .ifname == $relay_client
                    or .ifname == $relay_exit)
            ' >/dev/null 2>&1 || return 1
    hook_relay_client_public_key=
    hook_relay_exit_public_key=
    hook_relay_client_listen_port=
    hook_relay_exit_listen_port=
    for hook_pair_interface in \
        "$hook_relay_client_interface" "$hook_relay_exit_interface"; do
        /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/sbin/ip -6 -json address show dev "$hook_pair_interface" 2>/dev/null \
            | /usr/bin/jq -e '
                  type == "array" and length == 1
                  and ([.[0].addr_info[]
                        | select(.family == "inet6"
                            and .prefixlen == 128
                            and .scope == "global")] | length) == 1
                ' >/dev/null 2>&1 || return 1
        hook_pair_public_key=$(/usr/bin/nsenter \
            --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/bin/wg show "$hook_pair_interface" public-key 2>/dev/null) \
            || return 1
        case $hook_pair_public_key in
            ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
        esac
        [ "${#hook_pair_public_key}" -eq 44 ] \
            && [ "$hook_pair_public_key" != "$functional_peer_public_key" ] \
            && [ "$hook_pair_public_key" != \
                "$functional_exit_peer_public_key" ] || return 1
        hook_pair_listen_port=$(/usr/bin/nsenter \
            --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/bin/wg show "$hook_pair_interface" listen-port 2>/dev/null) \
            || return 1
        number_is_safe "$hook_pair_listen_port" \
            && [ "$hook_pair_listen_port" -le 65535 ] \
            && [ "$hook_pair_listen_port" -ne \
                "$functional_relay_listen_port" ] \
            && [ "$hook_pair_listen_port" -ne \
                "$functional_exit_relay_listen_port" ] || return 1
        hook_pair_firewall_mark=$(/usr/bin/nsenter \
            --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/bin/wg show "$hook_pair_interface" fwmark 2>/dev/null) \
            || return 1
        [ "$hook_pair_firewall_mark" = off ] || return 1
        if [ "$hook_pair_interface" = "$hook_relay_client_interface" ]; then
            hook_relay_client_public_key=$hook_pair_public_key
            hook_relay_client_listen_port=$hook_pair_listen_port
        else
            hook_relay_exit_public_key=$hook_pair_public_key
            hook_relay_exit_listen_port=$hook_pair_listen_port
        fi
    done
    [ "$hook_relay_client_public_key" != "$hook_relay_exit_public_key" ] \
        && [ "$hook_relay_client_listen_port" != \
            "$hook_relay_exit_listen_port" ] || return 1
    printf '%s\t%s\n' \
        "$hook_relay_client_interface" "$hook_relay_exit_interface"
}

derive_relay_pair_address() {
    [ "$#" -eq 3 ] || return 1
    hook_pair_address_interface=$1
    hook_pair_address_expected_host=$2
    hook_pair_address_desired_host=$3
    case $hook_pair_address_interface in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#hook_pair_address_interface}" -le 15 ] || return 1
    case $hook_pair_address_expected_host:$hook_pair_address_desired_host in
        0002:0001|0002:0002|0003:0003|0003:0004) ;;
        *) return 1 ;;
    esac
    /usr/bin/awk \
        -v expected_interface="$hook_pair_address_interface" \
        -v expected_host="$hook_pair_address_expected_host" \
        -v desired_host="$hook_pair_address_desired_host" '
        $6 == expected_interface \
            && length($1) == 32 \
            && $1 ~ /^[0-9a-f]+$/ \
            && substr($1, 1, 12) == "fd766f6c7061" \
            && substr($1, 21, 4) == "0001" \
            && substr($1, 29, 4) == expected_host \
            && $3 == "80" \
            && $4 == "00" {
                candidates++
                address = substr($1, 1, 28) desired_host
            }
        END {
            if (candidates != 1) exit 1
            printf "%s:%s:%s:%s:%s:%s:%s:%s\n", \
                substr(address, 1, 4), substr(address, 5, 4), \
                substr(address, 9, 4), substr(address, 13, 4), \
                substr(address, 17, 4), substr(address, 21, 4), \
                substr(address, 25, 4), substr(address, 29, 4)
        }
    '
}

worker_relay_pair_address() {
    [ "$#" -eq 4 ] || return 1
    hook_namespace_fd=$1
    hook_pair_address_interface=$2
    hook_pair_address_expected_host=$3
    hook_pair_address_desired_host=$4
    fd_number_is_safe "$hook_namespace_fd" || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/cat /proc/net/if_inet6 2>/dev/null \
        | derive_relay_pair_address \
            "$hook_pair_address_interface" \
            "$hook_pair_address_expected_host" \
            "$hook_pair_address_desired_host"
}

derive_client_peer_address() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] || return 1
    /usr/bin/awk -v expected_interface="$1" '
        $6 == expected_interface \
            && length($1) == 32 \
            && $1 ~ /^[0-9a-f]+$/ \
            && substr($1, 1, 12) == "fd766f6c7061" \
            && substr($1, 21, 4) == "0001" \
            && substr($1, 29, 4) == "0001" \
            && $3 == "80" \
            && $4 == "00" {
                candidates++
                peer = substr($1, 1, 28) "0002"
            }
        END {
            if (candidates != 1) exit 1
            printf "%s:%s:%s:%s:%s:%s:%s:%s\n", \
                substr(peer, 1, 4), substr(peer, 5, 4), \
                substr(peer, 9, 4), substr(peer, 13, 4), \
                substr(peer, 17, 4), substr(peer, 21, 4), \
                substr(peer, 25, 4), substr(peer, 29, 4)
        }
    '
}

derive_client_local_address() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] || return 1
    /usr/bin/awk -v expected_interface="$1" '
        $6 == expected_interface \
            && length($1) == 32 \
            && $1 ~ /^[0-9a-f]+$/ \
            && substr($1, 1, 12) == "fd766f6c7061" \
            && substr($1, 21, 4) == "0001" \
            && substr($1, 29, 4) == "0001" \
            && $3 == "80" \
            && $4 == "00" {
                candidates++
                local_address = $1
            }
        END {
            if (candidates != 1) exit 1
            printf "%s:%s:%s:%s:%s:%s:%s:%s\n", \
                substr(local_address, 1, 4), substr(local_address, 5, 4), \
                substr(local_address, 9, 4), substr(local_address, 13, 4), \
                substr(local_address, 17, 4), substr(local_address, 21, 4), \
                substr(local_address, 25, 4), substr(local_address, 29, 4)
        }
    '
}

derive_exit_peer_address() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] || return 1
    /usr/bin/awk -v expected_interface="$1" '
        $6 == expected_interface \
            && length($1) == 32 \
            && $1 ~ /^[0-9a-f]+$/ \
            && substr($1, 1, 12) == "fd766f6c7061" \
            && substr($1, 21, 4) == "0001" \
            && substr($1, 29, 4) == "0004" \
            && $3 == "80" \
            && $4 == "00" {
                candidates++
                peer = substr($1, 1, 28) "0003"
            }
        END {
            if (candidates != 1) exit 1
            printf "%s:%s:%s:%s:%s:%s:%s:%s\n", \
                substr(peer, 1, 4), substr(peer, 5, 4), \
                substr(peer, 9, 4), substr(peer, 13, 4), \
                substr(peer, 17, 4), substr(peer, 21, 4), \
                substr(peer, 25, 4), substr(peer, 29, 4)
        }
    '
}

derive_exit_local_address() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] || return 1
    /usr/bin/awk -v expected_interface="$1" '
        $6 == expected_interface \
            && length($1) == 32 \
            && $1 ~ /^[0-9a-f]+$/ \
            && substr($1, 1, 12) == "fd766f6c7061" \
            && substr($1, 21, 4) == "0001" \
            && substr($1, 29, 4) == "0004" \
            && $3 == "80" \
            && $4 == "00" {
                candidates++
                local_address = $1
            }
        END {
            if (candidates != 1) exit 1
            printf "%s:%s:%s:%s:%s:%s:%s:%s\n", \
                substr(local_address, 1, 4), substr(local_address, 5, 4), \
                substr(local_address, 9, 4), substr(local_address, 13, 4), \
                substr(local_address, 17, 4), substr(local_address, 21, 4), \
                substr(local_address, 25, 4), substr(local_address, 29, 4)
        }
    '
}

wireguard_counter_line_is_exact() {
    [ "$#" -eq 3 ] || return 1
    case $3 in
        2|3) ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$1" | /usr/bin/awk \
        -F '\t' -v expected_key="$2" -v expected_fields="$3" '
        function canonical_u64(value) {
            if (value == "0") return 1
            if (value !~ /^[1-9][0-9]*$/ || length(value) > 20) return 0
            if (length(value) < 20) return 1
            return ("x" value) <= "x18446744073709551615"
        }
        {
            records++
            valid = NF == expected_fields && $1 == expected_key \
                && canonical_u64($2)
            if (expected_fields == 3) valid = valid && canonical_u64($3)
            if (!valid) invalid = 1
        }
        END {
            if (records != 1 || invalid) exit 1
        }
    '
}

wireguard_snapshot_from_lines() {
    [ "$#" -eq 3 ] || return 1
    printf '%s\n%s\n' "$1" "$2" | /usr/bin/awk \
        -F '\t' -v expected_key="$3" '
        function canonical_u64(value) {
            if (value == "0") return 1
            if (value !~ /^[1-9][0-9]*$/ || length(value) > 20) return 0
            if (length(value) < 20) return 1
            return ("x" value) <= "x18446744073709551615"
        }
        NR == 1 {
            valid = NF == 2 && $1 == expected_key && canonical_u64($2)
            handshake = $2
        }
        NR == 2 {
            valid = valid && NF == 3 && $1 == expected_key \
                && canonical_u64($2) && canonical_u64($3)
            received = $2
            transmitted = $3
        }
        NR > 2 { valid = 0 }
        END {
            if (NR != 2 || !valid) exit 1
            printf "%s\t%s\t%s\n", handshake, received, transmitted
        }
    '
}

worker_wireguard_snapshot() {
    [ "$#" -eq 3 ] || return 1
    hook_namespace_fd=$1
    hook_interface=$2
    hook_expected_key=$3
    fd_number_is_safe "$hook_namespace_fd" || return 1
    hook_handshake_line=$(/usr/bin/nsenter \
        --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" latest-handshakes 2>/dev/null) \
        || return 1
    hook_transfer_line=$(/usr/bin/nsenter \
        --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" transfer 2>/dev/null) || return 1
    wireguard_snapshot_from_lines \
        "$hook_handshake_line" "$hook_transfer_line" "$hook_expected_key"
}

relay_wireguard_snapshot() {
    [ "$#" -eq 2 ] || return 1
    hook_interface=$1
    hook_expected_key=$2
    hook_handshake_line=$(/usr/bin/wg show \
        "$hook_interface" latest-handshakes 2>/dev/null) || return 1
    hook_transfer_line=$(/usr/bin/wg show \
        "$hook_interface" transfer 2>/dev/null) || return 1
    wireguard_snapshot_from_lines \
        "$hook_handshake_line" "$hook_transfer_line" "$hook_expected_key"
}

functional_peer_wireguard_snapshot() {
    [ "$#" -eq 5 ] || return 1
    hook_peer_pid=$1
    hook_peer_starttime=$2
    hook_peer_namespace_identity=$3
    hook_peer_interface=$4
    hook_peer_expected_key=$5
    functional_peer_keeper_is_exact \
        "$hook_peer_pid" "$hook_peer_starttime" \
        "$hook_peer_namespace_identity" || return 1
    hook_handshake_line=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" \
            latest-handshakes 2>/dev/null) || return 1
    hook_transfer_line=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" transfer 2>/dev/null) || return 1
    wireguard_snapshot_from_lines \
        "$hook_handshake_line" "$hook_transfer_line" "$hook_peer_expected_key"
}

functional_relay_pair_client_wireguard_snapshot() {
    [ "$#" -eq 1 ] || return 1
    functional_peer_wireguard_snapshot \
        "$functional_pair_client_keeper_pid" \
        "$functional_pair_client_keeper_starttime" \
        "$functional_pair_client_namespace_identity" \
        "$functional_relay" "$1"
}

functional_relay_pair_exit_wireguard_snapshot() {
    [ "$#" -eq 1 ] || return 1
    functional_peer_wireguard_snapshot \
        "$functional_pair_exit_keeper_pid" \
        "$functional_pair_exit_keeper_starttime" \
        "$functional_pair_exit_namespace_identity" \
        "$functional_exit_relay" "$1"
}

wireguard_snapshot_has_growth() {
    [ "$#" -eq 2 ] || return 1
    /usr/bin/awk -v baseline="$1" -v current="$2" '
        function canonical_u64(value) {
            if (value == "0") return 1
            if (value !~ /^[1-9][0-9]*$/ || length(value) > 20) return 0
            if (length(value) < 20) return 1
            return ("x" value) <= "x18446744073709551615"
        }
        function greater(left, right) {
            if (length(left) != length(right)) return length(left) > length(right)
            return ("x" left) > ("x" right)
        }
        BEGIN {
            baseline_count = split(baseline, before, "\t")
            current_count = split(current, after, "\t")
            if (baseline_count != 3 || current_count != 3) exit 1
            for (position = 1; position <= 3; position++) {
                if (!canonical_u64(before[position]) \
                    || !canonical_u64(after[position])) exit 1
            }
            if (after[1] == "0" \
                || !greater(after[2], before[2]) \
                || !greater(after[3], before[3])) exit 1
        }
    '
}

activated_route_destination() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] || return 1
    /usr/bin/jq -e -r --arg interface "$1" '
        select(
            type == "array" and length == 1
            and (.[0] | keys)
                == ["dev", "dst", "flags", "metric", "pref", "protocol"]
            and (.[0].dst | type) == "string"
            and (.[0].dst | contains(":"))
            and .[0].dst != "default"
            and .[0].dev == $interface
            and .[0].protocol == "static"
            and .[0].metric == 1024
            and .[0].flags == []
            and .[0].pref == "medium"
            and (.[0] | has("gateway") | not)
            and (.[0] | has("via") | not)
            and (.[0] | has("nexthops") | not)
            and (.[0] | has("nhid") | not)
            and (.[0] | has("prefsrc") | not)
            and (.[0] | has("src") | not)
        )
        | .[0].dst
    '
}

worker_client_peer_address() {
    [ "$#" -eq 2 ] || return 1
    hook_namespace_fd=$1
    hook_interface=$2
    fd_number_is_safe "$hook_namespace_fd" || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/cat /proc/net/if_inet6 2>/dev/null \
        | derive_client_peer_address "$hook_interface"
}

worker_client_local_address() {
    [ "$#" -eq 2 ] || return 1
    hook_namespace_fd=$1
    hook_interface=$2
    fd_number_is_safe "$hook_namespace_fd" || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/cat /proc/net/if_inet6 2>/dev/null \
        | derive_client_local_address "$hook_interface"
}

worker_exit_peer_address() {
    [ "$#" -eq 2 ] || return 1
    hook_namespace_fd=$1
    hook_interface=$2
    fd_number_is_safe "$hook_namespace_fd" || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/cat /proc/net/if_inet6 2>/dev/null \
        | derive_exit_peer_address "$hook_interface"
}

worker_exit_local_address() {
    [ "$#" -eq 2 ] || return 1
    hook_namespace_fd=$1
    hook_interface=$2
    fd_number_is_safe "$hook_namespace_fd" || return 1
    /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/cat /proc/net/if_inet6 2>/dev/null \
        | derive_exit_local_address "$hook_interface"
}

worker_activated_wireguard_is_exact() {
    [ "$#" -eq 5 ] || return 1
    hook_namespace_fd=$1
    hook_interface=$2
    hook_peer_address=$3
    hook_expected_peer_public_key=$4
    hook_expected_peer_endpoint=$5
    fd_number_is_safe "$hook_namespace_fd" || return 1
    case $hook_interface in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#hook_interface}" -le 15 ] || return 1
    case $hook_peer_address in
        ''|*[!0-9a-f:]*) return 1 ;;
    esac
    [ "${#hook_peer_address}" -eq 39 ] || return 1
    case $hook_expected_peer_public_key in
        ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
    esac
    [ "${#hook_expected_peer_public_key}" -eq 44 ] || return 1
    [ "$hook_expected_peer_endpoint" = "$functional_peer_endpoint" ] \
        || [ "$hook_expected_peer_endpoint" = "$functional_exit_peer_endpoint" ] \
        || return 1

    # The peer address was independently derived from the full binary role address above. Query
    # that exact /128 in table main; never infer route identity from a displayed AllowedIP.
    hook_route_destination=$(
        /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/sbin/ip -6 -json route show table main \
                exact "$hook_peer_address/128" 2>/dev/null \
            | activated_route_destination "$hook_interface" 2>/dev/null
    ) || return 1
    case $hook_route_destination in
        ''|default|*/*|*[!0-9a-f:]*) return 1 ;;
    esac
    hook_default_routes=$(
        /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/sbin/ip -6 -json route show table main default 2>/dev/null
    ) || return 1
    [ "$hook_default_routes" = '[]' ] || return 1

    # Selector-specific `wg show` reads never expose the interface private key. Every public field
    # must remain bound to the one fixed peer while the kernel counters may truthfully be zero.
    hook_peers=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" peers 2>/dev/null) || return 1
    [ "$hook_peers" = "$hook_expected_peer_public_key" ] || return 1
    hook_expected_peer_field=$(printf '%s\t%s' \
        "$hook_expected_peer_public_key" "$hook_expected_peer_endpoint") || return 1
    hook_peer_field=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" endpoints 2>/dev/null) || return 1
    [ "$hook_peer_field" = "$hook_expected_peer_field" ] || return 1
    hook_expected_peer_field=$(printf '%s\t%s/128' \
        "$hook_expected_peer_public_key" "$hook_route_destination") || return 1
    hook_peer_field=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" allowed-ips 2>/dev/null) || return 1
    [ "$hook_peer_field" = "$hook_expected_peer_field" ] || return 1
    hook_expected_peer_field=$(printf '%s\t%s' \
        "$hook_expected_peer_public_key" "$functional_peer_keepalive") || return 1
    hook_peer_field=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" persistent-keepalive 2>/dev/null) || return 1
    [ "$hook_peer_field" = "$hook_expected_peer_field" ] || return 1
    hook_peer_field=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" latest-handshakes 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_peer_field" "$hook_expected_peer_public_key" 2 || return 1
    hook_peer_field=$(/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
        /usr/bin/wg show "$hook_interface" transfer 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_peer_field" "$hook_expected_peer_public_key" 3
}

functional_relay_link_is_absent() {
    [ ! -e "/sys/class/net/$functional_relay" ] \
        && [ ! -L "/sys/class/net/$functional_relay" ]
}

functional_relay_route_is_absent() {
    if [ -z "$functional_relay_client_address" ]; then
        return 0
    fi
    hook_relay_route=$(/usr/sbin/ip -6 -json route show table main \
        exact "$functional_relay_client_address/128" 2>/dev/null) || return 1
    [ "$hook_relay_route" = '[]' ]
}

functional_relay_identity_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_expected_ifindex=$1
    number_is_safe "$hook_expected_ifindex" || return 1
    /usr/sbin/ip -details -json link show dev "$functional_relay" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$functional_relay" \
            --argjson ifindex "$hook_expected_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].linkinfo.info_kind == "wireguard"
            ' >/dev/null 2>&1
}

functional_relay_link_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_expected_ifindex=$1
    number_is_safe "$hook_expected_ifindex" || return 1
    /usr/sbin/ip -details -json link show dev "$functional_relay" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$functional_relay" \
            --arg alias "$functional_relay_alias" \
            --argjson ifindex "$hook_expected_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].ifalias == $alias
              and .[0].linkinfo.info_kind == "wireguard"
            ' >/dev/null 2>&1
}

functional_peer_namespace_shape_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_primary_fixture=$1
    case $functional_fixture_shape:$hook_primary_fixture in
        single:"$functional_relay"|single:"$functional_exit_relay")
            /usr/sbin/ip -details -json link show 2>/dev/null \
                | /usr/bin/jq -e \
                    --arg underlay "$functional_underlay" \
                    --arg primary "$hook_primary_fixture" '
                      type == "array" and length == 3
                      and any(.[]; .ifname == "lo")
                      and any(.[];
                            .ifname == $underlay
                            and .linkinfo.info_kind == "dummy")
                      and any(.[];
                            .ifname == $primary
                            and .linkinfo.info_kind == "wireguard"
                            and (.flags | index("UP")) != null)
                      and all(.[];
                            .ifname == "lo"
                            or .ifname == $underlay
                            or .ifname == $primary)
                    ' >/dev/null 2>&1
            ;;
        pair:"$functional_relay"|pair:"$functional_exit_relay")
            /usr/sbin/ip -details -json link show 2>/dev/null \
                | /usr/bin/jq -e \
                    --arg underlay "$functional_underlay" \
                    --arg relay_client "$functional_relay" \
                    --arg relay_exit "$functional_exit_relay" '
                      type == "array" and length == 4
                      and any(.[]; .ifname == "lo")
                      and any(.[];
                            .ifname == $underlay
                            and .linkinfo.info_kind == "dummy")
                      and any(.[];
                            .ifname == $relay_client
                            and .linkinfo.info_kind == "wireguard"
                            and (.flags | index("UP")) != null)
                      and any(.[];
                            .ifname == $relay_exit
                            and .linkinfo.info_kind == "wireguard"
                            and (.flags | index("UP")) != null)
                      and all(.[];
                            .ifname == "lo"
                            or .ifname == $underlay
                            or .ifname == $relay_client
                            or .ifname == $relay_exit)
                    ' >/dev/null 2>&1
            ;;
        *) return 1 ;;
    esac
}

functional_relay_fixture_is_exact() {
    [ "$#" -eq 5 ] || return 1
    hook_expected_ifindex=$1
    hook_client_public_key=$2
    hook_client_listen_port=$3
    hook_client_local_address=$4
    hook_relay_local_address=$5
    functional_relay_link_is_exact "$hook_expected_ifindex" || return 1
    functional_peer_namespace_shape_is_exact "$functional_relay" || return 1
    hook_relay_public_key=$(/usr/bin/wg show \
        "$functional_relay" public-key 2>/dev/null) || return 1
    [ "$hook_relay_public_key" = "$functional_relay_public_key" ] || return 1
    hook_relay_port=$(/usr/bin/wg show \
        "$functional_relay" listen-port 2>/dev/null) || return 1
    [ "$hook_relay_port" = "$functional_relay_listen_port" ] || return 1
    hook_relay_mark=$(/usr/bin/wg show \
        "$functional_relay" fwmark 2>/dev/null) || return 1
    [ "$hook_relay_mark" = off ] || return 1
    hook_relay_address_hex=$(printf '%s' "$hook_relay_local_address" \
        | /usr/bin/tr -d ':') || return 1
    [ "${#hook_relay_address_hex}" -eq 32 ] || return 1
    /usr/bin/awk \
        -v expected_address="$hook_relay_address_hex" \
        -v expected_interface="$functional_relay" '
        $6 == expected_interface {
            records++
            if ($1 == expected_address && $3 == "80" && $4 == "00") matches++
        }
        END { if (records != 1 || matches != 1) exit 1 }
    ' /proc/net/if_inet6 || return 1
    hook_relay_route_destination=$(
        /usr/sbin/ip -6 -json route show table main \
            exact "$hook_client_local_address/128" 2>/dev/null \
            | activated_route_destination "$functional_relay" 2>/dev/null
    ) || return 1
    hook_relay_default_routes=$(/usr/sbin/ip -6 -json \
        route show table main default 2>/dev/null) || return 1
    [ "$hook_relay_default_routes" = '[]' ] || return 1
    hook_relay_peers=$(/usr/bin/wg show \
        "$functional_relay" peers 2>/dev/null) || return 1
    [ "$hook_relay_peers" = "$hook_client_public_key" ] || return 1
    hook_expected_relay_field=$(printf '%s\t%s:%s' \
        "$hook_client_public_key" "$functional_underlay_address" \
        "$hook_client_listen_port") || return 1
    hook_relay_field=$(/usr/bin/wg show \
        "$functional_relay" endpoints 2>/dev/null) || return 1
    [ "$hook_relay_field" = "$hook_expected_relay_field" ] || return 1
    hook_expected_relay_field=$(printf '%s\t%s/128' \
        "$hook_client_public_key" "$hook_relay_route_destination") || return 1
    hook_relay_field=$(/usr/bin/wg show \
        "$functional_relay" allowed-ips 2>/dev/null) || return 1
    [ "$hook_relay_field" = "$hook_expected_relay_field" ] || return 1
    hook_expected_relay_field=$(printf '%s\t%s' \
        "$hook_client_public_key" "$functional_peer_keepalive") || return 1
    hook_relay_field=$(/usr/bin/wg show \
        "$functional_relay" persistent-keepalive 2>/dev/null) || return 1
    [ "$hook_relay_field" = "$hook_expected_relay_field" ] || return 1
    hook_relay_field=$(/usr/bin/wg show \
        "$functional_relay" latest-handshakes 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_relay_field" "$hook_client_public_key" 2 || return 1
    hook_relay_field=$(/usr/bin/wg show \
        "$functional_relay" transfer 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_relay_field" "$hook_client_public_key" 3
}

add_functional_relay_link() {
    /usr/sbin/ip link add name "$functional_relay" type wireguard
}

capture_functional_relay_ifindex() {
    hook_captured_relay_ifindex=$(/usr/bin/cat \
        "/sys/class/net/$functional_relay/ifindex") || return 1
    number_is_safe "$hook_captured_relay_ifindex"
}

mark_functional_relay_link() {
    /usr/sbin/ip link set dev "$functional_relay" alias \
        "$functional_relay_alias"
}

configure_functional_relay_wireguard() {
    [ "$#" -eq 3 ] || return 1
    hook_client_public_key=$1
    hook_client_listen_port=$2
    hook_client_local_address=$3
    emit_functional_relay_private_key \
        | /usr/bin/wg set "$functional_relay" \
            listen-port "$functional_relay_listen_port" \
            private-key /dev/stdin \
            peer "$hook_client_public_key" \
            allowed-ips "$hook_client_local_address/128" \
            endpoint "$functional_underlay_address:$hook_client_listen_port" \
            persistent-keepalive "$functional_peer_keepalive"
}

add_functional_relay_address() {
    [ "$#" -eq 1 ] || return 1
    hook_relay_local_address=$1
    /usr/sbin/ip -6 address add "$hook_relay_local_address/128" \
        dev "$functional_relay"
}

raise_functional_relay_link() {
    /usr/sbin/ip link set dev "$functional_relay" up
}

add_functional_relay_route() {
    [ "$#" -eq 1 ] || return 1
    hook_client_local_address=$1
    /usr/sbin/ip -6 route add "$hook_client_local_address/128" \
        dev "$functional_relay" proto static metric 1024
}

delete_functional_relay_link() {
    /usr/sbin/ip link delete dev "$functional_relay"
}

forget_functional_relay_fixture() {
    functional_relay_state=absent
    functional_relay_ifindex=
    functional_relay_client_address=
    hook_captured_relay_ifindex=
}

create_functional_relay_fixture() {
    [ "$#" -eq 4 ] || return 1
    hook_client_public_key=$1
    hook_client_listen_port=$2
    hook_client_local_address=$3
    hook_relay_local_address=$4
    case $hook_client_public_key in
        ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
    esac
    [ "${#hook_client_public_key}" -eq 44 ] \
        && [ "$hook_client_public_key" != "$functional_relay_public_key" ] || return 1
    number_is_safe "$hook_client_listen_port" \
        && [ "$hook_client_listen_port" -le 65535 ] || return 1
    for hook_relay_address in \
        "$hook_client_local_address" "$hook_relay_local_address"; do
        case $hook_relay_address in
            ''|*[!0-9a-f:]*) return 1 ;;
        esac
        [ "${#hook_relay_address}" -eq 39 ] || return 1
    done
    functional_relay_link_is_absent || return 1
    functional_relay_client_address=$hook_client_local_address
    functional_relay_ifindex=
    hook_captured_relay_ifindex=
    functional_relay_state=adding
    add_functional_relay_link || return 1
    capture_functional_relay_ifindex || return 1
    functional_relay_ifindex=$hook_captured_relay_ifindex
    functional_relay_state=created
    functional_relay_identity_is_exact "$functional_relay_ifindex" || return 1
    mark_functional_relay_link || return 1
    functional_relay_link_is_exact "$functional_relay_ifindex" || return 1
    functional_relay_state=marked
    configure_functional_relay_wireguard \
        "$hook_client_public_key" \
        "$hook_client_listen_port" \
        "$hook_client_local_address" || return 1
    add_functional_relay_address "$hook_relay_local_address" || return 1
    raise_functional_relay_link || return 1
    add_functional_relay_route "$hook_client_local_address" || return 1
    functional_relay_fixture_is_exact \
        "$functional_relay_ifindex" \
        "$hook_client_public_key" \
        "$hook_client_listen_port" \
        "$hook_client_local_address" \
        "$hook_relay_local_address"
}

remove_functional_relay_fixture() {
    case $functional_relay_state in
        absent) return 0 ;;
        adding)
            functional_relay_link_is_absent || return 1
            functional_relay_state=deleted
            ;;
        created)
            if functional_relay_link_is_absent; then
                functional_relay_state=deleted
            else
                functional_relay_identity_is_exact \
                    "$functional_relay_ifindex" || return 1
                if delete_functional_relay_link \
                    || functional_relay_link_is_absent; then
                    functional_relay_state=deleted
                else
                    return 1
                fi
            fi
            ;;
        marked)
            if functional_relay_link_is_absent; then
                functional_relay_state=deleted
            else
                functional_relay_link_is_exact \
                    "$functional_relay_ifindex" || return 1
                if delete_functional_relay_link \
                    || functional_relay_link_is_absent; then
                    functional_relay_state=deleted
                else
                    return 1
                fi
            fi
            ;;
        deleted) ;;
        *) return 1 ;;
    esac
    functional_relay_link_is_absent || return 1
    functional_relay_route_is_absent || return 1
    forget_functional_relay_fixture
}

functional_exit_relay_link_is_absent() {
    [ ! -e "/sys/class/net/$functional_exit_relay" ] \
        && [ ! -L "/sys/class/net/$functional_exit_relay" ]
}

functional_exit_relay_route_is_absent() {
    if [ -z "$functional_exit_relay_exit_address" ]; then
        return 0
    fi
    hook_exit_relay_route=$(/usr/sbin/ip -6 -json route show table main \
        exact "$functional_exit_relay_exit_address/128" 2>/dev/null) || return 1
    [ "$hook_exit_relay_route" = '[]' ]
}

functional_exit_relay_identity_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_expected_ifindex=$1
    number_is_safe "$hook_expected_ifindex" || return 1
    /usr/sbin/ip -details -json link show dev "$functional_exit_relay" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$functional_exit_relay" \
            --argjson ifindex "$hook_expected_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].linkinfo.info_kind == "wireguard"
            ' >/dev/null 2>&1
}

functional_exit_relay_link_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_expected_ifindex=$1
    number_is_safe "$hook_expected_ifindex" || return 1
    /usr/sbin/ip -details -json link show dev "$functional_exit_relay" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$functional_exit_relay" \
            --arg alias "$functional_exit_relay_alias" \
            --argjson ifindex "$hook_expected_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].ifalias == $alias
              and .[0].linkinfo.info_kind == "wireguard"
            ' >/dev/null 2>&1
}

functional_exit_relay_fixture_is_exact() {
    [ "$#" -eq 5 ] || return 1
    hook_expected_ifindex=$1
    hook_exit_public_key=$2
    hook_exit_listen_port=$3
    hook_exit_local_address=$4
    hook_exit_relay_local_address=$5
    functional_exit_relay_link_is_exact "$hook_expected_ifindex" || return 1
    functional_peer_namespace_shape_is_exact "$functional_exit_relay" || return 1
    hook_exit_relay_public_key=$(/usr/bin/wg show \
        "$functional_exit_relay" public-key 2>/dev/null) || return 1
    [ "$hook_exit_relay_public_key" = "$functional_exit_relay_public_key" ] || return 1
    hook_exit_relay_port=$(/usr/bin/wg show \
        "$functional_exit_relay" listen-port 2>/dev/null) || return 1
    [ "$hook_exit_relay_port" = "$functional_exit_relay_listen_port" ] || return 1
    hook_exit_relay_mark=$(/usr/bin/wg show \
        "$functional_exit_relay" fwmark 2>/dev/null) || return 1
    [ "$hook_exit_relay_mark" = off ] || return 1
    hook_exit_relay_address_hex=$(printf '%s' "$hook_exit_relay_local_address" \
        | /usr/bin/tr -d ':') || return 1
    [ "${#hook_exit_relay_address_hex}" -eq 32 ] || return 1
    /usr/bin/awk \
        -v expected_address="$hook_exit_relay_address_hex" \
        -v expected_interface="$functional_exit_relay" '
        $6 == expected_interface {
            records++
            if ($1 == expected_address && $3 == "80" && $4 == "00") matches++
        }
        END { if (records != 1 || matches != 1) exit 1 }
    ' /proc/net/if_inet6 || return 1
    hook_exit_relay_route_destination=$(
        /usr/sbin/ip -6 -json route show table main \
            exact "$hook_exit_local_address/128" 2>/dev/null \
            | activated_route_destination "$functional_exit_relay" 2>/dev/null
    ) || return 1
    hook_exit_relay_default_routes=$(/usr/sbin/ip -6 -json \
        route show table main default 2>/dev/null) || return 1
    [ "$hook_exit_relay_default_routes" = '[]' ] || return 1
    hook_exit_relay_peers=$(/usr/bin/wg show \
        "$functional_exit_relay" peers 2>/dev/null) || return 1
    [ "$hook_exit_relay_peers" = "$hook_exit_public_key" ] || return 1
    hook_expected_exit_relay_field=$(printf '%s\t%s:%s' \
        "$hook_exit_public_key" "$functional_underlay_address" \
        "$hook_exit_listen_port") || return 1
    hook_exit_relay_field=$(/usr/bin/wg show \
        "$functional_exit_relay" endpoints 2>/dev/null) || return 1
    [ "$hook_exit_relay_field" = "$hook_expected_exit_relay_field" ] || return 1
    hook_expected_exit_relay_field=$(printf '%s\t%s/128' \
        "$hook_exit_public_key" "$hook_exit_relay_route_destination") || return 1
    hook_exit_relay_field=$(/usr/bin/wg show \
        "$functional_exit_relay" allowed-ips 2>/dev/null) || return 1
    [ "$hook_exit_relay_field" = "$hook_expected_exit_relay_field" ] || return 1
    hook_expected_exit_relay_field=$(printf '%s\t%s' \
        "$hook_exit_public_key" "$functional_peer_keepalive") || return 1
    hook_exit_relay_field=$(/usr/bin/wg show \
        "$functional_exit_relay" persistent-keepalive 2>/dev/null) || return 1
    [ "$hook_exit_relay_field" = "$hook_expected_exit_relay_field" ] || return 1
    hook_exit_relay_field=$(/usr/bin/wg show \
        "$functional_exit_relay" latest-handshakes 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_exit_relay_field" "$hook_exit_public_key" 2 || return 1
    hook_exit_relay_field=$(/usr/bin/wg show \
        "$functional_exit_relay" transfer 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_exit_relay_field" "$hook_exit_public_key" 3
}

add_functional_exit_relay_link() {
    /usr/sbin/ip link add name "$functional_exit_relay" type wireguard
}

capture_functional_exit_relay_ifindex() {
    hook_captured_exit_relay_ifindex=$(/usr/bin/cat \
        "/sys/class/net/$functional_exit_relay/ifindex") || return 1
    number_is_safe "$hook_captured_exit_relay_ifindex"
}

mark_functional_exit_relay_link() {
    /usr/sbin/ip link set dev "$functional_exit_relay" alias \
        "$functional_exit_relay_alias"
}

configure_functional_exit_relay_wireguard() {
    [ "$#" -eq 3 ] || return 1
    hook_exit_public_key=$1
    hook_exit_listen_port=$2
    hook_exit_local_address=$3
    emit_functional_exit_relay_private_key \
        | /usr/bin/wg set "$functional_exit_relay" \
            listen-port "$functional_exit_relay_listen_port" \
            private-key /dev/stdin \
            peer "$hook_exit_public_key" \
            allowed-ips "$hook_exit_local_address/128" \
            endpoint "$functional_underlay_address:$hook_exit_listen_port" \
            persistent-keepalive "$functional_peer_keepalive"
}

add_functional_exit_relay_address() {
    [ "$#" -eq 1 ] || return 1
    hook_exit_relay_local_address=$1
    /usr/sbin/ip -6 address add "$hook_exit_relay_local_address/128" \
        dev "$functional_exit_relay"
}

raise_functional_exit_relay_link() {
    /usr/sbin/ip link set dev "$functional_exit_relay" up
}

add_functional_exit_relay_route() {
    [ "$#" -eq 1 ] || return 1
    hook_exit_local_address=$1
    /usr/sbin/ip -6 route add "$hook_exit_local_address/128" \
        dev "$functional_exit_relay" proto static metric 1024
}

delete_functional_exit_relay_link() {
    /usr/sbin/ip link delete dev "$functional_exit_relay"
}

forget_functional_exit_relay_fixture() {
    functional_exit_relay_state=absent
    functional_exit_relay_ifindex=
    functional_exit_relay_exit_address=
    hook_captured_exit_relay_ifindex=
}

create_functional_exit_relay_fixture() {
    [ "$#" -eq 4 ] || return 1
    hook_exit_public_key=$1
    hook_exit_listen_port=$2
    hook_exit_local_address=$3
    hook_exit_relay_local_address=$4
    case $hook_exit_public_key in
        ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
    esac
    [ "${#hook_exit_public_key}" -eq 44 ] \
        && [ "$hook_exit_public_key" != "$functional_exit_relay_public_key" ] || return 1
    number_is_safe "$hook_exit_listen_port" \
        && [ "$hook_exit_listen_port" -le 65535 ] || return 1
    for hook_exit_relay_address in \
        "$hook_exit_local_address" "$hook_exit_relay_local_address"; do
        case $hook_exit_relay_address in
            ''|*[!0-9a-f:]*) return 1 ;;
        esac
        [ "${#hook_exit_relay_address}" -eq 39 ] || return 1
    done
    functional_exit_relay_link_is_absent || return 1
    functional_exit_relay_exit_address=$hook_exit_local_address
    functional_exit_relay_ifindex=
    hook_captured_exit_relay_ifindex=
    functional_exit_relay_state=adding
    add_functional_exit_relay_link || return 1
    capture_functional_exit_relay_ifindex || return 1
    functional_exit_relay_ifindex=$hook_captured_exit_relay_ifindex
    functional_exit_relay_state=created
    functional_exit_relay_identity_is_exact \
        "$functional_exit_relay_ifindex" || return 1
    mark_functional_exit_relay_link || return 1
    functional_exit_relay_link_is_exact \
        "$functional_exit_relay_ifindex" || return 1
    functional_exit_relay_state=marked
    configure_functional_exit_relay_wireguard \
        "$hook_exit_public_key" \
        "$hook_exit_listen_port" \
        "$hook_exit_local_address" || return 1
    add_functional_exit_relay_address "$hook_exit_relay_local_address" || return 1
    raise_functional_exit_relay_link || return 1
    add_functional_exit_relay_route "$hook_exit_local_address" || return 1
    functional_exit_relay_fixture_is_exact \
        "$functional_exit_relay_ifindex" \
        "$hook_exit_public_key" \
        "$hook_exit_listen_port" \
        "$hook_exit_local_address" \
        "$hook_exit_relay_local_address"
}

remove_functional_exit_relay_fixture() {
    case $functional_exit_relay_state in
        absent) return 0 ;;
        adding)
            functional_exit_relay_link_is_absent || return 1
            functional_exit_relay_state=deleted
            ;;
        created)
            if functional_exit_relay_link_is_absent; then
                functional_exit_relay_state=deleted
            else
                functional_exit_relay_identity_is_exact \
                    "$functional_exit_relay_ifindex" || return 1
                if delete_functional_exit_relay_link \
                    || functional_exit_relay_link_is_absent; then
                    functional_exit_relay_state=deleted
                else
                    return 1
                fi
            fi
            ;;
        marked)
            if functional_exit_relay_link_is_absent; then
                functional_exit_relay_state=deleted
            else
                functional_exit_relay_link_is_exact \
                    "$functional_exit_relay_ifindex" || return 1
                if delete_functional_exit_relay_link \
                    || functional_exit_relay_link_is_absent; then
                    functional_exit_relay_state=deleted
                else
                    return 1
                fi
            fi
            ;;
        deleted) ;;
        *) return 1 ;;
    esac
    functional_exit_relay_link_is_absent || return 1
    functional_exit_relay_route_is_absent || return 1
    forget_functional_exit_relay_fixture
}

functional_direct_child_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_peer_pid=$1
    number_is_safe "$hook_peer_pid" || return 1
    [ -f "/proc/$hook_peer_pid/status" ] \
        && [ ! -L "/proc/$hook_peer_pid/status" ] || return 1
    /usr/bin/awk -v expected_pid="$hook_peer_pid" -v expected_parent="$$" '
        $1 == "Pid:" {
            pid_records++
            if (NF != 2 || $2 != expected_pid) invalid = 1
        }
        $1 == "PPid:" {
            parent_records++
            if (NF != 2 || $2 != expected_parent) invalid = 1
        }
        END {
            if (invalid || pid_records != 1 || parent_records != 1) exit 1
        }
    ' "/proc/$hook_peer_pid/status"
}

functional_peer_keeper_is_exact() {
    [ "$#" -eq 3 ] || return 1
    hook_peer_pid=$1
    hook_peer_starttime=$2
    hook_peer_namespace_identity=$3
    number_is_safe "$hook_peer_pid" \
        && kernel_object_number_is_safe "$hook_peer_starttime" \
        && kernel_object_identity_is_safe \
            "$hook_peer_namespace_identity" || return 1
    functional_direct_child_is_exact "$hook_peer_pid" || return 1
    [ "$(capture_process_starttime "$hook_peer_pid")" = \
        "$hook_peer_starttime" ] || return 1
    [ "$(readlink "/proc/$hook_peer_pid/exe" 2>/dev/null)" = \
        /usr/bin/sleep ] || return 1
    hook_observed_namespace=$(stat -Lc '%d:%i' \
        "/proc/$hook_peer_pid/ns/net" 2>/dev/null) || return 1
    [ "$hook_observed_namespace" = "$hook_peer_namespace_identity" ] \
        || return 1
    hook_parent_namespace=$(stat -Lc '%d:%i' \
        /proc/self/ns/net 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_parent_namespace" \
        && [ "$hook_parent_namespace" != \
            "$hook_peer_namespace_identity" ]
}

launch_functional_peer_keeper() {
    hook_peer_keeper_pid=
    hook_peer_keeper_starttime=
    hook_peer_keeper_namespace_identity=
    /usr/bin/unshare --net -- /usr/bin/sleep 3600 \
        </dev/null >/dev/null 2>&1 &
    hook_peer_keeper_pid=$!
    number_is_safe "$hook_peer_keeper_pid" || return 1
    hook_parent_namespace=$(stat -Lc '%d:%i' \
        /proc/self/ns/net 2>/dev/null) || return 1
    kernel_object_identity_is_safe "$hook_parent_namespace" || return 1
    hook_peer_wait_attempt=0
    while :; do
        hook_peer_keeper_starttime=$(capture_process_starttime \
            "$hook_peer_keeper_pid" 2>/dev/null) || hook_peer_keeper_starttime=
        hook_peer_keeper_namespace_identity=$(stat -Lc '%d:%i' \
            "/proc/$hook_peer_keeper_pid/ns/net" 2>/dev/null) \
            || hook_peer_keeper_namespace_identity=
        hook_peer_executable=$(readlink \
            "/proc/$hook_peer_keeper_pid/exe" 2>/dev/null) \
            || hook_peer_executable=
        if kernel_object_number_is_safe "$hook_peer_keeper_starttime" \
            && kernel_object_identity_is_safe \
                "$hook_peer_keeper_namespace_identity" \
            && [ "$hook_peer_keeper_namespace_identity" != \
                "$hook_parent_namespace" ] \
            && [ "$hook_peer_executable" = /usr/bin/sleep ] \
            && functional_direct_child_is_exact \
                "$hook_peer_keeper_pid"; then
            return 0
        fi
        kill -0 "$hook_peer_keeper_pid" 2>/dev/null || return 1
        hook_peer_wait_attempt=$((hook_peer_wait_attempt + 1))
        [ "$hook_peer_wait_attempt" -lt 200 ] || return 1
        sleep 0.01
    done
}

retire_functional_peer_keeper() {
    [ "$#" -eq 4 ] || return 1
    hook_peer_state=$1
    hook_peer_pid=$2
    hook_peer_starttime=$3
    hook_peer_namespace_identity=$4
    hook_peer_requires_term_status=no
    case $hook_peer_state in
        absent) return 0 ;;
        launching)
            number_is_safe "$hook_peer_pid" || return 1
            functional_direct_child_is_exact "$hook_peer_pid" \
                || return 1
            ;;
        ready)
            functional_peer_keeper_is_exact \
                "$hook_peer_pid" "$hook_peer_starttime" \
                "$hook_peer_namespace_identity" || return 1
            hook_peer_requires_term_status=yes
            ;;
        *) return 1 ;;
    esac
    kill -TERM "$hook_peer_pid" 2>/dev/null || return 1
    if wait "$hook_peer_pid"; then
        hook_peer_wait_status=0
    else
        hook_peer_wait_status=$?
    fi
    if [ "$hook_peer_requires_term_status" = yes ]; then
        [ "$hook_peer_wait_status" -eq 143 ] || return 1
    else
        [ "$hook_peer_wait_status" -ne 127 ] || return 1
    fi
    [ ! -e "/proc/$hook_peer_pid" ] \
        && [ ! -L "/proc/$hook_peer_pid" ]
}

functional_pair_parent_wireguard_is_exact() {
    [ "$#" -eq 9 ] || return 1
    hook_peer_interface=$1
    hook_peer_alias=$2
    hook_peer_ifindex=$3
    hook_peer_public_key=$4
    hook_peer_listen_port=$5
    hook_worker_public_key=$6
    hook_worker_listen_port=$7
    hook_worker_address=$8
    hook_cross_address=$9
    /usr/sbin/ip -details -json link show dev \
        "$hook_peer_interface" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$hook_peer_interface" \
            --arg alias "$hook_peer_alias" \
            --argjson ifindex "$hook_peer_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].ifalias == $alias
              and .[0].linkinfo.info_kind == "wireguard"
            ' >/dev/null 2>&1 || return 1
    [ "$(/usr/bin/wg show "$hook_peer_interface" \
        public-key 2>/dev/null)" = "$hook_peer_public_key" ] || return 1
    [ "$(/usr/bin/wg show "$hook_peer_interface" \
        listen-port 2>/dev/null)" = "$hook_peer_listen_port" ] || return 1
    [ "$(/usr/bin/wg show "$hook_peer_interface" \
        fwmark 2>/dev/null)" = off ] || return 1
    [ "$(/usr/bin/wg show "$hook_peer_interface" \
        peers 2>/dev/null)" = "$hook_worker_public_key" ] || return 1
    hook_expected_peer_field=$(printf '%s\t%s:%s' \
        "$hook_worker_public_key" "$functional_underlay_address" \
        "$hook_worker_listen_port") || return 1
    [ "$(/usr/bin/wg show "$hook_peer_interface" \
        endpoints 2>/dev/null)" = "$hook_expected_peer_field" ] || return 1
    hook_allowed_ips=$(/usr/bin/wg show "$hook_peer_interface" \
        allowed-ips 2>/dev/null) || return 1
    printf '%s\n' "$hook_allowed_ips" | /usr/bin/awk -F '\t' \
        -v expected_key="$hook_worker_public_key" \
        -v first="$hook_worker_address/128" \
        -v second="$hook_cross_address/128" '
          NR == 1 && NF == 2 && $1 == expected_key {
              count = split($2, address, " ")
              if (count == 2 \
                  && ((address[1] == first && address[2] == second) \
                      || (address[1] == second && address[2] == first))) valid = 1
          }
          END { if (NR != 1 || !valid) exit 1 }
        ' || return 1
    hook_expected_peer_field=$(printf '%s\t%s' \
        "$hook_worker_public_key" "$functional_peer_keepalive") || return 1
    [ "$(/usr/bin/wg show "$hook_peer_interface" \
        persistent-keepalive 2>/dev/null)" = \
        "$hook_expected_peer_field" ]
}

configure_functional_relay_pair_wireguard() {
    [ "$#" -eq 4 ] || return 1
    emit_functional_relay_private_key \
        | /usr/bin/wg set "$functional_relay" \
            listen-port "$functional_relay_listen_port" \
            private-key /dev/stdin \
            peer "$1" \
            allowed-ips "$3/128,$4/128" \
            endpoint "$functional_underlay_address:$2" \
            persistent-keepalive "$functional_peer_keepalive"
}

configure_functional_exit_relay_pair_wireguard() {
    [ "$#" -eq 4 ] || return 1
    emit_functional_exit_relay_private_key \
        | /usr/bin/wg set "$functional_exit_relay" \
            listen-port "$functional_exit_relay_listen_port" \
            private-key /dev/stdin \
            peer "$1" \
            allowed-ips "$3/128,$4/128" \
            endpoint "$functional_underlay_address:$2" \
            persistent-keepalive "$functional_peer_keepalive"
}

configure_functional_pair_peer_namespace() {
    [ "$#" -eq 7 ] || return 1
    hook_peer_pid=$1
    hook_peer_starttime=$2
    hook_peer_namespace_identity=$3
    hook_peer_interface=$4
    hook_peer_local_address=$5
    hook_worker_address=$6
    hook_cross_address=$7
    functional_peer_keeper_is_exact \
        "$hook_peer_pid" "$hook_peer_starttime" \
        "$hook_peer_namespace_identity" || return 1
    # shellcheck disable=SC2016
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip link set dev lo up || return 1
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip -6 address add "$hook_peer_local_address/128" \
            dev "$hook_peer_interface" nodad || return 1
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip link set dev "$hook_peer_interface" up || return 1
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip -6 route add "$hook_worker_address/128" \
            dev "$hook_peer_interface" proto static metric 1024 || return 1
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip -6 route add "$hook_cross_address/128" \
            dev "$hook_peer_interface" proto static metric 1024
}

functional_pair_peer_fixture_is_exact() {
    [ "$#" -eq 13 ] || return 1
    hook_peer_pid=$1
    hook_peer_starttime=$2
    hook_peer_namespace_identity=$3
    hook_peer_interface=$4
    hook_peer_alias=$5
    hook_peer_ifindex=$6
    hook_peer_public_key=$7
    hook_peer_listen_port=$8
    hook_worker_public_key=$9
    shift 9
    hook_worker_listen_port=$1
    hook_peer_local_address=$2
    hook_worker_address=$3
    hook_cross_address=$4
    functional_peer_keeper_is_exact \
        "$hook_peer_pid" "$hook_peer_starttime" \
        "$hook_peer_namespace_identity" || return 1
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip -details -json link show 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$hook_peer_interface" \
            --arg alias "$hook_peer_alias" \
            --argjson ifindex "$hook_peer_ifindex" '
              type == "array" and length == 2
              and any(.[];
                    .ifname == "lo" and (.flags | index("UP")) != null)
              and any(.[];
                    .ifname == $name
                    and .ifindex == $ifindex
                    and .ifalias == $alias
                    and .linkinfo.info_kind == "wireguard"
                    and (.flags | index("UP")) != null)
              and all(.[]; .ifname == "lo" or .ifname == $name)
            ' >/dev/null 2>&1 || return 1
    hook_peer_address_hex=$(printf '%s' "$hook_peer_local_address" \
        | /usr/bin/tr -d ':') || return 1
    # shellcheck disable=SC2016
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/awk \
            -v expected_address="$hook_peer_address_hex" \
            -v expected_interface="$hook_peer_interface" '
              $6 == expected_interface {
                  records++
                  if ($1 == expected_address && $3 == "80" && $4 == "00") matches++
              }
              END { if (records != 1 || matches != 1) exit 1 }
            ' /proc/net/if_inet6 || return 1
    for hook_route_address in "$hook_worker_address" "$hook_cross_address"; do
        hook_route_destination=$(/usr/bin/nsenter \
            --net="/proc/$hook_peer_pid/ns/net" -- \
            /usr/sbin/ip -6 -json route show table main \
                exact "$hook_route_address/128" 2>/dev/null \
            | activated_route_destination \
                "$hook_peer_interface" 2>/dev/null) || return 1
        [ "$hook_route_destination" = "$hook_route_address" ] || return 1
    done
    hook_default_routes=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip -6 -json route show table main default 2>/dev/null) \
        || return 1
    [ "$hook_default_routes" = '[]' ] || return 1
    hook_public_key=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" public-key 2>/dev/null) \
        || return 1
    [ "$hook_public_key" = "$hook_peer_public_key" ] || return 1
    hook_listen_port=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" listen-port 2>/dev/null) \
        || return 1
    [ "$hook_listen_port" = "$hook_peer_listen_port" ] || return 1
    hook_peer_field=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" peers 2>/dev/null) || return 1
    [ "$hook_peer_field" = "$hook_worker_public_key" ] || return 1
    hook_expected_peer_field=$(printf '%s\t%s:%s' \
        "$hook_worker_public_key" "$functional_underlay_address" \
        "$hook_worker_listen_port") || return 1
    hook_peer_field=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" endpoints 2>/dev/null) \
        || return 1
    [ "$hook_peer_field" = "$hook_expected_peer_field" ] || return 1
    hook_peer_field=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" allowed-ips 2>/dev/null) \
        || return 1
    printf '%s\n' "$hook_peer_field" | /usr/bin/awk -F '\t' \
        -v expected_key="$hook_worker_public_key" \
        -v first="$hook_worker_address/128" \
        -v second="$hook_cross_address/128" '
          NR == 1 && NF == 2 && $1 == expected_key {
              count = split($2, address, " ")
              if (count == 2 \
                  && ((address[1] == first && address[2] == second) \
                      || (address[1] == second && address[2] == first))) valid = 1
          }
          END { if (NR != 1 || !valid) exit 1 }
        ' || return 1
    hook_expected_peer_field=$(printf '%s\t%s' \
        "$hook_worker_public_key" "$functional_peer_keepalive") || return 1
    hook_peer_field=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" \
            persistent-keepalive 2>/dev/null) || return 1
    [ "$hook_peer_field" = "$hook_expected_peer_field" ] || return 1
    hook_peer_field=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" \
            latest-handshakes 2>/dev/null) || return 1
    wireguard_counter_line_is_exact \
        "$hook_peer_field" "$hook_worker_public_key" 2 || return 1
    hook_peer_field=$(/usr/bin/nsenter \
        --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/bin/wg show "$hook_peer_interface" transfer 2>/dev/null) \
        || return 1
    wireguard_counter_line_is_exact \
        "$hook_peer_field" "$hook_worker_public_key" 3
}

functional_pair_parent_namespace_is_exact() {
    /usr/sbin/ip -details -json link show 2>/dev/null \
        | /usr/bin/jq -e --arg underlay "$functional_underlay" '
          type == "array" and length == 2
          and any(.[]; .ifname == "lo")
          and any(.[];
                .ifname == $underlay
                and .linkinfo.info_kind == "dummy"
                and (.flags | index("UP")) != null)
          and all(.[]; .ifname == "lo" or .ifname == $underlay)
        ' >/dev/null 2>&1
}

functional_relay_pair_fixtures_are_exact() {
    functional_pair_parent_namespace_is_exact || return 1
    functional_pair_peer_fixture_is_exact \
        "$functional_pair_client_keeper_pid" \
        "$functional_pair_client_keeper_starttime" \
        "$functional_pair_client_namespace_identity" \
        "$functional_relay" "$functional_relay_alias" \
        "$functional_pair_client_ifindex" \
        "$functional_relay_public_key" "$functional_relay_listen_port" \
        "$functional_pair_client_public_key" \
        "$functional_pair_client_listen_port" \
        "$functional_pair_client_peer_address" \
        "$functional_pair_client_worker_address" \
        "$functional_pair_exit_peer_address" || return 1
    functional_pair_peer_fixture_is_exact \
        "$functional_pair_exit_keeper_pid" \
        "$functional_pair_exit_keeper_starttime" \
        "$functional_pair_exit_namespace_identity" \
        "$functional_exit_relay" "$functional_exit_relay_alias" \
        "$functional_pair_exit_ifindex" \
        "$functional_exit_relay_public_key" \
        "$functional_exit_relay_listen_port" \
        "$functional_pair_exit_public_key" \
        "$functional_pair_exit_listen_port" \
        "$functional_pair_exit_peer_address" \
        "$functional_pair_exit_worker_address" \
        "$functional_pair_client_peer_address"
}

build_functional_relay_pair_fixtures() {
    [ "$#" -eq 8 ] || return 1
    functional_pair_client_public_key=$1
    functional_pair_client_listen_port=$2
    functional_pair_client_worker_address=$3
    functional_pair_client_peer_address=$4
    functional_pair_exit_public_key=$5
    functional_pair_exit_listen_port=$6
    functional_pair_exit_worker_address=$7
    functional_pair_exit_peer_address=$8
    functional_relay_client_address=$3
    functional_exit_relay_exit_address=$7
    functional_fixture_shape=pair

    functional_pair_client_keeper_state=launching
    if launch_functional_peer_keeper; then
        functional_pair_client_keeper_pid=$hook_peer_keeper_pid
        functional_pair_client_keeper_starttime=$hook_peer_keeper_starttime
        functional_pair_client_namespace_identity=$hook_peer_keeper_namespace_identity
        functional_pair_client_keeper_state=ready
    else
        functional_pair_client_keeper_pid=$hook_peer_keeper_pid
        return 1
    fi
    functional_pair_exit_keeper_state=launching
    if launch_functional_peer_keeper; then
        functional_pair_exit_keeper_pid=$hook_peer_keeper_pid
        functional_pair_exit_keeper_starttime=$hook_peer_keeper_starttime
        functional_pair_exit_namespace_identity=$hook_peer_keeper_namespace_identity
        functional_pair_exit_keeper_state=ready
    else
        functional_pair_exit_keeper_pid=$hook_peer_keeper_pid
        return 1
    fi
    [ "$functional_pair_client_namespace_identity" != \
        "$functional_pair_exit_namespace_identity" ] || return 1

    functional_relay_ifindex=
    functional_relay_state=adding
    add_functional_relay_link || return 1
    capture_functional_relay_ifindex || return 1
    functional_relay_ifindex=$hook_captured_relay_ifindex
    functional_relay_state=created
    functional_relay_identity_is_exact "$functional_relay_ifindex" || return 1
    mark_functional_relay_link || return 1
    functional_relay_state=marked
    configure_functional_relay_pair_wireguard \
        "$1" "$2" "$3" "$8" || return 1
    functional_pair_parent_wireguard_is_exact \
        "$functional_relay" "$functional_relay_alias" \
        "$functional_relay_ifindex" "$functional_relay_public_key" \
        "$functional_relay_listen_port" "$1" "$2" "$3" "$8" || return 1
    functional_pair_client_link_state=parent

    functional_exit_relay_ifindex=
    functional_exit_relay_state=adding
    add_functional_exit_relay_link || return 1
    capture_functional_exit_relay_ifindex || return 1
    functional_exit_relay_ifindex=$hook_captured_exit_relay_ifindex
    functional_exit_relay_state=created
    functional_exit_relay_identity_is_exact \
        "$functional_exit_relay_ifindex" || return 1
    mark_functional_exit_relay_link || return 1
    functional_exit_relay_state=marked
    configure_functional_exit_relay_pair_wireguard \
        "$5" "$6" "$7" "$4" || return 1
    functional_pair_parent_wireguard_is_exact \
        "$functional_exit_relay" "$functional_exit_relay_alias" \
        "$functional_exit_relay_ifindex" \
        "$functional_exit_relay_public_key" \
        "$functional_exit_relay_listen_port" "$5" "$6" "$7" "$4" \
        || return 1
    functional_pair_exit_link_state=parent

    functional_peer_keeper_is_exact \
        "$functional_pair_client_keeper_pid" \
        "$functional_pair_client_keeper_starttime" \
        "$functional_pair_client_namespace_identity" || return 1
    functional_pair_client_ifindex=$functional_relay_ifindex
    /usr/sbin/ip link set dev "$functional_relay" \
        netns "$functional_pair_client_keeper_pid" || return 1
    functional_pair_client_link_state=moved
    hook_pair_moved_ifindex=$(/usr/bin/nsenter \
        --net="/proc/$functional_pair_client_keeper_pid/ns/net" -- \
        /usr/bin/cat "/sys/class/net/$functional_relay/ifindex") || return 1
    number_is_safe "$hook_pair_moved_ifindex" \
        && [ "$hook_pair_moved_ifindex" = \
            "$functional_pair_client_ifindex" ] || return 1
    configure_functional_pair_peer_namespace \
        "$functional_pair_client_keeper_pid" \
        "$functional_pair_client_keeper_starttime" \
        "$functional_pair_client_namespace_identity" \
        "$functional_relay" "$4" "$3" "$8" || return 1

    functional_peer_keeper_is_exact \
        "$functional_pair_exit_keeper_pid" \
        "$functional_pair_exit_keeper_starttime" \
        "$functional_pair_exit_namespace_identity" || return 1
    functional_pair_exit_ifindex=$functional_exit_relay_ifindex
    /usr/sbin/ip link set dev "$functional_exit_relay" \
        netns "$functional_pair_exit_keeper_pid" || return 1
    functional_pair_exit_link_state=moved
    hook_pair_moved_ifindex=$(/usr/bin/nsenter \
        --net="/proc/$functional_pair_exit_keeper_pid/ns/net" -- \
        /usr/bin/cat "/sys/class/net/$functional_exit_relay/ifindex") || return 1
    number_is_safe "$hook_pair_moved_ifindex" \
        && [ "$hook_pair_moved_ifindex" = \
            "$functional_pair_exit_ifindex" ] || return 1
    configure_functional_pair_peer_namespace \
        "$functional_pair_exit_keeper_pid" \
        "$functional_pair_exit_keeper_starttime" \
        "$functional_pair_exit_namespace_identity" \
        "$functional_exit_relay" "$8" "$7" "$4" || return 1
    functional_relay_pair_fixtures_are_exact
}

create_functional_relay_pair_fixtures() {
    [ "$#" -eq 8 ] || return 1
    for hook_pair_public_key in "$1" "$5"; do
        case $hook_pair_public_key in
            ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
        esac
        [ "${#hook_pair_public_key}" -eq 44 ] \
            && [ "$hook_pair_public_key" != "$functional_relay_public_key" ] \
            && [ "$hook_pair_public_key" != \
                "$functional_exit_relay_public_key" ] || return 1
    done
    [ "$1" != "$5" ] || return 1
    for hook_pair_port in "$2" "$6"; do
        number_is_safe "$hook_pair_port" \
            && [ "$hook_pair_port" -le 65535 ] || return 1
    done
    [ "$2" != "$6" ] || return 1
    for hook_pair_address in "$3" "$4" "$7" "$8"; do
        case $hook_pair_address in
            ''|*[!0-9a-f:]*) return 1 ;;
        esac
        [ "${#hook_pair_address}" -eq 39 ] || return 1
    done
    [ "$3" != "$4" ] && [ "$3" != "$7" ] && [ "$3" != "$8" ] \
        && [ "$4" != "$7" ] && [ "$4" != "$8" ] \
        && [ "$7" != "$8" ] || return 1
    [ "$functional_fixture_shape" = single ] \
        && [ "$functional_relay_state" = absent ] \
        && [ "$functional_exit_relay_state" = absent ] \
        && [ "$functional_pair_client_keeper_state" = absent ] \
        && [ "$functional_pair_exit_keeper_state" = absent ] \
        && functional_relay_link_is_absent \
        && functional_exit_relay_link_is_absent || return 1
    if build_functional_relay_pair_fixtures "$@"; then
        return 0
    fi
    remove_functional_relay_pair_fixtures || return 1
    return 1
}

functional_pair_peer_link_identity_is_exact() {
    [ "$#" -eq 7 ] || return 1
    hook_peer_pid=$1
    hook_peer_starttime=$2
    hook_peer_namespace_identity=$3
    hook_peer_interface=$4
    hook_peer_alias=$5
    hook_peer_ifindex=$6
    hook_peer_state=$7
    [ "$hook_peer_state" = moved ] || return 1
    functional_peer_keeper_is_exact \
        "$hook_peer_pid" "$hook_peer_starttime" \
        "$hook_peer_namespace_identity" || return 1
    /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip -details -json link show dev \
            "$hook_peer_interface" 2>/dev/null \
        | /usr/bin/jq -e \
            --arg name "$hook_peer_interface" \
            --arg alias "$hook_peer_alias" \
            --argjson ifindex "$hook_peer_ifindex" '
              type == "array" and length == 1
              and .[0].ifname == $name
              and .[0].ifindex == $ifindex
              and .[0].ifalias == $alias
              and .[0].linkinfo.info_kind == "wireguard"
            ' >/dev/null 2>&1
}

functional_pair_peer_link_is_absent() {
    [ "$#" -eq 4 ] || return 1
    hook_peer_pid=$1
    hook_peer_interface=$2
    hook_worker_address=$3
    hook_cross_address=$4
    if /usr/bin/nsenter --net="/proc/$hook_peer_pid/ns/net" -- \
        /usr/sbin/ip link show dev "$hook_peer_interface" \
            >/dev/null 2>&1; then
        return 1
    fi
    for hook_route_address in "$hook_worker_address" "$hook_cross_address"; do
        hook_route=$(/usr/bin/nsenter \
            --net="/proc/$hook_peer_pid/ns/net" -- \
            /usr/sbin/ip -6 -json route show table main \
                exact "$hook_route_address/128" 2>/dev/null) || return 1
        [ "$hook_route" = '[]' ] || return 1
    done
}

remove_functional_relay_pair_exit_fixture() {
    case $functional_pair_exit_link_state in
        absent|parent)
            remove_functional_exit_relay_fixture || return 1
            ;;
        moved)
            functional_pair_peer_link_identity_is_exact \
                "$functional_pair_exit_keeper_pid" \
                "$functional_pair_exit_keeper_starttime" \
                "$functional_pair_exit_namespace_identity" \
                "$functional_exit_relay" "$functional_exit_relay_alias" \
                "$functional_pair_exit_ifindex" \
                "$functional_pair_exit_link_state" || return 1
            if /usr/bin/nsenter \
                --net="/proc/$functional_pair_exit_keeper_pid/ns/net" -- \
                /usr/sbin/ip link delete dev "$functional_exit_relay"; then
                functional_pair_exit_link_state=deleted
            elif functional_pair_peer_link_is_absent \
                "$functional_pair_exit_keeper_pid" \
                "$functional_exit_relay" \
                "$functional_pair_exit_worker_address" \
                "$functional_pair_client_peer_address"; then
                functional_pair_exit_link_state=deleted
            else
                return 1
            fi
            functional_pair_peer_link_is_absent \
                "$functional_pair_exit_keeper_pid" \
                "$functional_exit_relay" \
                "$functional_pair_exit_worker_address" \
                "$functional_pair_client_peer_address" || return 1
            forget_functional_exit_relay_fixture
            ;;
        deleted)
            functional_peer_keeper_is_exact \
                "$functional_pair_exit_keeper_pid" \
                "$functional_pair_exit_keeper_starttime" \
                "$functional_pair_exit_namespace_identity" || return 1
            functional_pair_peer_link_is_absent \
                "$functional_pair_exit_keeper_pid" \
                "$functional_exit_relay" \
                "$functional_pair_exit_worker_address" \
                "$functional_pair_client_peer_address" || return 1
            forget_functional_exit_relay_fixture
            ;;
        *) return 1 ;;
    esac
    functional_pair_exit_link_state=absent
    retire_functional_peer_keeper \
        "$functional_pair_exit_keeper_state" \
        "$functional_pair_exit_keeper_pid" \
        "$functional_pair_exit_keeper_starttime" \
        "$functional_pair_exit_namespace_identity" || return 1
    functional_pair_exit_keeper_state=absent
    functional_pair_exit_keeper_pid=
    functional_pair_exit_keeper_starttime=
    functional_pair_exit_namespace_identity=
    functional_pair_exit_ifindex=
}

remove_functional_relay_pair_client_fixture() {
    case $functional_pair_client_link_state in
        absent|parent)
            remove_functional_relay_fixture || return 1
            ;;
        moved)
            functional_pair_peer_link_identity_is_exact \
                "$functional_pair_client_keeper_pid" \
                "$functional_pair_client_keeper_starttime" \
                "$functional_pair_client_namespace_identity" \
                "$functional_relay" "$functional_relay_alias" \
                "$functional_pair_client_ifindex" \
                "$functional_pair_client_link_state" || return 1
            if /usr/bin/nsenter \
                --net="/proc/$functional_pair_client_keeper_pid/ns/net" -- \
                /usr/sbin/ip link delete dev "$functional_relay"; then
                functional_pair_client_link_state=deleted
            elif functional_pair_peer_link_is_absent \
                "$functional_pair_client_keeper_pid" "$functional_relay" \
                "$functional_pair_client_worker_address" \
                "$functional_pair_exit_peer_address"; then
                functional_pair_client_link_state=deleted
            else
                return 1
            fi
            functional_pair_peer_link_is_absent \
                "$functional_pair_client_keeper_pid" "$functional_relay" \
                "$functional_pair_client_worker_address" \
                "$functional_pair_exit_peer_address" || return 1
            forget_functional_relay_fixture
            ;;
        deleted)
            functional_peer_keeper_is_exact \
                "$functional_pair_client_keeper_pid" \
                "$functional_pair_client_keeper_starttime" \
                "$functional_pair_client_namespace_identity" || return 1
            functional_pair_peer_link_is_absent \
                "$functional_pair_client_keeper_pid" "$functional_relay" \
                "$functional_pair_client_worker_address" \
                "$functional_pair_exit_peer_address" || return 1
            forget_functional_relay_fixture
            ;;
        *) return 1 ;;
    esac
    functional_pair_client_link_state=absent
    retire_functional_peer_keeper \
        "$functional_pair_client_keeper_state" \
        "$functional_pair_client_keeper_pid" \
        "$functional_pair_client_keeper_starttime" \
        "$functional_pair_client_namespace_identity" || return 1
    functional_pair_client_keeper_state=absent
    functional_pair_client_keeper_pid=
    functional_pair_client_keeper_starttime=
    functional_pair_client_namespace_identity=
    functional_pair_client_ifindex=
}

functional_relay_pair_fixtures_are_absent() {
    [ "$functional_pair_client_keeper_state" = absent ] \
        && [ -z "$functional_pair_client_keeper_pid" ] \
        && [ "$functional_pair_client_link_state" = absent ] \
        && [ "$functional_pair_exit_keeper_state" = absent ] \
        && [ -z "$functional_pair_exit_keeper_pid" ] \
        && [ "$functional_pair_exit_link_state" = absent ] \
        && [ "$functional_relay_state" = absent ] \
        && [ "$functional_exit_relay_state" = absent ] \
        && functional_relay_link_is_absent \
        && functional_exit_relay_link_is_absent
}

# shellcheck disable=SC2120
remove_functional_relay_pair_fixtures() {
    [ "$#" -eq 0 ] || return 1
    functional_fixture_shape=pair
    remove_functional_relay_pair_exit_fixture || return 1
    remove_functional_relay_pair_client_fixture || return 1
    functional_pair_client_public_key=
    functional_pair_client_listen_port=
    functional_pair_client_worker_address=
    functional_pair_client_peer_address=
    functional_pair_exit_public_key=
    functional_pair_exit_listen_port=
    functional_pair_exit_worker_address=
    functional_pair_exit_peer_address=
    functional_fixture_shape=single
    functional_relay_pair_fixtures_are_absent
}

worker_wireguard_is_absent() {
    [ "$#" -eq 2 ] || return 1
    hook_namespace_fd=$1
    hook_peer_address=$2
    fd_number_is_safe "$hook_namespace_fd" || return 1
    case $hook_peer_address in
        ''|*[!0-9a-f:]*) return 1 ;;
    esac
    [ "${#hook_peer_address}" -eq 39 ] || return 1
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
            ' >/dev/null 2>&1 \
        || return 1
    hook_route=$(
        /usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" -- \
            /usr/sbin/ip -6 -json route show table main \
                exact "$hook_peer_address/128" 2>/dev/null
    ) || return 1
    [ "$hook_route" = '[]' ]
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
    printf '%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$functional_ready_record" \
        "$functional_exit_ready_record" \
        "$functional_exit_pass_record" \
        "$functional_relay_pair_ready_record" \
        "$functional_relay_pair_pass_record" \
        "$functional_pass_record" \
        >"$hook_functional_expected" || return 1
    chmod 0600 "$hook_functional_expected" || return 1
    if ! private_file_is_safe "$hook_functional_expected" \
        || ! cmp -s "$hook_functional_expected" "$hook_functional_output"; then
        rm -f -- "$hook_functional_expected"
        return 1
    fi
    rm -f -- "$hook_functional_expected"
}

functional_probe_failure_value_is_safe() {
    [ "$#" -eq 1 ] || return 1
    hook_functional_failure_value=$1
    hook_functional_failure_phase=${hook_functional_failure_value%%,*}
    hook_functional_failure_class=${hook_functional_failure_value#*,}
    [ "$hook_functional_failure_value" = \
        "$hook_functional_failure_phase,$hook_functional_failure_class" ] \
        || return 1
    case $hook_functional_failure_phase in
        plan|connect|bind|prepare|activate|shutdown|ready|release|reconnect|commit|destroy|\
        second-cycle-plan|second-cycle-bind|second-cycle-prepare|\
        second-cycle-activate|reuse|second-cycle-shutdown|second-cycle-ready|\
        second-cycle-release|second-cycle-reconnect|second-cycle-commit|\
        second-cycle-destroy|relay-pair-plan|relay-pair-bind|relay-pair-prepare|\
        relay-pair-activate|relay-pair-reuse|relay-pair-shutdown|relay-pair-ready|\
        relay-pair-release|relay-pair-reconnect|relay-pair-commit|\
        relay-pair-destroy|final-shutdown)
            ;;
        *) return 1 ;;
    esac
    case $hook_functional_failure_class in
        random|protocol|io|timeout|untrusted|correlation|unexpected-response)
            return 0
            ;;
        *) return 1 ;;
    esac
}

functional_probe_failure_record_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_functional_failure_source=$1
    private_file_is_safe "$hook_functional_failure_source" || return 1
    hook_functional_failure_size=$(stat -Lc '%s' \
        "$hook_functional_failure_source" 2>/dev/null) || return 1
    [ "$hook_functional_failure_size" -ge 1 ] \
        && [ "$hook_functional_failure_size" -le 128 ] || return 1
    hook_functional_failure_line=$(cat "$hook_functional_failure_source") \
        || return 1
    case $hook_functional_failure_line in
        "$functional_failure_prefix"*)
            hook_functional_failure_value=${hook_functional_failure_line#"$functional_failure_prefix"}
            ;;
        *) return 1 ;;
    esac
    functional_probe_failure_value_is_safe "$hook_functional_failure_value" \
        || return 1
    hook_functional_failure_expected=$functional_failure_prefix$hook_functional_failure_value
    [ "$hook_functional_failure_line" = "$hook_functional_failure_expected" ] \
        || return 1
    hook_functional_failure_expected_size=$((
        ${#hook_functional_failure_expected} + 1
    ))
    [ "$hook_functional_failure_size" -eq \
        "$hook_functional_failure_expected_size" ]
}

publish_functional_probe_failure() {
    [ "$#" -eq 2 ] || return 1
    hook_functional_failure_status=$1
    hook_functional_failure_source=$2
    [ "$hook_functional_failure_status" -eq 1 ] || return 1
    [ ! -e "$functional_failure_record" ] \
        && [ ! -L "$functional_failure_record" ] \
        && [ ! -e "$functional_failure_record.next" ] \
        && [ ! -L "$functional_failure_record.next" ] || return 1
    functional_probe_failure_record_is_exact "$hook_functional_failure_source" \
        || return 1
    hook_functional_failure_line=$(cat "$hook_functional_failure_source") \
        || return 1
    write_private_file "$functional_failure_record" \
        "$hook_functional_failure_line" || return 1
    functional_probe_failure_record_is_exact "$functional_failure_record"
}

observe_functional_probe_failure() {
    [ "$#" -eq 2 ] || return 1
    hook_functional_failure_pid=$1
    hook_functional_failure_source=$2
    number_is_safe "$hook_functional_failure_pid" || return 1
    if wait "$hook_functional_failure_pid"; then
        hook_functional_failure_status=0
    else
        hook_functional_failure_status=$?
    fi
    publish_functional_probe_failure \
        "$hook_functional_failure_status" "$hook_functional_failure_source"
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
        "$hook_functional_fifo" "$hook_functional_stdout" "$hook_functional_stderr" \
        "$functional_failure_record" "$functional_failure_record.next"; do
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
        if [ -s "$hook_functional_stderr" ] \
            || ! kill -0 "$hook_functional_probe_pid" 2>/dev/null; then
            observe_functional_probe_failure \
                "$hook_functional_probe_pid" "$hook_functional_stderr" || return 1
            return 1
        fi
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
    hook_functional_peer_address=$(worker_client_peer_address \
        7 "$hook_functional_wireguard") || return 1
    hook_functional_client_address=$(worker_client_local_address \
        7 "$hook_functional_wireguard") || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_wireguard" "$hook_functional_peer_address" \
        "$functional_peer_public_key" "$functional_peer_endpoint" || return 1
    hook_functional_client_public_key=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_wireguard" public-key 2>/dev/null) \
        || return 1
    case $hook_functional_client_public_key in
        ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
    esac
    [ "${#hook_functional_client_public_key}" -eq 44 ] \
        && [ "$hook_functional_client_public_key" != \
            "$functional_relay_public_key" ] || return 1
    hook_functional_client_listen_port=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_wireguard" listen-port 2>/dev/null) \
        || return 1
    number_is_safe "$hook_functional_client_listen_port" \
        && [ "$hook_functional_client_listen_port" -le 65535 ] || return 1
    [ "$hook_functional_client_listen_port" -ne \
        "$functional_relay_listen_port" ] || return 1
    hook_functional_baseline=$(worker_wireguard_snapshot \
        7 "$hook_functional_wireguard" "$functional_relay_public_key") \
        || return 1

    advance_start_failure_stage functional-relay-fixture || return 1
    create_functional_relay_fixture \
        "$hook_functional_client_public_key" \
        "$hook_functional_client_listen_port" \
        "$hook_functional_client_address" \
        "$hook_functional_peer_address" || return 1

    advance_start_failure_stage functional-relay-traffic || return 1
    /usr/bin/ping -6 -n -I "$functional_relay" \
        -c 1 -W 3 "$hook_functional_client_address" >/dev/null 2>&1 || return 1
    hook_functional_wait_attempt=0
    while :; do
        hook_functional_current=$(worker_wireguard_snapshot \
            7 "$hook_functional_wireguard" "$functional_relay_public_key") \
            || return 1
        if wireguard_snapshot_has_growth \
            "$hook_functional_baseline" "$hook_functional_current"; then
            break
        fi
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    hook_functional_relay_snapshot=$(relay_wireguard_snapshot \
        "$functional_relay" "$hook_functional_client_public_key") || return 1
    hook_functional_zero_snapshot=$(printf '0\t0\t0') || return 1
    wireguard_snapshot_has_growth \
        "$hook_functional_zero_snapshot" "$hook_functional_relay_snapshot" || return 1
    functional_relay_fixture_is_exact \
        "$functional_relay_ifindex" \
        "$hook_functional_client_public_key" \
        "$hook_functional_client_listen_port" \
        "$hook_functional_client_address" \
        "$hook_functional_peer_address" || return 1

    advance_start_failure_stage functional-relay-cleanup || return 1
    remove_functional_relay_fixture || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_wireguard" "$hook_functional_peer_address" \
        "$functional_peer_public_key" "$functional_peer_endpoint" || return 1
    hook_functional_retained=$(worker_wireguard_snapshot \
        7 "$hook_functional_wireguard" "$functional_relay_public_key") \
        || return 1
    wireguard_snapshot_has_growth \
        "$hook_functional_baseline" "$hook_functional_retained" || return 1
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

    advance_start_failure_stage functional-client-release || return 1
    printf '%s' "$functional_release_byte" >&6 || return 1
    hook_functional_exit_ready_output=$(printf '%s\n%s' \
        "$functional_ready_record" "$functional_exit_ready_record") || return 1
    hook_functional_wait_attempt=0
    while ! probe_output_is_exact \
        "$hook_functional_stdout" "$hook_functional_exit_ready_output"; do
        private_file_is_safe "$hook_functional_stderr" || return 1
        if [ -s "$hook_functional_stderr" ] \
            || ! kill -0 "$hook_functional_probe_pid" 2>/dev/null; then
            observe_functional_probe_failure \
                "$hook_functional_probe_pid" "$hook_functional_stderr" || return 1
            return 1
        fi
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 300 ] || return 1
        sleep 0.05
    done

    advance_start_failure_stage functional-client-cleanup || return 1
    hook_functional_wait_attempt=0
    while ! worker_process_fd_is_retired 8; do
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" = \
        "$hook_functional_process_identity" ] || return 1
    worker_wireguard_is_absent 7 "$hook_functional_peer_address" || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/7 2>/dev/null)" = \
        "$hook_functional_worker_namespace" ] || return 1
    command exec 8>&- || return 1
    [ ! -e /proc/self/fd/8 ] && [ ! -L /proc/self/fd/8 ] || return 1
    command exec 7>&- || return 1
    [ ! -e /proc/self/fd/7 ] && [ ! -L /proc/self/fd/7 ] || return 1

    advance_start_failure_stage functional-exit-ready || return 1
    running_identity_is_unchanged \
        "$hook_functional_unit" \
        "$proof_directory/unit.identity" \
        "$hook_functional_agent_gid" || return 1
    socket_identity_is_unchanged \
        "$proof_directory/socket.identity" "$hook_functional_agent_gid" || return 1
    unit_fdstore_is_empty "$hook_functional_unit" || return 1

    advance_start_failure_stage functional-exit-worker-observation || return 1
    hook_functional_exit_worker_pid=$(direct_helper_child "$hook_functional_main_pid") \
        || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_exit_worker_pid" || return 1
    hook_functional_exit_pidfd_count=$hook_custody_pidfd_count
    hook_functional_exit_pidfd_identity=$hook_custody_pidfd_identity
    hook_functional_exit_process_count=$hook_custody_process_count
    hook_functional_exit_namespace_count=$hook_custody_namespace_count
    hook_functional_exit_parent_namespace=$hook_custody_parent_namespace
    hook_functional_exit_process_parent_fd=$hook_custody_process_fd
    hook_functional_exit_process_identity=$hook_custody_process_identity
    hook_functional_exit_namespace_parent_fd=$hook_custody_namespace_fd
    hook_functional_exit_worker_namespace=$hook_custody_namespace_identity
    # Retired PID and nsfs numbers are reusable after their last pins close.
    # Only the current live pidfd, proc-dir and netns custody is identity
    # authority; comparing against a stale numeric observation would be flaky.
    [ "$hook_functional_exit_parent_namespace" = "$hook_functional_parent_namespace" ] \
        && [ "$hook_functional_exit_parent_namespace" != \
            "$hook_functional_exit_worker_namespace" ] || return 1
    hook_functional_exit_parent_process_path=/proc/$hook_functional_main_pid/fd/$hook_functional_exit_process_parent_fd
    hook_functional_exit_parent_namespace_path=/proc/$hook_functional_main_pid/fd/$hook_functional_exit_namespace_parent_fd
    [ "$(capture_parent_process_fd_identity \
        "$hook_functional_main_pid" "$hook_functional_exit_process_parent_fd" \
        "$hook_functional_exit_worker_pid")" = \
        "$hook_functional_exit_process_identity" ] || return 1
    [ "$(capture_parent_namespace_fd_identity \
        "$hook_functional_main_pid" "$hook_functional_exit_namespace_parent_fd")" = \
        "$hook_functional_exit_worker_namespace" ] || return 1
    command exec 7<"$hook_functional_exit_parent_namespace_path" || return 1
    command exec 8<"$hook_functional_exit_parent_process_path" || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/7 2>/dev/null)" = \
        "$hook_functional_exit_worker_namespace" ] || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" = \
        "$hook_functional_exit_process_identity" ] || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_exit_worker_pid" || return 1
    [ "$hook_custody_pidfd_count" = "$hook_functional_exit_pidfd_count" ] \
        && [ "$hook_custody_pidfd_identity" = \
            "$hook_functional_exit_pidfd_identity" ] \
        && [ "$hook_custody_process_count" = \
            "$hook_functional_exit_process_count" ] \
        && [ "$hook_custody_namespace_count" = \
            "$hook_functional_exit_namespace_count" ] \
        && [ "$hook_custody_process_fd" = \
            "$hook_functional_exit_process_parent_fd" ] \
        && [ "$hook_custody_process_identity" = \
            "$hook_functional_exit_process_identity" ] \
        && [ "$hook_custody_namespace_fd" = \
            "$hook_functional_exit_namespace_parent_fd" ] \
        && [ "$hook_custody_namespace_identity" = \
            "$hook_functional_exit_worker_namespace" ] || return 1
    hook_functional_exit_worker_starttime=$(worker_identity_from_process_fd \
        8 "$hook_functional_exit_worker_pid" "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" "$hook_functional_worker_gid" \
        "$hook_functional_parent_filters") || return 1
    hook_functional_exit_wireguard=$(worker_wireguard_interface 7) || return 1
    case $hook_functional_exit_wireguard in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "$hook_functional_exit_wireguard" != "$hook_functional_wireguard" ] || return 1
    hook_functional_exit_peer_address=$(worker_exit_peer_address \
        7 "$hook_functional_exit_wireguard") || return 1
    hook_functional_exit_local_address=$(worker_exit_local_address \
        7 "$hook_functional_exit_wireguard") || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_exit_wireguard" "$hook_functional_exit_peer_address" \
        "$functional_exit_peer_public_key" "$functional_exit_peer_endpoint" || return 1
    hook_functional_exit_public_key=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_exit_wireguard" public-key 2>/dev/null) \
        || return 1
    case $hook_functional_exit_public_key in
        ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
    esac
    [ "${#hook_functional_exit_public_key}" -eq 44 ] \
        && [ "$hook_functional_exit_public_key" != \
            "$functional_exit_relay_public_key" ] \
        && [ "$hook_functional_exit_public_key" != \
            "$hook_functional_client_public_key" ] || return 1
    hook_functional_exit_listen_port=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_exit_wireguard" listen-port 2>/dev/null) \
        || return 1
    number_is_safe "$hook_functional_exit_listen_port" \
        && [ "$hook_functional_exit_listen_port" -le 65535 ] || return 1
    [ "$hook_functional_exit_listen_port" -ne \
        "$functional_exit_relay_listen_port" ] || return 1
    hook_functional_exit_baseline=$(worker_wireguard_snapshot \
        7 "$hook_functional_exit_wireguard" "$functional_exit_relay_public_key") \
        || return 1

    advance_start_failure_stage functional-exit-relay-fixture || return 1
    create_functional_exit_relay_fixture \
        "$hook_functional_exit_public_key" \
        "$hook_functional_exit_listen_port" \
        "$hook_functional_exit_local_address" \
        "$hook_functional_exit_peer_address" || return 1

    advance_start_failure_stage functional-exit-relay-traffic || return 1
    /usr/bin/ping -6 -n -I "$functional_exit_relay" \
        -c 1 -W 3 "$hook_functional_exit_local_address" >/dev/null 2>&1 || return 1
    hook_functional_wait_attempt=0
    while :; do
        hook_functional_exit_current=$(worker_wireguard_snapshot \
            7 "$hook_functional_exit_wireguard" \
            "$functional_exit_relay_public_key") || return 1
        if wireguard_snapshot_has_growth \
            "$hook_functional_exit_baseline" "$hook_functional_exit_current"; then
            break
        fi
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    hook_functional_exit_relay_snapshot=$(relay_wireguard_snapshot \
        "$functional_exit_relay" "$hook_functional_exit_public_key") || return 1
    wireguard_snapshot_has_growth \
        "$hook_functional_zero_snapshot" \
        "$hook_functional_exit_relay_snapshot" || return 1
    functional_exit_relay_fixture_is_exact \
        "$functional_exit_relay_ifindex" \
        "$hook_functional_exit_public_key" \
        "$hook_functional_exit_listen_port" \
        "$hook_functional_exit_local_address" \
        "$hook_functional_exit_peer_address" || return 1

    advance_start_failure_stage functional-exit-relay-cleanup || return 1
    remove_functional_exit_relay_fixture || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_exit_wireguard" "$hook_functional_exit_peer_address" \
        "$functional_exit_peer_public_key" "$functional_exit_peer_endpoint" || return 1
    hook_functional_exit_retained=$(worker_wireguard_snapshot \
        7 "$hook_functional_exit_wireguard" "$functional_exit_relay_public_key") \
        || return 1
    wireguard_snapshot_has_growth \
        "$hook_functional_exit_baseline" "$hook_functional_exit_retained" || return 1
    [ "$(worker_identity_from_process_fd \
        8 "$hook_functional_exit_worker_pid" "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" "$hook_functional_worker_gid" \
        "$hook_functional_parent_filters")" = \
        "$hook_functional_exit_worker_starttime" ] || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_exit_worker_pid" || return 1
    [ "$hook_custody_pidfd_count" = "$hook_functional_exit_pidfd_count" ] \
        && [ "$hook_custody_pidfd_identity" = \
            "$hook_functional_exit_pidfd_identity" ] \
        && [ "$hook_custody_process_count" = \
            "$hook_functional_exit_process_count" ] \
        && [ "$hook_custody_namespace_count" = \
            "$hook_functional_exit_namespace_count" ] \
        && [ "$hook_custody_process_fd" = \
            "$hook_functional_exit_process_parent_fd" ] \
        && [ "$hook_custody_process_identity" = \
            "$hook_functional_exit_process_identity" ] \
        && [ "$hook_custody_namespace_fd" = \
            "$hook_functional_exit_namespace_parent_fd" ] \
        && [ "$hook_custody_namespace_identity" = \
            "$hook_functional_exit_worker_namespace" ] || return 1

    advance_start_failure_stage functional-exit-release || return 1
    printf '%s' "$functional_release_byte" >&6 || return 1
    hook_functional_relay_pair_ready_output=$(printf '%s\n%s\n%s\n%s' \
        "$functional_ready_record" \
        "$functional_exit_ready_record" \
        "$functional_exit_pass_record" \
        "$functional_relay_pair_ready_record") || return 1
    hook_functional_wait_attempt=0
    while ! probe_output_is_exact \
        "$hook_functional_stdout" "$hook_functional_relay_pair_ready_output"; do
        private_file_is_safe "$hook_functional_stderr" || return 1
        if [ -s "$hook_functional_stderr" ] \
            || ! kill -0 "$hook_functional_probe_pid" 2>/dev/null; then
            observe_functional_probe_failure \
                "$hook_functional_probe_pid" "$hook_functional_stderr" || return 1
            return 1
        fi
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 300 ] || return 1
        sleep 0.05
    done

    advance_start_failure_stage functional-exit-cleanup || return 1
    hook_functional_wait_attempt=0
    while ! worker_process_fd_is_retired 8; do
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" = \
        "$hook_functional_exit_process_identity" ] || return 1
    worker_wireguard_is_absent \
        7 "$hook_functional_exit_peer_address" || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/7 2>/dev/null)" = \
        "$hook_functional_exit_worker_namespace" ] || return 1
    command exec 8>&- || return 1
    [ ! -e /proc/self/fd/8 ] && [ ! -L /proc/self/fd/8 ] || return 1
    command exec 7>&- || return 1
    [ ! -e /proc/self/fd/7 ] && [ ! -L /proc/self/fd/7 ] || return 1

    advance_start_failure_stage functional-relay-pair-ready || return 1
    running_identity_is_unchanged \
        "$hook_functional_unit" \
        "$proof_directory/unit.identity" \
        "$hook_functional_agent_gid" || return 1
    socket_identity_is_unchanged \
        "$proof_directory/socket.identity" "$hook_functional_agent_gid" || return 1
    unit_fdstore_is_empty "$hook_functional_unit" || return 1

    advance_start_failure_stage functional-relay-pair-worker-observation || return 1
    hook_functional_pair_worker_pid=$(direct_helper_child \
        "$hook_functional_main_pid") || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_pair_worker_pid" || return 1
    hook_functional_pair_pidfd_count=$hook_custody_pidfd_count
    hook_functional_pair_pidfd_identity=$hook_custody_pidfd_identity
    hook_functional_pair_process_count=$hook_custody_process_count
    hook_functional_pair_namespace_count=$hook_custody_namespace_count
    hook_functional_pair_parent_namespace=$hook_custody_parent_namespace
    hook_functional_pair_process_parent_fd=$hook_custody_process_fd
    hook_functional_pair_process_identity=$hook_custody_process_identity
    hook_functional_pair_namespace_parent_fd=$hook_custody_namespace_fd
    hook_functional_pair_worker_namespace=$hook_custody_namespace_identity
    # As above, retired numeric identities may be reused. Bind this generation
    # to its live parent-held descriptors instead of stale observations.
    [ "$hook_functional_pair_parent_namespace" = \
        "$hook_functional_parent_namespace" ] \
        && [ "$hook_functional_pair_parent_namespace" != \
            "$hook_functional_pair_worker_namespace" ] || return 1
    hook_functional_pair_parent_process_path=/proc/$hook_functional_main_pid/fd/$hook_functional_pair_process_parent_fd
    hook_functional_pair_parent_namespace_path=/proc/$hook_functional_main_pid/fd/$hook_functional_pair_namespace_parent_fd
    [ "$(capture_parent_process_fd_identity \
        "$hook_functional_main_pid" "$hook_functional_pair_process_parent_fd" \
        "$hook_functional_pair_worker_pid")" = \
        "$hook_functional_pair_process_identity" ] || return 1
    [ "$(capture_parent_namespace_fd_identity \
        "$hook_functional_main_pid" "$hook_functional_pair_namespace_parent_fd")" = \
        "$hook_functional_pair_worker_namespace" ] || return 1
    command exec 7<"$hook_functional_pair_parent_namespace_path" || return 1
    command exec 8<"$hook_functional_pair_parent_process_path" || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/7 2>/dev/null)" = \
        "$hook_functional_pair_worker_namespace" ] || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" = \
        "$hook_functional_pair_process_identity" ] || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_pair_worker_pid" || return 1
    [ "$hook_custody_pidfd_count" = "$hook_functional_pair_pidfd_count" ] \
        && [ "$hook_custody_pidfd_identity" = \
            "$hook_functional_pair_pidfd_identity" ] \
        && [ "$hook_custody_process_count" = \
            "$hook_functional_pair_process_count" ] \
        && [ "$hook_custody_namespace_count" = \
            "$hook_functional_pair_namespace_count" ] \
        && [ "$hook_custody_process_fd" = \
            "$hook_functional_pair_process_parent_fd" ] \
        && [ "$hook_custody_process_identity" = \
            "$hook_functional_pair_process_identity" ] \
        && [ "$hook_custody_namespace_fd" = \
            "$hook_functional_pair_namespace_parent_fd" ] \
        && [ "$hook_custody_namespace_identity" = \
            "$hook_functional_pair_worker_namespace" ] || return 1
    hook_functional_pair_worker_starttime=$(worker_identity_from_process_fd \
        8 "$hook_functional_pair_worker_pid" "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" "$hook_functional_worker_gid" \
        "$hook_functional_parent_filters") || return 1

    hook_functional_pair_interfaces=$(worker_relay_pair_interfaces 7) || return 1
    hook_functional_pair_relay_client_interface=$(printf '%s\n' \
        "$hook_functional_pair_interfaces" \
        | /usr/bin/awk -F '\t' 'NF == 2 { records++; value = $1 }
            END { if (records != 1) exit 1; print value }') || return 1
    hook_functional_pair_relay_exit_interface=$(printf '%s\n' \
        "$hook_functional_pair_interfaces" \
        | /usr/bin/awk -F '\t' 'NF == 2 { records++; value = $2 }
            END { if (records != 1) exit 1; print value }') || return 1
    hook_functional_pair_client_peer_address=$(worker_relay_pair_address \
        7 "$hook_functional_pair_relay_client_interface" 0002 0001) || return 1
    hook_functional_pair_client_local_address=$(worker_relay_pair_address \
        7 "$hook_functional_pair_relay_client_interface" 0002 0002) || return 1
    hook_functional_pair_exit_local_address=$(worker_relay_pair_address \
        7 "$hook_functional_pair_relay_exit_interface" 0003 0003) || return 1
    hook_functional_pair_exit_peer_address=$(worker_relay_pair_address \
        7 "$hook_functional_pair_relay_exit_interface" 0003 0004) || return 1
    hook_functional_pair_prefix=${hook_functional_pair_client_local_address%:*}
    [ "$hook_functional_pair_prefix" = \
        "${hook_functional_pair_client_peer_address%:*}" ] \
        && [ "$hook_functional_pair_prefix" = \
            "${hook_functional_pair_exit_local_address%:*}" ] \
        && [ "$hook_functional_pair_prefix" = \
            "${hook_functional_pair_exit_peer_address%:*}" ] \
        && [ "$hook_functional_pair_client_peer_address" != \
            "$hook_functional_pair_client_local_address" ] \
        && [ "$hook_functional_pair_client_peer_address" != \
            "$hook_functional_pair_exit_local_address" ] \
        && [ "$hook_functional_pair_client_peer_address" != \
            "$hook_functional_pair_exit_peer_address" ] \
        && [ "$hook_functional_pair_client_local_address" != \
            "$hook_functional_pair_exit_local_address" ] \
        && [ "$hook_functional_pair_client_local_address" != \
            "$hook_functional_pair_exit_peer_address" ] \
        && [ "$hook_functional_pair_exit_local_address" != \
            "$hook_functional_pair_exit_peer_address" ] || return 1

    hook_functional_pair_client_public_key=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_pair_relay_client_interface" \
            public-key 2>/dev/null) || return 1
    hook_functional_pair_exit_public_key=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_pair_relay_exit_interface" \
            public-key 2>/dev/null) || return 1
    for hook_functional_pair_public_key in \
        "$hook_functional_pair_client_public_key" \
        "$hook_functional_pair_exit_public_key"; do
        case $hook_functional_pair_public_key in
            ''|'(none)'|*[!A-Za-z0-9+/=]*) return 1 ;;
        esac
        [ "${#hook_functional_pair_public_key}" -eq 44 ] \
            && [ "$hook_functional_pair_public_key" != \
                "$functional_relay_public_key" ] \
            && [ "$hook_functional_pair_public_key" != \
                "$functional_exit_relay_public_key" ] || return 1
    done
    [ "$hook_functional_pair_client_public_key" != \
        "$hook_functional_pair_exit_public_key" ] || return 1
    hook_functional_pair_client_listen_port=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_pair_relay_client_interface" \
            listen-port 2>/dev/null) || return 1
    hook_functional_pair_exit_listen_port=$(/usr/bin/nsenter \
        --net=/proc/self/fd/7 -- \
        /usr/bin/wg show "$hook_functional_pair_relay_exit_interface" \
            listen-port 2>/dev/null) || return 1
    for hook_functional_pair_listen_port in \
        "$hook_functional_pair_client_listen_port" \
        "$hook_functional_pair_exit_listen_port"; do
        number_is_safe "$hook_functional_pair_listen_port" \
            && [ "$hook_functional_pair_listen_port" -le 65535 ] \
            && [ "$hook_functional_pair_listen_port" -ne \
                "$functional_relay_listen_port" ] \
            && [ "$hook_functional_pair_listen_port" -ne \
                "$functional_exit_relay_listen_port" ] || return 1
    done
    [ "$hook_functional_pair_client_listen_port" != \
        "$hook_functional_pair_exit_listen_port" ] || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_pair_relay_client_interface" \
        "$hook_functional_pair_client_peer_address" \
        "$functional_peer_public_key" "$functional_peer_endpoint" || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_pair_relay_exit_interface" \
        "$hook_functional_pair_exit_peer_address" \
        "$functional_exit_peer_public_key" \
        "$functional_exit_peer_endpoint" || return 1
    hook_functional_pair_client_baseline=$(worker_wireguard_snapshot \
        7 "$hook_functional_pair_relay_client_interface" \
        "$functional_relay_public_key") || return 1
    hook_functional_pair_exit_baseline=$(worker_wireguard_snapshot \
        7 "$hook_functional_pair_relay_exit_interface" \
        "$functional_exit_relay_public_key") || return 1

    advance_start_failure_stage functional-relay-pair-fixtures || return 1
    create_functional_relay_pair_fixtures \
        "$hook_functional_pair_client_public_key" \
        "$hook_functional_pair_client_listen_port" \
        "$hook_functional_pair_client_local_address" \
        "$hook_functional_pair_client_peer_address" \
        "$hook_functional_pair_exit_public_key" \
        "$hook_functional_pair_exit_listen_port" \
        "$hook_functional_pair_exit_local_address" \
        "$hook_functional_pair_exit_peer_address" || return 1
    hook_functional_pair_relay_client_baseline=$( \
        functional_relay_pair_client_wireguard_snapshot \
        "$hook_functional_pair_client_public_key") || return 1
    hook_functional_pair_relay_exit_baseline=$( \
        functional_relay_pair_exit_wireguard_snapshot \
        "$hook_functional_pair_exit_public_key") || return 1

    advance_start_failure_stage functional-relay-pair-traffic || return 1
    functional_peer_keeper_is_exact \
        "$functional_pair_client_keeper_pid" \
        "$functional_pair_client_keeper_starttime" \
        "$functional_pair_client_namespace_identity" || return 1
    /usr/bin/nsenter \
        --net="/proc/$functional_pair_client_keeper_pid/ns/net" -- \
        /usr/bin/ping -6 -n -I "$functional_relay" -c 1 -W 3 \
            "$hook_functional_pair_exit_peer_address" \
            >/dev/null 2>&1 || return 1
    hook_functional_wait_attempt=0
    while :; do
        hook_functional_pair_client_current=$(worker_wireguard_snapshot \
            7 "$hook_functional_pair_relay_client_interface" \
            "$functional_relay_public_key") || return 1
        hook_functional_pair_exit_current=$(worker_wireguard_snapshot \
            7 "$hook_functional_pair_relay_exit_interface" \
            "$functional_exit_relay_public_key") || return 1
        hook_functional_pair_relay_client_current=$( \
            functional_relay_pair_client_wireguard_snapshot \
            "$hook_functional_pair_client_public_key") || return 1
        hook_functional_pair_relay_exit_current=$( \
            functional_relay_pair_exit_wireguard_snapshot \
            "$hook_functional_pair_exit_public_key") || return 1
        if wireguard_snapshot_has_growth \
            "$hook_functional_pair_client_baseline" \
            "$hook_functional_pair_client_current" \
            && wireguard_snapshot_has_growth \
                "$hook_functional_pair_exit_baseline" \
                "$hook_functional_pair_exit_current" \
            && wireguard_snapshot_has_growth \
                "$hook_functional_pair_relay_client_baseline" \
                "$hook_functional_pair_relay_client_current" \
            && wireguard_snapshot_has_growth \
                "$hook_functional_pair_relay_exit_baseline" \
                "$hook_functional_pair_relay_exit_current"; then
            break
        fi
        hook_functional_wait_attempt=$((hook_functional_wait_attempt + 1))
        [ "$hook_functional_wait_attempt" -lt 100 ] || return 1
        sleep 0.05
    done
    functional_relay_pair_fixtures_are_exact || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_pair_relay_client_interface" \
        "$hook_functional_pair_client_peer_address" \
        "$functional_peer_public_key" "$functional_peer_endpoint" || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_pair_relay_exit_interface" \
        "$hook_functional_pair_exit_peer_address" \
        "$functional_exit_peer_public_key" \
        "$functional_exit_peer_endpoint" || return 1

    advance_start_failure_stage functional-relay-pair-cleanup || return 1
    # shellcheck disable=SC2119
    remove_functional_relay_pair_fixtures || return 1
    functional_relay_pair_fixtures_are_absent || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_pair_relay_client_interface" \
        "$hook_functional_pair_client_peer_address" \
        "$functional_peer_public_key" "$functional_peer_endpoint" || return 1
    worker_activated_wireguard_is_exact \
        7 "$hook_functional_pair_relay_exit_interface" \
        "$hook_functional_pair_exit_peer_address" \
        "$functional_exit_peer_public_key" \
        "$functional_exit_peer_endpoint" || return 1
    hook_functional_pair_client_retained=$(worker_wireguard_snapshot \
        7 "$hook_functional_pair_relay_client_interface" \
        "$functional_relay_public_key") || return 1
    hook_functional_pair_exit_retained=$(worker_wireguard_snapshot \
        7 "$hook_functional_pair_relay_exit_interface" \
        "$functional_exit_relay_public_key") || return 1
    wireguard_snapshot_has_growth \
        "$hook_functional_pair_client_baseline" \
        "$hook_functional_pair_client_retained" || return 1
    wireguard_snapshot_has_growth \
        "$hook_functional_pair_exit_baseline" \
        "$hook_functional_pair_exit_retained" || return 1
    [ "$(worker_identity_from_process_fd \
        8 "$hook_functional_pair_worker_pid" "$hook_functional_main_pid" \
        "$hook_functional_worker_uid" "$hook_functional_worker_gid" \
        "$hook_functional_parent_filters")" = \
        "$hook_functional_pair_worker_starttime" ] || return 1
    capture_parent_worker_custody \
        "$hook_functional_main_pid" "$hook_functional_pair_worker_pid" || return 1
    [ "$hook_custody_pidfd_count" = "$hook_functional_pair_pidfd_count" ] \
        && [ "$hook_custody_pidfd_identity" = \
            "$hook_functional_pair_pidfd_identity" ] \
        && [ "$hook_custody_process_count" = \
            "$hook_functional_pair_process_count" ] \
        && [ "$hook_custody_namespace_count" = \
            "$hook_functional_pair_namespace_count" ] \
        && [ "$hook_custody_process_fd" = \
            "$hook_functional_pair_process_parent_fd" ] \
        && [ "$hook_custody_process_identity" = \
            "$hook_functional_pair_process_identity" ] \
        && [ "$hook_custody_namespace_fd" = \
            "$hook_functional_pair_namespace_parent_fd" ] \
        && [ "$hook_custody_namespace_identity" = \
            "$hook_functional_pair_worker_namespace" ] || return 1

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
    if [ "$hook_functional_probe_status" -ne 0 ]; then
        publish_functional_probe_failure \
            "$hook_functional_probe_status" "$hook_functional_stderr" || return 1
        return 1
    fi
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
        "$hook_functional_pair_process_identity" ] || return 1
    helper_holds_no_worker_custody "$hook_functional_main_pid" || return 1
    worker_wireguard_is_absent \
        7 "$hook_functional_pair_client_peer_address" || return 1
    worker_wireguard_is_absent \
        7 "$hook_functional_pair_exit_peer_address" || return 1
    [ "$(stat -Lc '%d:%i' /proc/self/fd/7 2>/dev/null)" = \
        "$hook_functional_pair_worker_namespace" ] || return 1
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
        || fail 'sequential Client/Exit and simultaneous Relay-pair live proof failed'

    advance_start_failure_stage publication \
        || fail 'start failure stage transition is invalid'
    hook_start_pass=$(printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
        'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
        "$functional_ready_record" \
        "$functional_activated_kernel_record" \
        "$functional_committed_kernel_record" \
        "$functional_pass_record" \
        "$functional_cleanup_record" \
        "$functional_exit_ready_record" \
        "$functional_exit_activated_kernel_record" \
        "$functional_exit_committed_kernel_record" \
        "$functional_exit_pass_record" \
        "$functional_exit_cleanup_record" \
        "$functional_relay_pair_ready_record" \
        "$functional_relay_pair_activated_kernel_record" \
        "$functional_relay_pair_committed_kernel_record" \
        "$functional_relay_pair_pass_record" \
        "$functional_relay_pair_cleanup_record")
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
