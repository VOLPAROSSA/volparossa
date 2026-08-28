#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Root-only capture primitives shared by the live gate and its unprivileged contract test.

# The caller must set these to the owner of its validated private capture directory.
: "${VP_CAPTURE_OWNER_UID:?VP_CAPTURE_OWNER_UID must be set}"
: "${VP_CAPTURE_OWNER_GID:?VP_CAPTURE_OWNER_GID must be set}"

vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    vp_capture_checked_path=$1
    [ -f "$vp_capture_checked_path" ] && [ ! -L "$vp_capture_checked_path" ] || return 1
    # GNU stat labels a zero-length regular file "regular empty file" with %F.
    # Use the numeric mode instead: 0x8000 (S_IFREG) | 0600 is exactly 0x8180,
    # independently of whether the capture has content.
    vp_capture_checked_metadata=$(stat -Lc '%f:%u:%g:%a:%h' \
        "$vp_capture_checked_path") || return 1
    [ "$vp_capture_checked_metadata" = \
        "8180:$VP_CAPTURE_OWNER_UID:$VP_CAPTURE_OWNER_GID:600:1" ]
}

vp_capture_remove_failed_output() {
    [ "$#" -eq 1 ] || return 1
    vp_capture_failed_path=$1
    case $vp_capture_failed_path in
        ''|/|.|..) return 1 ;;
    esac
    rm -f -- "$vp_capture_failed_path"
}

# Capture a producer without a pipeline. Partial output is removed on any error.
vp_capture_run() {
    [ "$#" -ge 2 ] || return 1
    vp_capture_run_output=$1
    shift
    : >"$vp_capture_run_output" || return 1
    chmod 0600 "$vp_capture_run_output" || {
        vp_capture_remove_failed_output "$vp_capture_run_output" || true
        return 1
    }
    if ! "$@" >"$vp_capture_run_output"; then
        vp_capture_remove_failed_output "$vp_capture_run_output" || true
        return 1
    fi
    if ! vp_capture_file_is_safe "$vp_capture_run_output"; then
        vp_capture_remove_failed_output "$vp_capture_run_output" || true
        return 1
    fi
}

# Normalize one validated capture without a pipeline. Partial normalized output
# is removed if the parser or its output validation fails.
vp_capture_normalize() {
    [ "$#" -ge 3 ] || return 1
    vp_capture_normalize_input=$1
    vp_capture_normalize_output=$2
    shift 2
    vp_capture_file_is_safe "$vp_capture_normalize_input" || return 1
    : >"$vp_capture_normalize_output" || return 1
    chmod 0600 "$vp_capture_normalize_output" || {
        vp_capture_remove_failed_output "$vp_capture_normalize_output" || true
        return 1
    }
    if ! "$@" <"$vp_capture_normalize_input" >"$vp_capture_normalize_output"; then
        vp_capture_remove_failed_output "$vp_capture_normalize_output" || true
        return 1
    fi
    if ! vp_capture_file_is_safe "$vp_capture_normalize_output"; then
        vp_capture_remove_failed_output "$vp_capture_normalize_output" || true
        return 1
    fi
}

vp_capture_checksum_from_line() {
    [ "$#" -eq 1 ] || return 1
    vp_capture_checksum=${1%% *}
    case $vp_capture_checksum in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    [ "${#vp_capture_checksum}" -eq 64 ] || return 1
    printf '%s\n' "$vp_capture_checksum"
}

vp_capture_sha256_file() {
    [ "$#" -eq 1 ] || return 1
    vp_capture_digest_path=$1
    [ -f "$vp_capture_digest_path" ] && [ ! -L "$vp_capture_digest_path" ] || return 1
    vp_capture_checksum_line=$(sha256sum "$vp_capture_digest_path") || return 1
    vp_capture_checksum_from_line "$vp_capture_checksum_line"
}

vp_capture_sha256() {
    [ "$#" -eq 1 ] || return 1
    vp_capture_file_is_safe "$1" || return 1
    vp_capture_sha256_file "$1"
}

# Hash only a validated capture and publish only that digest in another
# validated private file.
vp_capture_publish_digest() {
    [ "$#" -eq 2 ] || return 1
    vp_capture_digest_input=$1
    vp_capture_digest_output=$2
    vp_capture_published_digest=$(vp_capture_sha256 "$vp_capture_digest_input") || return 1
    : >"$vp_capture_digest_output" || return 1
    chmod 0600 "$vp_capture_digest_output" || {
        vp_capture_remove_failed_output "$vp_capture_digest_output" || true
        return 1
    }
    if ! printf '%s\n' "$vp_capture_published_digest" >"$vp_capture_digest_output"; then
        vp_capture_remove_failed_output "$vp_capture_digest_output" || true
        return 1
    fi
    if ! vp_capture_file_is_safe "$vp_capture_digest_output"; then
        vp_capture_remove_failed_output "$vp_capture_digest_output" || true
        return 1
    fi
}

# Stream a secret-bearing producer through a validated 0600 FIFO into a
# separately supervised SHA-256 consumer. Neither raw input nor partial digest
# output survives a producer, consumer, wait, metadata, or parse failure.
vp_capture_stream_sha256() {
    [ "$#" -ge 3 ] || return 1
    vp_capture_fifo=$1
    vp_capture_stream_output=$2
    shift 2
    [ ! -e "$vp_capture_fifo" ] && [ ! -L "$vp_capture_fifo" ] || return 1
    [ ! -e "$vp_capture_stream_output" ] && [ ! -L "$vp_capture_stream_output" ] || return 1
    if ! mkfifo -m 0600 "$vp_capture_fifo"; then
        return 1
    fi
    vp_capture_fifo_metadata=$(stat -Lc '%F:%u:%g:%a:%h' "$vp_capture_fifo") || {
        vp_capture_remove_failed_output "$vp_capture_fifo" || true
        return 1
    }
    if [ "$vp_capture_fifo_metadata" != \
        "fifo:$VP_CAPTURE_OWNER_UID:$VP_CAPTURE_OWNER_GID:600:1" ]; then
        vp_capture_remove_failed_output "$vp_capture_fifo" || true
        return 1
    fi

    vp_capture_consumer_output=$vp_capture_stream_output.consumer
    : >"$vp_capture_consumer_output" || {
        vp_capture_remove_failed_output "$vp_capture_fifo" || true
        return 1
    }
    chmod 0600 "$vp_capture_consumer_output" || {
        vp_capture_remove_failed_output "$vp_capture_fifo" || true
        vp_capture_remove_failed_output "$vp_capture_consumer_output" || true
        return 1
    }
    sha256sum <"$vp_capture_fifo" >"$vp_capture_consumer_output" &
    vp_capture_consumer_pid=$!
    if "$@" >"$vp_capture_fifo"; then
        vp_capture_producer_status=0
    else
        vp_capture_producer_status=$?
    fi
    if wait "$vp_capture_consumer_pid"; then
        vp_capture_consumer_status=0
    else
        vp_capture_consumer_status=$?
    fi
    vp_capture_remove_failed_output "$vp_capture_fifo" || {
        vp_capture_remove_failed_output "$vp_capture_consumer_output" || true
        return 1
    }
    if [ "$vp_capture_producer_status" -ne 0 ] \
        || [ "$vp_capture_consumer_status" -ne 0 ] \
        || ! vp_capture_file_is_safe "$vp_capture_consumer_output"; then
        vp_capture_remove_failed_output "$vp_capture_consumer_output" || true
        return 1
    fi
    vp_capture_stream_line=$(cat "$vp_capture_consumer_output") || {
        vp_capture_remove_failed_output "$vp_capture_consumer_output" || true
        return 1
    }
    vp_capture_stream_digest=$(vp_capture_checksum_from_line "$vp_capture_stream_line") || {
        vp_capture_remove_failed_output "$vp_capture_consumer_output" || true
        return 1
    }
    vp_capture_remove_failed_output "$vp_capture_consumer_output" || return 1

    : >"$vp_capture_stream_output" || return 1
    chmod 0600 "$vp_capture_stream_output" || {
        vp_capture_remove_failed_output "$vp_capture_stream_output" || true
        return 1
    }
    if ! printf '%s\n' "$vp_capture_stream_digest" >"$vp_capture_stream_output"; then
        vp_capture_remove_failed_output "$vp_capture_stream_output" || true
        return 1
    fi
    if ! vp_capture_file_is_safe "$vp_capture_stream_output"; then
        vp_capture_remove_failed_output "$vp_capture_stream_output" || true
        return 1
    fi
}

vp_capture_mode_is_not_group_or_world_writable() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        [0-7][0-7][0-7]) ;;
        *) return 1 ;;
    esac
    case $1 in
        ?[2367]?|??[2367]) return 1 ;;
        *) return 0 ;;
    esac
}

vp_capture_resolver_reject() {
    [ "$#" -eq 1 ] || return 1
    case $1 in
        authority-config|object-metadata|resolved-path|target-owner-class|target-metadata|\
            parent-owner-class|parent-metadata|object-drift|target-drift|runtime-drift|\
            snapshot-drift)
            vp_resolver_rejection=$1
            ;;
        *) vp_resolver_rejection=internal ;;
    esac
    if [ "${VP_CAPTURE_RESOLVER_DIAGNOSTICS:-no}" = yes ]; then
        printf 'resolver capture rejected: %s\n' "$vp_resolver_rejection" >&2
    fi
    return 1
}

vp_capture_resolver_authority_is_valid() {
    [ "$#" -eq 3 ] || return 1
    vp_resolver_runtime_directory=$1
    vp_resolver_runtime_uid=$2
    vp_resolver_runtime_gid=$3
    case $vp_resolver_runtime_directory in
        /*) ;;
        *) return 1 ;;
    esac
    case $vp_resolver_runtime_directory in
        /|*/|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./@+-]*) return 1 ;;
    esac
    case $vp_resolver_runtime_uid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    case $vp_resolver_runtime_gid in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    if [ ! -d "$vp_resolver_runtime_directory" ] \
        || [ -L "$vp_resolver_runtime_directory" ]; then
        return 1
    fi
    [ "$(stat -Lc '%F:%u:%g:%a' "$vp_resolver_runtime_directory" 2>/dev/null)" = \
        "directory:$vp_resolver_runtime_uid:$vp_resolver_runtime_gid:755" ] || return 1
}

vp_capture_resolver_target_is_managed() {
    [ "$#" -eq 2 ] || return 1
    case $1 in
        "$2/stub-resolv.conf"|"$2/resolv.conf") return 0 ;;
        *) return 1 ;;
    esac
}

vp_capture_resolver_parent_chain_is_safe() {
    [ "$#" -eq 4 ] || return 1
    vp_capture_resolver_authority_is_valid "$2" "$3" "$4" \
        || { vp_capture_resolver_reject authority-config; return 1; }
    vp_resolver_runtime_directory=$2
    vp_resolver_runtime_uid=$3
    vp_resolver_runtime_gid=$4
    vp_resolver_parent=${1%/*}
    [ -n "$vp_resolver_parent" ] || vp_resolver_parent=/
    while :; do
        if [ ! -d "$vp_resolver_parent" ] || [ -L "$vp_resolver_parent" ]; then
            vp_capture_resolver_reject parent-metadata
            return 1
        fi
        vp_resolver_parent_metadata=$(stat -Lc '%F:%u:%g:%a' \
            "$vp_resolver_parent") \
            || { vp_capture_resolver_reject parent-metadata; return 1; }
        if [ "$vp_resolver_parent" = "$vp_resolver_runtime_directory" ]; then
            [ "$vp_resolver_parent_metadata" = \
                "directory:$vp_resolver_runtime_uid:$vp_resolver_runtime_gid:755" ] \
                || { vp_capture_resolver_reject parent-owner-class; return 1; }
        elif [ "$vp_resolver_parent_metadata" = 'directory:0:0:1777' ]; then
            :
        else
            vp_resolver_parent_type=${vp_resolver_parent_metadata%%:*}
            vp_resolver_parent_fields=${vp_resolver_parent_metadata#*:}
            vp_resolver_parent_uid=${vp_resolver_parent_fields%%:*}
            vp_resolver_parent_fields=${vp_resolver_parent_fields#*:}
            vp_resolver_parent_gid=${vp_resolver_parent_fields%%:*}
            vp_resolver_parent_mode=${vp_resolver_parent_fields##*:}
            [ "$vp_resolver_parent_type" = directory ] \
                || { vp_capture_resolver_reject parent-metadata; return 1; }
            case "$vp_resolver_parent_uid:$vp_resolver_parent_gid" in
                0:0|"$VP_CAPTURE_OWNER_UID:$VP_CAPTURE_OWNER_GID") ;;
                *) vp_capture_resolver_reject parent-owner-class; return 1 ;;
            esac
            vp_capture_mode_is_not_group_or_world_writable "$vp_resolver_parent_mode" \
                || { vp_capture_resolver_reject parent-metadata; return 1; }
        fi
        [ "$vp_resolver_parent" != / ] || break
        vp_resolver_parent=${vp_resolver_parent%/*}
        [ -n "$vp_resolver_parent" ] || vp_resolver_parent=/
    done
}

vp_capture_resolver_target_is_safe() {
    [ "$#" -eq 4 ] || return 1
    vp_capture_resolver_authority_is_valid "$2" "$3" "$4" \
        || { vp_capture_resolver_reject authority-config; return 1; }
    vp_resolver_target=$1
    vp_resolver_runtime_directory=$2
    vp_resolver_runtime_uid=$3
    vp_resolver_runtime_gid=$4
    case $vp_resolver_target in
        /*) ;;
        *) vp_capture_resolver_reject resolved-path; return 1 ;;
    esac
    case $vp_resolver_target in
        *[!A-Za-z0-9_./@+-]*) vp_capture_resolver_reject resolved-path; return 1 ;;
    esac
    if [ ! -f "$vp_resolver_target" ] || [ -L "$vp_resolver_target" ]; then
        vp_capture_resolver_reject target-metadata
        return 1
    fi
    vp_resolver_target_metadata=$(stat -Lc '%F:%u:%g:%a:%h:%s' \
        "$vp_resolver_target") \
        || { vp_capture_resolver_reject target-metadata; return 1; }
    vp_resolver_saved_ifs=$IFS
    IFS=:
    # The fixed stat serialization contains no glob metacharacters.
    # shellcheck disable=SC2086
    set -- $vp_resolver_target_metadata
    IFS=$vp_resolver_saved_ifs
    if [ "$#" -ne 6 ] || [ "$1" != 'regular file' ]; then
        vp_capture_resolver_reject target-metadata
        return 1
    fi
    vp_resolver_target_uid=$2
    vp_resolver_target_gid=$3
    vp_resolver_target_mode=$4
    vp_resolver_target_links=$5
    vp_resolver_target_size=$6
    if vp_capture_resolver_target_is_managed \
        "$vp_resolver_target" "$vp_resolver_runtime_directory"; then
        [ "$vp_resolver_target_uid:$vp_resolver_target_gid:$vp_resolver_target_mode" = \
            "$vp_resolver_runtime_uid:$vp_resolver_runtime_gid:644" ] \
            || { vp_capture_resolver_reject target-owner-class; return 1; }
    else
        [ "$vp_resolver_target_uid:$vp_resolver_target_gid" = \
            "$VP_CAPTURE_OWNER_UID:$VP_CAPTURE_OWNER_GID" ] \
            || { vp_capture_resolver_reject target-owner-class; return 1; }
        vp_capture_mode_is_not_group_or_world_writable "$vp_resolver_target_mode" \
            || { vp_capture_resolver_reject target-metadata; return 1; }
    fi
    vp_resolver_owner_digit=${vp_resolver_target_mode%??}
    case $vp_resolver_owner_digit in
        4|5|6|7) ;;
        *) vp_capture_resolver_reject target-metadata; return 1 ;;
    esac
    [ "$vp_resolver_target_links" = 1 ] \
        || { vp_capture_resolver_reject target-metadata; return 1; }
    case $vp_resolver_target_size in
        ''|*[!0-9]*) vp_capture_resolver_reject target-metadata; return 1 ;;
    esac
    [ "$vp_resolver_target_size" -le 65536 ] \
        || { vp_capture_resolver_reject target-metadata; return 1; }
    vp_capture_resolver_parent_chain_is_safe "$vp_resolver_target" \
        "$vp_resolver_runtime_directory" "$vp_resolver_runtime_uid" \
        "$vp_resolver_runtime_gid"
}

vp_capture_resolver_target_is_allowed() {
    [ "$#" -eq 2 ] || return 1
    vp_resolver_allowed_target=$1
    vp_resolver_allowed_roots=$2
    for vp_resolver_allowed_root in $vp_resolver_allowed_roots; do
        case $vp_resolver_allowed_root in
            /*) ;;
            *) return 1 ;;
        esac
        case $vp_resolver_allowed_target in
            "$vp_resolver_allowed_root"|"$vp_resolver_allowed_root"/*) return 0 ;;
        esac
    done
    return 1
}

vp_capture_resolver_observation() {
    [ "$#" -eq 5 ] || return 1
    vp_resolver_path=$1
    vp_resolver_roots=$2
    vp_resolver_runtime_directory=$3
    vp_resolver_runtime_uid=$4
    vp_resolver_runtime_gid=$5
    vp_capture_resolver_authority_is_valid "$vp_resolver_runtime_directory" \
        "$vp_resolver_runtime_uid" "$vp_resolver_runtime_gid" \
        || { vp_capture_resolver_reject authority-config; return 1; }
    case $vp_resolver_path in
        /*) ;;
        *) vp_capture_resolver_reject object-metadata; return 1 ;;
    esac
    case $vp_resolver_path in
        *[!A-Za-z0-9_./@+-]*) vp_capture_resolver_reject object-metadata; return 1 ;;
    esac
    vp_capture_resolver_parent_chain_is_safe "$vp_resolver_path" \
        "$vp_resolver_runtime_directory" "$vp_resolver_runtime_uid" \
        "$vp_resolver_runtime_gid" || return 1
    vp_resolver_runtime_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_runtime_directory") \
        || { vp_capture_resolver_reject parent-metadata; return 1; }
    vp_resolver_object_before=$(stat -c '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_path") \
        || { vp_capture_resolver_reject object-metadata; return 1; }
    vp_resolver_object_type=$(stat -c '%F' "$vp_resolver_path") \
        || { vp_capture_resolver_reject object-metadata; return 1; }
    case $vp_resolver_object_type in
        'regular file') vp_resolver_link_before=REGULAR ;;
        'symbolic link')
            vp_resolver_link_before=$(readlink -- "$vp_resolver_path") \
                || { vp_capture_resolver_reject object-metadata; return 1; }
            [ -n "$vp_resolver_link_before" ] \
                || { vp_capture_resolver_reject object-metadata; return 1; }
            ;;
        *) vp_capture_resolver_reject object-metadata; return 1 ;;
    esac
    vp_resolver_resolved_before=$(readlink -f -- "$vp_resolver_path") \
        || { vp_capture_resolver_reject resolved-path; return 1; }
    vp_capture_resolver_target_is_allowed "$vp_resolver_resolved_before" "$vp_resolver_roots" \
        || { vp_capture_resolver_reject resolved-path; return 1; }
    vp_capture_resolver_target_is_safe "$vp_resolver_resolved_before" \
        "$vp_resolver_runtime_directory" "$vp_resolver_runtime_uid" \
        "$vp_resolver_runtime_gid" || return 1
    vp_resolver_target_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_resolved_before") || return 1
    vp_resolver_digest_before=$(vp_capture_sha256_file "$vp_resolver_resolved_before") \
        || return 1
    vp_resolver_target_middle=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_resolved_before") || return 1
    vp_resolver_digest_after=$(vp_capture_sha256_file "$vp_resolver_resolved_before") \
        || return 1
    vp_resolver_target_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_resolved_before") || return 1
    vp_resolver_object_after=$(stat -c '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_path") || return 1
    vp_resolver_resolved_after=$(readlink -f -- "$vp_resolver_path") || return 1
    if [ "$vp_resolver_object_type" = 'symbolic link' ]; then
        vp_resolver_link_after=$(readlink -- "$vp_resolver_path") || return 1
    else
        vp_resolver_link_after=REGULAR
    fi
    if [ "$vp_resolver_object_before" != "$vp_resolver_object_after" ] \
        || [ "$vp_resolver_link_before" != "$vp_resolver_link_after" ] \
        || [ "$vp_resolver_resolved_before" != "$vp_resolver_resolved_after" ]; then
        vp_capture_resolver_reject object-drift
        return 1
    fi
    if [ "$vp_resolver_target_before" != "$vp_resolver_target_middle" ] \
        || [ "$vp_resolver_target_before" != "$vp_resolver_target_after" ] \
        || [ "$vp_resolver_digest_before" != "$vp_resolver_digest_after" ]; then
        vp_capture_resolver_reject target-drift
        return 1
    fi
    vp_capture_resolver_target_is_safe "$vp_resolver_resolved_after" \
        "$vp_resolver_runtime_directory" "$vp_resolver_runtime_uid" \
        "$vp_resolver_runtime_gid" || return 1
    vp_resolver_runtime_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' \
        "$vp_resolver_runtime_directory") \
        || { vp_capture_resolver_reject parent-metadata; return 1; }
    [ "$vp_resolver_runtime_before" = "$vp_resolver_runtime_after" ] \
        || { vp_capture_resolver_reject runtime-drift; return 1; }
    printf '%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$vp_resolver_object_before" \
        "$vp_resolver_link_before" \
        "$vp_resolver_resolved_before" \
        "$vp_resolver_target_before" \
        "$vp_resolver_digest_before" \
        "$vp_resolver_runtime_before"
}

vp_capture_resolver_snapshot_producer() {
    [ "$#" -eq 5 ] || return 1
    vp_resolver_first=$(vp_capture_resolver_observation "$1" "$2" "$3" "$4" "$5") \
        || return 1
    vp_resolver_second=$(vp_capture_resolver_observation "$1" "$2" "$3" "$4" "$5") \
        || return 1
    [ "$vp_resolver_first" = "$vp_resolver_second" ] \
        || { vp_capture_resolver_reject snapshot-drift; return 1; }
    printf '%s\n' "$vp_resolver_first"
}

vp_capture_resolver_snapshot() {
    [ "$#" -eq 6 ] || return 1
    vp_capture_run "$2" vp_capture_resolver_snapshot_producer \
        "$1" "$3" "$4" "$5" "$6"
}
