#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Pure naming and ownership contract for the disposable netns lifecycle runner.
#
# This file is sourced by callers. It deliberately installs no traps, changes no shell options,
# creates no files and deletes no objects. Public validators return 0 for a valid value, 1 for an
# invalid value and 64 for an invalid function invocation. Name helpers print exactly one name.

VP_LIFECYCLE_MANIFEST_MAGIC=VOLPAROSSA_NETNS_OWNERSHIP_V1
VP_LIFECYCLE_MANIFEST_MAX_BYTES=4096
VP_LIFECYCLE_MANIFEST_MAX_RECORDS=2

_vp_lifecycle_validate_u64() {
    [ "$#" -eq 1 ] || return 64
    [ -n "$1" ] || return 1
    case $1 in
        *[!0123456789]*|0|0*) return 1 ;;
    esac
    [ "${#1}" -le 20 ] || return 1
    [ "${#1}" -lt 20 ] && return 0

    LC_ALL=C awk -v value="$1" 'BEGIN {
        maximum = "18446744073709551615"
        for (position = 1; position <= 20; position++) {
            digit = substr(value, position, 1) + 0
            maximum_digit = substr(maximum, position, 1) + 0
            if (digit < maximum_digit) {
                exit 0
            }
            if (digit > maximum_digit) {
                exit 1
            }
        }
        exit 0
    }'
}

_vp_lifecycle_validate_uid() {
    [ "$#" -eq 1 ] || return 64
    case $1 in
        0) return 0 ;;
        '') return 1 ;;
    esac
    _vp_lifecycle_validate_u64 "$1"
}

_vp_lifecycle_validate_safe_namespace_name() {
    [ "$#" -eq 1 ] || return 64
    [ -n "$1" ] && [ "${#1}" -le 63 ] || return 1
    case $1 in
        [abcdefghijklmnopqrstuvwxyz0123456789]*) ;;
        *) return 1 ;;
    esac
    case $1 in
        *[!abcdefghijklmnopqrstuvwxyz0123456789.-]*|*..*|*.) return 1 ;;
    esac
}

_vp_lifecycle_private_file_identity() {
    [ "$#" -eq 3 ] || return 64
    _vp_lifecycle_private_path=$1
    _vp_lifecycle_private_limit=$2
    _vp_lifecycle_private_uid=$3

    _vp_lifecycle_validate_uid "$_vp_lifecycle_private_uid" || return 1
    case $_vp_lifecycle_private_limit in
        ''|*[!0123456789]*|0|0*) return 1 ;;
    esac
    [ ! -L "$_vp_lifecycle_private_path" ] || return 1
    [ -f "$_vp_lifecycle_private_path" ] || return 1

    _vp_lifecycle_private_metadata=$(LC_ALL=C stat -c '%d:%i:%u:%a:%s' -- \
        "$_vp_lifecycle_private_path") || return 1
    _vp_lifecycle_private_device=${_vp_lifecycle_private_metadata%%:*}
    _vp_lifecycle_private_rest=${_vp_lifecycle_private_metadata#*:}
    _vp_lifecycle_private_inode=${_vp_lifecycle_private_rest%%:*}
    _vp_lifecycle_private_rest=${_vp_lifecycle_private_rest#*:}
    _vp_lifecycle_private_actual_uid=${_vp_lifecycle_private_rest%%:*}
    _vp_lifecycle_private_rest=${_vp_lifecycle_private_rest#*:}
    _vp_lifecycle_private_mode=${_vp_lifecycle_private_rest%%:*}
    _vp_lifecycle_private_size=${_vp_lifecycle_private_rest#*:}

    case $_vp_lifecycle_private_size in
        *:*) return 1 ;;
    esac
    _vp_lifecycle_validate_u64 "$_vp_lifecycle_private_device" || return 1
    _vp_lifecycle_validate_u64 "$_vp_lifecycle_private_inode" || return 1
    _vp_lifecycle_validate_uid "$_vp_lifecycle_private_actual_uid" || return 1
    [ "$_vp_lifecycle_private_actual_uid" = "$_vp_lifecycle_private_uid" ] || return 1
    [ "$_vp_lifecycle_private_mode" = 600 ] || return 1
    case $_vp_lifecycle_private_size in
        ''|*[!0123456789]*) return 1 ;;
    esac
    [ "$_vp_lifecycle_private_size" -gt 0 ] || return 1
    [ "$_vp_lifecycle_private_size" -le "$_vp_lifecycle_private_limit" ] || return 1

    printf '%s:%s\n' "$_vp_lifecycle_private_device" "$_vp_lifecycle_private_inode"
}

_vp_lifecycle_private_file_sha256() {
    [ "$#" -eq 1 ] || return 64
    LC_ALL=C sha256sum -- "$1" | LC_ALL=C awk '
        NR == 1 && length($1) == 64 && $1 !~ /[^0123456789abcdef]/ {
            print $1
            accepted = 1
        }
        END {
            if (!accepted || NR != 1) {
                exit 1
            }
        }
    '
}

_vp_lifecycle_has_final_newline() {
    [ "$#" -eq 1 ] || return 64
    [ -s "$1" ] || return 1
    _vp_lifecycle_last_byte=$(LC_ALL=C tail -c 1 -- "$1" | \
        LC_ALL=C od -An -tuC | LC_ALL=C tr -d '[:space:]') || return 1
    [ "$_vp_lifecycle_last_byte" = 10 ]
}

# Validate one 128-bit lifecycle identifier in canonical lowercase hexadecimal notation.
vp_lifecycle_validate_run_id() {
    [ "$#" -eq 1 ] || return 64
    [ "${#1}" -eq 32 ] || return 1
    case $1 in
        *[!0123456789abcdef]*) return 1 ;;
    esac
}

# Print the deterministic namespace name for endpoint a or b.
vp_lifecycle_namespace_name() {
    [ "$#" -eq 2 ] || return 64
    vp_lifecycle_validate_run_id "$1" || return 1
    case $2 in
        a|b) ;;
        *) return 1 ;;
    esac
    printf 'vpl-%s-%s\n' "$1" "$2"
}

# Print one deterministic, IFNAMSIZ-safe underlay interface name for endpoint a or b.
vp_lifecycle_interface_name() {
    [ "$#" -eq 2 ] || return 64
    vp_lifecycle_validate_run_id "$1" || return 1
    case $2 in
        a|b) ;;
        *) return 1 ;;
    esac
    printf 'vp%s%.8s\n' "$2" "$1"
}

# Print the deterministic nftables table name for this isolated run.
vp_lifecycle_table_name() {
    [ "$#" -eq 1 ] || return 64
    vp_lifecycle_validate_run_id "$1" || return 1
    printf 'vpl_%s\n' "$1"
}

# Validate a namespace name as belonging to the supplied lifecycle run.
vp_lifecycle_validate_namespace_name() {
    [ "$#" -eq 2 ] || return 64
    vp_lifecycle_validate_run_id "$1" || return 1
    _vp_lifecycle_validate_safe_namespace_name "$2" || return 1
    case $2 in
        "vpl-$1-a"|"vpl-$1-b") ;;
        *) return 1 ;;
    esac
}

# Validate an exact, sorted, bounded V1 namespace ownership manifest.
#
# Canonical bytes:
#   VOLPAROSSA_NETNS_OWNERSHIP_V1
#   run_id=<thirty-two lowercase hex characters>
#   namespace<TAB><run-bound name><TAB><canonical device>:<canonical inode>
#   ...
#   END
#
# Usage: vp_lifecycle_validate_manifest FILE EXPECTED_RUN_ID EXPECTED_UID
vp_lifecycle_validate_manifest() {
    [ "$#" -eq 3 ] || return 64
    _vp_lifecycle_manifest_path=$1
    _vp_lifecycle_manifest_run_id=$2
    _vp_lifecycle_manifest_uid=$3
    vp_lifecycle_validate_run_id "$_vp_lifecycle_manifest_run_id" || return 1

    _vp_lifecycle_manifest_identity=$(
        _vp_lifecycle_private_file_identity \
            "$_vp_lifecycle_manifest_path" \
            "$VP_LIFECYCLE_MANIFEST_MAX_BYTES" \
            "$_vp_lifecycle_manifest_uid"
    ) || return 1
    _vp_lifecycle_manifest_sha256=$(
        _vp_lifecycle_private_file_sha256 "$_vp_lifecycle_manifest_path"
    ) || return 1
    _vp_lifecycle_has_final_newline "$_vp_lifecycle_manifest_path" || return 1

    LC_ALL=C awk \
        -v expected_run_id="$_vp_lifecycle_manifest_run_id" \
        -v expected_prefix="vpl-$_vp_lifecycle_manifest_run_id-" \
        -v magic="$VP_LIFECYCLE_MANIFEST_MAGIC" \
        -v maximum_records="$VP_LIFECYCLE_MANIFEST_MAX_RECORDS" '
        function canonical_u64(value, maximum, position, digit, maximum_digit) {
            if (value !~ /^[1-9][0-9]*$/ || length(value) > 20) {
                return 0
            }
            if (length(value) < 20) {
                return 1
            }
            maximum = "18446744073709551615"
            for (position = 1; position <= 20; position++) {
                digit = substr(value, position, 1) + 0
                maximum_digit = substr(maximum, position, 1) + 0
                if (digit < maximum_digit) {
                    return 1
                }
                if (digit > maximum_digit) {
                    return 0
                }
            }
            return 1
        }
        NR == 1 {
            if ($0 != magic) {
                invalid = 1
            }
            next
        }
        NR == 2 {
            if ($0 != "run_id=" expected_run_id) {
                invalid = 1
            }
            next
        }
        ended {
            invalid = 1
            next
        }
        $0 == "END" {
            ended = 1
            next
        }
        {
            if (split($0, fields, "\t") != 3 || fields[1] != "namespace") {
                invalid = 1
                next
            }
            name = fields[2]
            if (length(name) < length(expected_prefix) + 1 || length(name) > 63 ||
                substr(name, 1, length(expected_prefix)) != expected_prefix) {
                invalid = 1
                next
            }
            suffix = substr(name, length(expected_prefix) + 1)
            if (suffix != "a" && suffix != "b") {
                invalid = 1
                next
            }
            if (previous_name != "" && name <= previous_name) {
                invalid = 1
                next
            }
            if (split(fields[3], identity, ":") != 2 ||
                !canonical_u64(identity[1]) || !canonical_u64(identity[2])) {
                invalid = 1
                next
            }
            identity_key = identity[1] ":" identity[2]
            if (names[name] || identities[identity_key]) {
                invalid = 1
                next
            }
            names[name] = 1
            identities[identity_key] = 1
            previous_name = name
            records++
            if (records > maximum_records) {
                invalid = 1
            }
        }
        END {
            if (invalid || !ended || records < 1 || records > maximum_records) {
                exit 1
            }
            exit 0
        }
    ' "$_vp_lifecycle_manifest_path" || return 1

    _vp_lifecycle_manifest_identity_after=$(
        _vp_lifecycle_private_file_identity \
            "$_vp_lifecycle_manifest_path" \
            "$VP_LIFECYCLE_MANIFEST_MAX_BYTES" \
            "$_vp_lifecycle_manifest_uid"
    ) || return 1
    _vp_lifecycle_manifest_sha256_after=$(
        _vp_lifecycle_private_file_sha256 "$_vp_lifecycle_manifest_path"
    ) || return 1
    [ "$_vp_lifecycle_manifest_identity" = "$_vp_lifecycle_manifest_identity_after" ] &&
        [ "$_vp_lifecycle_manifest_sha256" = "$_vp_lifecycle_manifest_sha256_after" ]
}

# Print ABSENT, OWNED, FOREIGN or INVALID for one manifest-bound namespace mountpoint.
# This function performs file, lstat and stat observations only; it never removes or changes an
# object. The manifest must be owned by the current uid so a less-trusted caller cannot nominate
# another process's namespace.
#
# Usage: vp_lifecycle_ownership_decision MANIFEST MOUNT_ROOT NAME
vp_lifecycle_ownership_decision() {
    [ "$#" -eq 3 ] || return 64
    _vp_lifecycle_decision_manifest=$1
    _vp_lifecycle_mount_root=$2
    _vp_lifecycle_mount_name=$3

    _vp_lifecycle_decision_uid=$(LC_ALL=C id -u) || {
        printf '%s\n' INVALID
        return 0
    }
    _vp_lifecycle_validate_uid "$_vp_lifecycle_decision_uid" || {
        printf '%s\n' INVALID
        return 0
    }
    case $_vp_lifecycle_decision_manifest in
        /*) ;;
        *)
            printf '%s\n' INVALID
            return 0
            ;;
    esac
    _vp_lifecycle_canonical_manifest=$(LC_ALL=C readlink -f -- \
        "$_vp_lifecycle_decision_manifest") || {
        printf '%s\n' INVALID
        return 0
    }
    if [ "$_vp_lifecycle_canonical_manifest" != "$_vp_lifecycle_decision_manifest" ]; then
        printf '%s\n' INVALID
        return 0
    fi
    _vp_lifecycle_private_file_identity \
        "$_vp_lifecycle_decision_manifest" \
        "$VP_LIFECYCLE_MANIFEST_MAX_BYTES" \
        "$_vp_lifecycle_decision_uid" >/dev/null || {
        printf '%s\n' INVALID
        return 0
    }
    _vp_lifecycle_decision_run_id=$(LC_ALL=C sed -n '2s/^run_id=//p' -- \
        "$_vp_lifecycle_decision_manifest") || {
        printf '%s\n' INVALID
        return 0
    }
    if ! vp_lifecycle_validate_manifest \
        "$_vp_lifecycle_decision_manifest" \
        "$_vp_lifecycle_decision_run_id" \
        "$_vp_lifecycle_decision_uid"
    then
        printf '%s\n' INVALID
        return 0
    fi
    if ! vp_lifecycle_validate_namespace_name \
        "$_vp_lifecycle_decision_run_id" "$_vp_lifecycle_mount_name"
    then
        printf '%s\n' INVALID
        return 0
    fi

    _vp_lifecycle_decision_manifest_identity=$(
        _vp_lifecycle_private_file_identity \
            "$_vp_lifecycle_decision_manifest" \
            "$VP_LIFECYCLE_MANIFEST_MAX_BYTES" \
            "$_vp_lifecycle_decision_uid"
    ) || {
        printf '%s\n' INVALID
        return 0
    }
    _vp_lifecycle_decision_manifest_sha256=$(
        _vp_lifecycle_private_file_sha256 "$_vp_lifecycle_decision_manifest"
    ) || {
        printf '%s\n' INVALID
        return 0
    }
    _vp_lifecycle_expected_identity=$(LC_ALL=C awk \
        -F '\t' -v expected_name="$_vp_lifecycle_mount_name" '
        $1 == "namespace" && $2 == expected_name {
            print $3
            matches++
        }
        END {
            if (matches != 1) {
                exit 1
            }
        }
    ' "$_vp_lifecycle_decision_manifest") || {
        printf '%s\n' INVALID
        return 0
    }

    case $_vp_lifecycle_mount_root in
        /*) ;;
        *)
            printf '%s\n' INVALID
            return 0
            ;;
    esac
    if [ -L "$_vp_lifecycle_mount_root" ] || [ ! -d "$_vp_lifecycle_mount_root" ]; then
        printf '%s\n' INVALID
        return 0
    fi
    _vp_lifecycle_canonical_mount_root=$(LC_ALL=C readlink -f -- \
        "$_vp_lifecycle_mount_root") || {
        printf '%s\n' INVALID
        return 0
    }
    if [ "$_vp_lifecycle_canonical_mount_root" != "$_vp_lifecycle_mount_root" ]; then
        printf '%s\n' INVALID
        return 0
    fi

    _vp_lifecycle_mount_path=$_vp_lifecycle_mount_root/$_vp_lifecycle_mount_name
    if [ ! -e "$_vp_lifecycle_mount_path" ] && [ ! -L "$_vp_lifecycle_mount_path" ]; then
        _vp_lifecycle_decision=ABSENT
    elif [ -L "$_vp_lifecycle_mount_path" ] || [ ! -f "$_vp_lifecycle_mount_path" ]; then
        _vp_lifecycle_decision=FOREIGN
    else
        _vp_lifecycle_lstat_before=$(LC_ALL=C stat -c '%d:%i' -- \
            "$_vp_lifecycle_mount_path") || _vp_lifecycle_lstat_before=
        _vp_lifecycle_stat=$(LC_ALL=C stat -L -c '%d:%i' -- \
            "$_vp_lifecycle_mount_path") || _vp_lifecycle_stat=
        _vp_lifecycle_lstat_after=$(LC_ALL=C stat -c '%d:%i' -- \
            "$_vp_lifecycle_mount_path") || _vp_lifecycle_lstat_after=
        if [ -n "$_vp_lifecycle_lstat_before" ] &&
            [ "$_vp_lifecycle_lstat_before" = "$_vp_lifecycle_expected_identity" ] &&
            [ "$_vp_lifecycle_stat" = "$_vp_lifecycle_expected_identity" ] &&
            [ "$_vp_lifecycle_lstat_after" = "$_vp_lifecycle_expected_identity" ]
        then
            _vp_lifecycle_decision=OWNED
        else
            _vp_lifecycle_decision=FOREIGN
        fi
    fi

    _vp_lifecycle_decision_manifest_identity_after=$(
        _vp_lifecycle_private_file_identity \
            "$_vp_lifecycle_decision_manifest" \
            "$VP_LIFECYCLE_MANIFEST_MAX_BYTES" \
            "$_vp_lifecycle_decision_uid"
    ) || {
        printf '%s\n' INVALID
        return 0
    }
    _vp_lifecycle_decision_manifest_sha256_after=$(
        _vp_lifecycle_private_file_sha256 "$_vp_lifecycle_decision_manifest"
    ) || {
        printf '%s\n' INVALID
        return 0
    }
    if [ "$_vp_lifecycle_decision_manifest_identity" != \
            "$_vp_lifecycle_decision_manifest_identity_after" ] ||
        [ "$_vp_lifecycle_decision_manifest_sha256" != \
            "$_vp_lifecycle_decision_manifest_sha256_after" ]
    then
        printf '%s\n' INVALID
        return 0
    fi
    printf '%s\n' "$_vp_lifecycle_decision"
}
