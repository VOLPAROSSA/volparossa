#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed external adapter for the disposable singleton MayOwn Relay KVM proof.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
case $1 in
    pre-exec-one|pre-exec-two|pre-exec-three)
        [ "$#" -eq 5 ] || exit 64
        preexec_mode=$1
        preexec_unit=$2
        preexec_gid=$3
        preexec_main_pid=$4
        preexec_invocation=$5
        case $preexec_unit in
            volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service) ;;
            *) exit 64 ;;
        esac
        case $preexec_gid in ''|0|0*|*[!0-9]*) exit 64 ;; esac
        case $preexec_main_pid in ''|0|0*|*[!0-9]*) exit 64 ;; esac
        [ "${#preexec_invocation}" -eq 32 ] || exit 64
        case $preexec_invocation in
            *[!0-9a-f]*|00000000000000000000000000000000) exit 64 ;;
        esac
        preexec_label=${preexec_mode#pre-exec-}
        proof_directory=/run/volparossa-helper-production-proof
        ready_record=$proof_directory/may-own.pre-exec-observer-ready.$preexec_label
        ready_next=$ready_record.next
        release_record=$proof_directory/may-own.pre-exec-observer-release.$preexec_label
        if [ -e "$ready_record" ] || [ -L "$ready_record" ] \
            || [ -e "$ready_next" ] || [ -L "$ready_next" ] \
            || [ -e "$release_record" ] || [ -L "$release_record" ]; then
            exit 65
        fi
        [ "$(stat -Lc '%d:%i' /proc/self/ns/mnt)" = \
            "$(stat -Lc '%d:%i' "/proc/$preexec_main_pid/ns/mnt")" ] || exit 65
        [ "$(stat -Lc '%d:%i' /proc/self/ns/net)" = \
            "$(stat -Lc '%d:%i' "/proc/$preexec_main_pid/ns/net")" ] || exit 65
        printf '%s\n%s\n%s\n%s\n' \
            'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_OBSERVER_V1=ready' \
            "$preexec_invocation" "$preexec_main_pid" "$$" >"$ready_next"
        chmod 0600 "$ready_next"
        [ "$(stat -Lc '%F:%u:%g:%a:%h' "$ready_next")" = \
            'regular file:0:0:600:1' ] || exit 65
        mv -T "$ready_next" "$ready_record"
        preexec_wait=0
        while [ ! -f "$release_record" ]; do
            [ ! -L "$release_record" ] || exit 65
            preexec_wait=$((preexec_wait + 1))
            [ "$preexec_wait" -lt 1200 ] || exit 65
            sleep 0.05
        done
        [ "$(stat -Lc '%F:%u:%g:%a:%h:%s' "$release_record")" = \
            'regular file:0:0:600:1:55' ] || exit 65
        [ "$(cat "$release_record")" = \
            'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_OBSERVER_V1=release' ] \
            || exit 65
        exit 0
        ;;
    armed|first-publication|after-first-crash|second-confirm|after-second-crash|third-removal)
        [ "$#" -eq 4 ] || exit 64
        ;;
    *) exit 64 ;;
esac
case $2 in
    volparossa-helper-live-proof-[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9].service) ;;
    *) exit 64 ;;
esac
observer_gid=$3
case $observer_gid in
    ''|0|0*|*[!0-9]*) exit 64 ;;
    *)
        if [ "${#observer_gid}" -gt 10 ] \
            || [ "$observer_gid" -gt 4294967294 ]; then
            exit 64
        fi
        ;;
esac
case $4 in ''|0|*[!0-9]*) exit 64 ;; esac
exec /usr/bin/setpriv \
    --reuid=0 \
    --regid="$observer_gid" \
    --groups="$observer_gid" \
    -- /run/volparossa-helper-production-ipc-hook may-own-observe "$@"
