#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed pre-exec barrier for the disposable KVM ExactPresent restart proof.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
[ "$#" -eq 0 ] || exit 64

proof_directory=/run/volparossa-helper-production-proof
crash_record=$proof_directory/restart.crash
ready_record=$proof_directory/restart.successor-barrier
ready_next=$proof_directory/restart.successor-barrier.next
release_fifo=$proof_directory/restart.successor-release
release_capture=$proof_directory/restart.successor-release.capture
production_helper=/run/volparossa-helper-production

invocation_id_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ "${#1}" -eq 32 ] || return 1
    case $1 in
        *[!0-9a-f]*|00000000000000000000000000000000) return 1 ;;
        *) return 0 ;;
    esac
}

case $$ in ''|0|0*|*[!0-9]*) exit 65 ;; esac
[ -x "$production_helper" ] && [ -f "$production_helper" ] \
    && [ ! -L "$production_helper" ] || exit 65

if [ ! -e "$crash_record" ] && [ ! -L "$crash_record" ]; then
    exec "$production_helper"
fi

invocation_id=${INVOCATION_ID:-}
invocation_id_is_safe "$invocation_id" || exit 65
[ "$(stat -Lc '%F:%u:%a:%h' "$crash_record" 2>/dev/null || true)" \
    = 'regular file:0:600:1' ] || exit 65
[ "$(stat -Lc '%F:%u:%g:%a:%h' "$release_fifo" 2>/dev/null || true)" \
    = 'fifo:0:0:600:1' ] || exit 65
if [ -e "$ready_record" ] || [ -L "$ready_record" ] \
    || [ -e "$ready_next" ] || [ -L "$ready_next" ] \
    || [ -e "$release_capture" ] || [ -L "$release_capture" ]; then
    exit 65
fi

printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_RESTART_SUCCESSOR_BARRIER_V1=ready' \
    "$invocation_id" "$$" >"$ready_next"
chmod 0600 "$ready_next"
[ "$(stat -Lc '%F:%u:%a:%h' "$ready_next" 2>/dev/null || true)" \
    = 'regular file:0:600:1' ] || exit 65
mv -T "$ready_next" "$ready_record"
[ "$(stat -Lc '%F:%u:%a:%h' "$ready_record" 2>/dev/null || true)" \
    = 'regular file:0:600:1' ] || exit 65

dd if="$release_fifo" of="$release_capture" iflag=fullblock \
    bs=2 count=1 status=none \
    || exit 65
[ "$(stat -Lc '%F:%u:%g:%a:%h:%s' "$release_capture" \
    2>/dev/null || true)" = 'regular file:0:0:600:1:1' ] || exit 65
[ "$(cat "$release_capture")" = G ] || exit 65
exec "$production_helper"
