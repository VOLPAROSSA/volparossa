#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed GDB-side adapter for the disposable singleton MayOwn Relay KVM proof.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
[ "$#" -eq 4 ] || exit 64
case $1 in
    armed|first-publication|after-first-crash|second-confirm|after-second-crash|third-removal) ;;
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
