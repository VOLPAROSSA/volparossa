#!/bin/sh
# Invoke only VOLPAROSSA's authenticated, ownership-scoped cleanup path.
set -eu

usage() {
    printf '%s\n' 'usage: scripts/cleanup-network.sh [--yes]'
}

case ${1-} in
    '') APPROVE=no ;;
    --yes) APPROVE=yes ;;
    *) usage >&2; exit 64 ;;
esac
[ "$#" -le 1 ] || { usage >&2; exit 64; }

if [ -n "${VOLPAROSSA_CLI-}" ]; then
    CLI=$VOLPAROSSA_CLI
elif command -v volparossa >/dev/null 2>&1; then
    CLI=volparossa
elif [ -x target/debug/volparossa ]; then
    CLI=target/debug/volparossa
elif [ -x target/release/volparossa ]; then
    CLI=target/release/volparossa
else
    printf '%s\n' 'volparossa CLI is unavailable; build or install it before cleanup' >&2
    exit 69
fi

"$CLI" cleanup
if [ "$APPROVE" != yes ]; then
    printf '%s' 'Execute this ownership-scoped cleanup? [y/N] '
    read -r answer
    case $answer in
        y|Y|yes|YES) ;;
        *) printf '%s\n' 'cancelled'; exit 0 ;;
    esac
fi

exec "$CLI" cleanup --execute
