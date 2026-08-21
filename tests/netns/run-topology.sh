#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Safe allowlisted dispatcher used by the justfile and CI.
set -eu

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
INTEGRATION_RUNNER=$SCRIPT_DIRECTORY/../integration/run.sh
TOPOLOGY=$SCRIPT_DIRECTORY/topology.sh
MODE=preview
SUITE=all
SEEN_MODE=no
SEEN_SUITE=no
APPROVE=no

usage() {
    printf '%s\n' \
        'usage: tests/netns/run-topology.sh [--preview|--execute] [--only all|mptcp|mpquic] [--yes]' \
        '' \
        'Preview is the default. Exit 77 means BLOCKED; no acceptance case passed.'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --preview)
            [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }
            MODE=preview
            SEEN_MODE=yes
            ;;
        --execute)
            [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }
            MODE=execute
            SEEN_MODE=yes
            ;;
        --only)
            if [ "$SEEN_SUITE" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            SUITE=$2
            SEEN_SUITE=yes
            shift
            ;;
        --yes)
            APPROVE=yes
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown topology-dispatch option: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
    esac
    shift
done

case "$SUITE" in
    all|mptcp|mpquic) ;;
    *)
        printf 'unsupported topology suite: %s\n' "$SUITE" >&2
        usage >&2
        exit 64
        ;;
esac
if [ "$MODE" = preview ] && [ "$APPROVE" = yes ]; then
    printf '%s\n' '--yes is valid only with --execute' >&2
    exit 64
fi

"$TOPOLOGY" --preview >&2

if [ "$MODE" = preview ]; then
    exec "$INTEGRATION_RUNNER" --preview --suite "$SUITE"
fi

exec "$INTEGRATION_RUNNER" --execute --suite "$SUITE"
