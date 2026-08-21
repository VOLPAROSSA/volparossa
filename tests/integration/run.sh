#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Emit an honest acceptance preview until the reviewed privileged driver exists.
set -eu

MODE=PREVIEW
SUITE=all
SEEN_MODE=no
SEEN_SUITE=no

usage() {
    printf '%s\n' \
        'usage: tests/integration/run.sh [--preview|--execute] [--suite all|mptcp|mpquic]' \
        '' \
        'Exit status 77 means the requested acceptance suite is BLOCKED and no test passed.'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --preview)
            [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }
            MODE=PREVIEW
            SEEN_MODE=yes
            ;;
        --execute)
            [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }
            MODE=EXECUTE
            SEEN_MODE=yes
            ;;
        --suite)
            if [ "$SEEN_SUITE" != no ] || [ "$#" -lt 2 ]; then
                usage >&2
                exit 64
            fi
            SUITE=$2
            SEEN_SUITE=yes
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown integration-runner option: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
    esac
    shift
done

case "$SUITE" in
    all|mptcp|mpquic) ;;
    *)
        printf 'unsupported acceptance suite: %s\n' "$SUITE" >&2
        usage >&2
        exit 64
        ;;
esac

case_is_selected() {
    case "$SUITE:$1" in
        all:*) return 0 ;;
        mptcp:A02|mptcp:A03|mptcp:A04|mptcp:A14|mptcp:A15) return 0 ;;
        mpquic:A06|mpquic:A07|mpquic:A14|mpquic:A15) return 0 ;;
        *) return 1 ;;
    esac
}

printf '%s\n' \
    'BLOCKED: the reviewed privileged acceptance driver is not present.' \
    'No namespace, link, route, firewall rule, WireGuard device, MPTCP endpoint, socket, or sysctl was changed.' >&2

printf '%s\n' '{'
printf '%s\n' '  "schema_version": 1,'
printf '%s\n' '  "report_kind": "acceptance",'
printf '  "suite": "%s",\n' "$SUITE"
printf '%s\n' '  "source_revision": null,'
printf '%s\n' '  "generated_at": null,'
printf '%s\n' '  "started_at": null,'
printf '%s\n' '  "finished_at": null,'
printf '%s\n' '  "execution": {'
printf '    "requested_mode": "%s",\n' "$MODE"
printf '%s\n' '    "attempted": false,'
printf '%s\n' '    "completed": false,'
printf '%s\n' '    "topology_created": false,'
printf '%s\n' '    "blockers": ['
printf '%s\n' '      {"code":"ACCEPTANCE_DRIVER_UNAVAILABLE","message":"No reviewed fixed acceptance driver is installed."}'
printf '%s\n' '    ]'
printf '%s\n' '  },'
printf '%s\n' '  "environment": {'
printf '%s\n' '    "debian_version": null,'
printf '%s\n' '    "architecture": null,'
printf '%s\n' '    "kernel": null,'
printf '%s\n' '    "rustc": null,'
printf '%s\n' '    "native_revisions": {}'
printf '%s\n' '  },'
printf '%s\n' '  "host_state": {'
printf '%s\n' '    "captured": false,'
printf '%s\n' '    "before_digest": null,'
printf '%s\n' '    "after_digest": null,'
printf '%s\n' '    "unchanged": null'
printf '%s\n' '  },'
printf '%s\n' '  "cases": ['

first=yes
for case_id in A01 A02 A03 A04 A05 A06 A07 A08 A09 A10 A11 A12 A13 A14 A15; do
    if case_is_selected "$case_id"; then
        selected=true
        reason_code=ACCEPTANCE_DRIVER_UNAVAILABLE
        reason_message='The selected case was not executed because the privileged driver is absent.'
    else
        selected=false
        reason_code=NOT_SELECTED
        reason_message='The case is outside the selected preview suite.'
    fi
    if [ "$first" = yes ]; then
        first=no
    else
        printf '%s\n' ','
    fi
    printf '    {"id":"%s","selected":%s,"result":"SKIPPED","reason":{"code":"%s","message":"%s"},"evidence":[]}' \
        "$case_id" "$selected" "$reason_code" "$reason_message"
done
printf '\n%s\n' '  ],'
printf '%s\n' '  "cleanup": {'
printf '%s\n' '    "attempted": false,'
printf '%s\n' '    "complete": null,'
printf '%s\n' '    "remaining_owned_objects": null'
printf '%s\n' '  },'
printf '%s\n' '  "overall": "BLOCKED"'
printf '%s\n' '}'

exit 77
