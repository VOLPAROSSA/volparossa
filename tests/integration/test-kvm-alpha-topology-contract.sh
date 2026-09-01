#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Cheap static contract for the manually dispatched KVM alpha runner.
# shellcheck disable=SC2016
set -eu

export LC_ALL=C
umask 077
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
GUEST=$HERE/kvm-alpha-topology.sh
HOST=$HERE/run-alpha-topology-vm.sh
WORKFLOW=$HERE/../../.github/workflows/alpha-topology.yml

for script in "$GUEST" "$HOST"; do
    [ -f "$script" ] && [ -x "$script" ] && [ ! -L "$script" ]
    sh -n "$script"
    "$script" --preview | grep -F 'PREVIEW ONLY:' >/dev/null
    set +e
    "$script" --execute >/dev/null 2>&1
    invalid_status=$?
    set -e
    [ "$invalid_status" -eq 64 ]
done

[ -f "$WORKFLOW" ] && [ ! -L "$WORKFLOW" ]
grep -Fx '  workflow_dispatch:' "$WORKFLOW" >/dev/null
if grep -Eq '^  (push|pull_request):' "$WORKFLOW"; then
    exit 1
fi

[ "$(grep -Fc 'launch_helper client "$CLIENT"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay1 "$R1"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay2 "$R2"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper exit "$EXIT_NODE"' "$GUEST")" -eq 1 ]
grep -F 'helper_unit=volparossa-alpha-helper@$node.service' "$GUEST" >/dev/null
grep -F 'agent_unit=volparossa-alpha-agent@$node.service' "$GUEST" >/dev/null
grep -F -- '--property="NetworkNamespacePath=/run/netns/$namespace"' "$GUEST" >/dev/null
grep -F 'GetUnitByPID u "$helper_pid"' "$GUEST" >/dev/null
grep -F -- '--property=NotifyAccess=main' "$GUEST" >/dev/null
grep -F -- '--property=FileDescriptorStoreMax=128' "$GUEST" >/dev/null
grep -F -- '--property=FileDescriptorStorePreserve=yes' "$GUEST" >/dev/null
grep -F -- '--property="BindPaths=$WORK/runtime-$node:/run/volparossa"' "$GUEST" >/dev/null
grep -F 'VOLPAROSSA_HELPER_SOCKET=/run/volparossa/helper.sock' "$GUEST" >/dev/null
grep -F 'DIRECT_CLIENT_EXIT_REACHABLE' "$GUEST" >/dev/null
if grep -F 'ip -n "$CLIENT" route add 46.162.3.1' "$GUEST"; then
    exit 1
fi
if grep -F 'link_nodes "$CLIENT"' "$GUEST" | grep -F '"$EXIT_NODE"'; then
    exit 1
fi

printf '%s\n' 'KVM alpha topology static contract passed'
