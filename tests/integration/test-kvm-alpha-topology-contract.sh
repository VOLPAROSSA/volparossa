#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Cheap static contract for the manually or integration-PR dispatched KVM alpha runner.
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
grep -Fx '  pull_request:' "$WORKFLOW" >/dev/null
grep -F 'github.event.pull_request.head.repo.full_name == github.repository' "$WORKFLOW" \
    >/dev/null
grep -F "github.head_ref == 'feature/alpha-vertical-runtime'" "$WORKFLOW" >/dev/null
if grep -Eq '^  push:' "$WORKFLOW"; then exit 1; fi

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
grep -F 'ip -n "$underlay_ns" link add underlay type dummy' "$GUEST" >/dev/null
grep -F 'ip -n "$underlay_ns" route add default dev underlay scope global' "$GUEST" >/dev/null
[ "$(grep -Fc 'add_public_underlay ' "$GUEST")" -eq 4 ]
grep -F 'ip -n "$CLIENT" route add unreachable "$forbidden/32"' "$GUEST" >/dev/null
grep -F '10.241.31.1 10.241.31.2 46.162.3.1' "$GUEST" >/dev/null
if grep -E 'ip -n "\$CLIENT" route add (unicast )?46\.162\.3\.1' "$GUEST"; then exit 1; fi
if grep -F 'link_nodes "$CLIENT"' "$GUEST" | grep -F '"$EXIT_NODE"'; then
    exit 1
fi
grep -F 'payload, source = udp.recvfrom(2048)' "$GUEST" >/dev/null
grep -F 'sent = udp.sendto(payload, source)' "$GUEST" >/dev/null
grep -F 'ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID"' "$GUEST" >/dev/null
grep -F 'application.sendto(payload, destination)' "$GUEST" >/dev/null
grep -F 'response, source = application.recvfrom(2048)' "$GUEST" >/dev/null
grep -F 'direct_client_exit_packets' "$GUEST" >/dev/null
grep -F 'selected_relay:$selected' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A05",success:$success' "$GUEST" >/dev/null
grep -F 'a05_udp_echo:{requested:$a05_requested,succeeded:$a05_succeeded' "$GUEST" \
    >/dev/null

printf '%s\n' 'KVM alpha topology static contract passed'
