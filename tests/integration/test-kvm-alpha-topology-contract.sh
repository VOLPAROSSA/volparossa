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
GENERATOR=$HERE/generate-alpha-acceptance-report.sh
WORKFLOW=$HERE/../../.github/workflows/alpha-topology.yml
RECIPROCITY=$HERE/reciprocity-smoke.sh
RECIPROCITY_PY=$HERE/reciprocity-smoke.py

for script in "$GUEST" "$HOST"; do
    [ -f "$script" ] && [ -x "$script" ] && [ ! -L "$script" ]
    sh -n "$script"
    "$script" --preview | grep -F 'PREVIEW ONLY:' >/dev/null
    "$script" --preview --scenario reciprocity | grep -Fi 'recipro' >/dev/null
    "$script" --preview --scenario local-link | grep -Fi 'local-link' >/dev/null
    set +e
    "$script" --preview --scenario unsupported >/dev/null 2>&1
    invalid_scenario_status=$?
    set -e
    [ "$invalid_scenario_status" -eq 64 ]
    set +e
    "$script" --execute >/dev/null 2>&1
    invalid_status=$?
    set -e
    [ "$invalid_status" -eq 64 ]
done
[ -f "$GENERATOR" ] && [ -x "$GENERATOR" ] && [ ! -L "$GENERATOR" ]
sh -n "$GENERATOR"

[ -f "$WORKFLOW" ] && [ ! -L "$WORKFLOW" ]
grep -Fx '  workflow_dispatch:' "$WORKFLOW" >/dev/null
grep -Fx '  pull_request:' "$WORKFLOW" >/dev/null
grep -F 'github.event.pull_request.head.repo.full_name == github.repository' "$WORKFLOW" \
    >/dev/null
grep -F "github.head_ref == 'feature/alpha-vertical-runtime'" "$WORKFLOW" >/dev/null
if grep -Eq '^  push:' "$WORKFLOW"; then exit 1; fi
grep -F 'native/volparossa-mpquic/scripts/fetch-upstream.sh --yes' "$WORKFLOW" \
    >/dev/null
grep -F 'native/volparossa-mpquic/scripts/build-upstream.sh' "$WORKFLOW" >/dev/null
grep -F 'VMP_BUILD_JOBS=2 VMP_RUN_TESTS=no' "$WORKFLOW" >/dev/null
grep -F -- '--mpquic "$VOLPAROSSA_ALPHA_MPQUIC"' "$WORKFLOW" >/dev/null
grep -F -- '--package "$VOLPAROSSA_ALPHA_PACKAGE"' "$WORKFLOW" >/dev/null
grep -F './packaging/build-deb.sh --build' "$WORKFLOW" >/dev/null
[ "$(grep -Fc './packaging/build-deb.sh --build' "$WORKFLOW")" -eq 2 ]
grep -F 'volparossa-package-target-rebuild' "$WORKFLOW" >/dev/null
grep -F 'cmp -- "$first_package" "$package"' "$WORKFLOW" >/dev/null
grep -F "test \"\$first_sha256\" = \"\$second_sha256\"" "$WORKFLOW" >/dev/null
grep -F 'scp_to "$mpquic_path" /home/vpci/volparossa-mpquic' "$HOST" >/dev/null
grep -F 'scp_to "$package_path" /home/vpci/volparossa.deb' "$HOST" >/dev/null
grep -F -- '--mpquic /home/vpci/volparossa-mpquic' "$HOST" >/dev/null
grep -F -- './tests/packaging/debian13-package-lifecycle.sh' "$HOST" >/dev/null
grep -F -- '--package /home/vpci/volparossa.deb' "$HOST" >/dev/null
grep -F -- '-p volparossa-test-support --example http3-acceptance-fixture' "$HOST" \
    >/dev/null
grep -F -- '-p volparossa-test-support --example tls-policy-acceptance-fixture' "$HOST" \
    >/dev/null

[ "$(grep -Fc 'launch_helper client "$CLIENT"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper bootstrap1 "$B1"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper bootstrap2 "$B2"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay0 "$R0"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay1 "$R1"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay2 "$R2"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay3 "$R3"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay4 "$R4"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper relay5 "$R5"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper exit "$EXIT_NODE"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_helper exit2 "$EXIT2_NODE"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_agent relay0 "$R0"' "$GUEST")" -eq 1 ]
grep -F 'launch_agent bootstrap1 "$B1"' "$GUEST" >/dev/null
grep -F 'launch_agent bootstrap2 "$B2"' "$GUEST" >/dev/null
grep -F 'verify_helper relay0 "$R0"' "$GUEST" >/dev/null
grep -F 'for cleanup_ns in "$DEST" "$EXIT2_NODE" "$EXIT_NODE" "$R5" "$R4" "$R3"' \
    "$GUEST" >/dev/null
grep -F 'helper_unit=volparossa-alpha-helper@$node.service' "$GUEST" >/dev/null
grep -F 'agent_unit=volparossa-alpha-agent@$node.service' "$GUEST" >/dev/null
grep -F -- '--property="NetworkNamespacePath=/run/netns/$namespace"' "$GUEST" >/dev/null
grep -F 'GetUnitByPID u "$helper_pid"' "$GUEST" >/dev/null
grep -F -- '--property=NotifyAccess=main' "$GUEST" >/dev/null
grep -F -- '--property=FileDescriptorStoreMax=128' "$GUEST" >/dev/null
grep -F -- '--property=FileDescriptorStorePreserve=yes' "$GUEST" >/dev/null
grep -F -- '--property="BindPaths=$WORK/runtime-$node:/run/volparossa"' "$GUEST" >/dev/null
grep -F 'VOLPAROSSA_HELPER_SOCKET=/run/volparossa/helper.sock' "$GUEST" >/dev/null
grep -F 'launch_mpquic client "$CLIENT" client' "$GUEST" >/dev/null
grep -F 'launch_mpquic exit "$EXIT_NODE" exit' "$GUEST" >/dev/null
grep -F 'launch_mpquic exit2 "$EXIT2_NODE" exit' "$GUEST" >/dev/null
if grep -Eq 'launch_mpquic relay[012]' "$GUEST"; then exit 1; fi
grep -F 'native_socket=/run/volparossa/native/mpquic.sock' "$GUEST" >/dev/null
grep -F -- '--socket "$native_socket"' "$GUEST" >/dev/null
grep -F 'native_mpquic:{ready:$mpquic,api_version:6,instances:$mpquic_records}' \
    "$GUEST" >/dev/null
grep -F 'and ($destination.peer_completion_observed == true)' "$GUEST" >/dev/null
grep -F 'DIRECT_CLIENT_EXIT_REACHABLE' "$GUEST" >/dev/null
grep -F 'ip -n "$underlay_ns" link add underlay type dummy' "$GUEST" >/dev/null
grep -F 'ip -n "$underlay_ns" route add default dev underlay scope global' "$GUEST" >/dev/null
[ "$(grep -Fc 'add_public_underlay ' "$GUEST")" -eq 11 ]
grep -F 'ip -n "$CLIENT" route add unreachable "$forbidden/32"' "$GUEST" >/dev/null
grep -F 'for forbidden in 10.241.20.2 10.241.21.2 10.241.22.2 10.241.23.2' \
    "$GUEST" >/dev/null
grep -F '10.241.32.1 10.241.32.2 46.162.3.1 47.163.4.1 51.167.7.1' \
    "$GUEST" >/dev/null
grep -F 'link_nodes "$CLIENT" cr0 10.241.10.1/30 "$R0" r0c 10.241.10.2/30' \
    "$GUEST" >/dev/null
grep -F 'link_nodes "$R0" r0x 10.241.20.1/30 "$EXIT_NODE" xr0 10.241.20.2/30' \
    "$GUEST" >/dev/null
grep -F 'write_config bootstrap1 null false false 40.156.1.1 none none none' \
    "$GUEST" >/dev/null
grep -F 'write_config bootstrap2 null false false 41.157.2.1 none none none' \
    "$GUEST" >/dev/null
grep -F 'write_config relay0 acceptance-relay-zero true false 42.158.0.1' \
    "$GUEST" >/dev/null
grep -F 'relay0) advertised_asn=64511; advertised_prefix=42.158.0.0/24' \
    "$GUEST" >/dev/null
grep -F '/ip4/42.158.0.1/udp/41000/quic-v1/p2p/$R0_PEER' "$GUEST" >/dev/null
grep -F '/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER' "$GUEST" >/dev/null
grep -F '/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER' "$GUEST" >/dev/null
grep -F 'write_config exit acceptance-exit false true 46.162.3.1' "$GUEST" >/dev/null
grep -F 'exit_control_relay:"relay0",data_relays:["relay1","relay2"]' \
    "$GUEST" >/dev/null
grep -F 'bootstrap1|bootstrap2) required_active_peers=7' "$GUEST" >/dev/null
grep -F 'relay0) required_active_peers=4' "$GUEST" >/dev/null
grep -F 'relay1|relay2|relay3|relay4|relay5) required_active_peers=2' "$GUEST" >/dev/null
grep -F 'node_count:12,relay_count:6,exit_count:2,physical_network_count:29' \
    "$GUEST" >/dev/null
grep -F 'production_helpers:11,production_agents:11,native_mpquic_processes:3' \
    "$GUEST" >/dev/null
grep -F '.network_namespace_count == 12' "$GUEST" >/dev/null
grep -F '.runtime_socket_count >= 25' "$GUEST" >/dev/null
grep -F 'length == 25 and' "$GUEST" >/dev/null
if grep -E 'ip -n "\$CLIENT" route add (unicast )?46\.162\.3\.1' "$GUEST"; then exit 1; fi
if grep -F 'link_nodes "$CLIENT"' "$GUEST" | grep -F '"$EXIT_NODE"'; then
    exit 1
fi
if grep -F 'link_nodes "$CLIENT"' "$GUEST" | grep -F '"$EXIT2_NODE"'; then
    exit 1
fi
grep -F 'payload, source = udp.recvfrom(2048)' "$GUEST" >/dev/null
grep -F 'sent = udp.sendto(payload, source)' "$GUEST" >/dev/null
grep -F 'ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID"' "$GUEST" >/dev/null
grep -F 'application.sendto(payload, destination)' "$GUEST" >/dev/null
grep -F 'response, source = application.recvfrom(2048)' "$GUEST" >/dev/null
grep -F 'direct_client_exit_packets' "$GUEST" >/dev/null
if grep -F 'relay0_wireguard_data_datagrams' "$GUEST"; then exit 1; fi
if grep -E 'is_wireguard_data and interface == "(cr0|xr0)"' "$GUEST"; then exit 1; fi
grep -F '"$DOWNLOAD_MARKER" cr1 cr2 underlay' "$GUEST" >/dev/null
grep -F '"$DOWNLOAD_MARKER" xr1 xr2 xd' "$GUEST" >/dev/null
grep -F 'client "$WORK/a05-client-capture.json" "$WORK/a05-client-capture.ready"' \
    "$GUEST" >/dev/null
grep -F 'exit "$WORK/a05-exit-capture.json" "$WORK/a05-exit-capture.ready"' \
    "$GUEST" >/dev/null
grep -F 'selected_relay:$selected' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A05",success:$success' "$GUEST" >/dev/null
grep -F 'a05_udp_echo:{requested:$a05_requested,succeeded:$a05_succeeded' "$GUEST" \
    >/dev/null
grep -F 'tcp.bind(("47.163.4.2", 18080))' "$GUEST" >/dev/null
grep -F 'socket.create_connection(destination, timeout=60)' "$GUEST" >/dev/null
grep -F '"relay1_wireguard_data_datagrams": 0' "$GUEST" >/dev/null
grep -F 'wireguard_message_type == 4 and udp_length > 40' "$GUEST" >/dev/null
grep -F 'tcp_payload_bytes = 4 * 1024 * 1024' "$GUEST" >/dev/null
grep -F 'source:"production MPTCP_INFO gate before payload"' "$GUEST" >/dev/null
grep -F 'required_subflows:2,gate_passed:true' "$GUEST" >/dev/null
grep -F 'if observed_frames > 131072:' "$GUEST" >/dev/null
grep -F 'destination_evidence="$WORK/destination/tcp-evidence-$attempt.json"' "$GUEST" \
    >/dev/null
grep -F '"$WORK/destination/udp-evidence.json"' "$GUEST" >/dev/null
grep -F 'and ($app.attempt == $destination.attempt)' "$GUEST" >/dev/null
grep -F 'destination_stop_attempt=0' "$GUEST" >/dev/null
grep -F 'event=INGRESS_TCP_STREAM_COMPLETED' "$GUEST" >/dev/null
grep -F 'event=MPTCP_EXIT_FLOW_COMPLETED' "$GUEST" >/dev/null
grep -F 'ordinary_tcp_fallback_allowed:false' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A02",success:$success' "$GUEST" >/dev/null
grep -F 'a02_transparent_tcp:{requested:$a02_requested,succeeded:$a02_succeeded' "$GUEST" \
    >/dev/null
grep -F 'rate 8mbit burst 128kb latency 250ms' "$GUEST" >/dev/null
grep -F 'start_mptcp_download a03-single a03-single' "$GUEST" >/dev/null
grep -F 'start_mptcp_download a03-aggregate a03-aggregate' "$GUEST" >/dev/null
grep -F 'measured_throughput_gain_ratio:' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A03",success:$success' "$GUEST" >/dev/null
grep -F 'a03_mptcp_aggregation:{requested:$a03_requested,succeeded:$a03_succeeded' "$GUEST" \
    >/dev/null
grep -F 'ip -n "$R1" link set r1c down' "$GUEST" >/dev/null
grep -F 'ip -n "$R1" link set r1x down' "$GUEST" >/dev/null
grep -F 'process_active_at_removal:$process_active_at_removal' "$GUEST" >/dev/null
grep -F 'after_marker.relay2_wireguard_data_datagrams > 0' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A04",success:$success' "$GUEST" >/dev/null
grep -F 'a04_mptcp_relay_failover:{requested:$a04_requested,succeeded:$a04_succeeded' "$GUEST" \
    >/dev/null
grep -F 'a01_transient_connect_unavailable "$WORK/connect-client.err" || break' "$GUEST" \
    >/dev/null
grep -F 'http3-acceptance-fixture" server' "$GUEST" >/dev/null
grep -F 'http3-acceptance-fixture" client a06' "$GUEST" >/dev/null
grep -F 'http3-acceptance-fixture" client a07' "$GUEST" >/dev/null
grep -F '43.159.1.1:52006 47.163.4.2:443' "$GUEST" >/dev/null
grep -F '43.159.1.1:52007 47.163.4.2:443' "$GUEST" >/dev/null
grep -F '"$WORK/client-fixtures/http3-cert.der"' "$GUEST" >/dev/null
grep -F 'connected: false' "$GUEST" >/dev/null
grep -F 'active contexts: 0' "$GUEST" >/dev/null
grep -F 'PHASE=a06-preconnect-multipath-route' "$GUEST" >/dev/null
grep -F -- '--transport multipath-quic' "$GUEST" >/dev/null
grep -F 'wait_active_native_mpquic_paths a06-preconnect-native-paths' \
    "$GUEST" >/dev/null
grep -F 'all(.paths[]; .state == 3)' "$GUEST" >/dev/null
grep -F 'preestablished_before_http3_client:true' "$GUEST" >/dev/null
grep -F '($preconnect.route_context_id == $native.route_context_id)' "$GUEST" >/dev/null
preconnect_line=$(grep -nF 'PHASE=a06-preconnect-multipath-route' "$GUEST" \
    | cut -d: -f1)
disconnect_line=$(grep -nF 'PHASE=a06-reset-single-path-route' "$GUEST" \
    | cut -d: -f1)
a06_client_line=$(grep -nF '"$WORK/bin/examples/http3-acceptance-fixture" client a06' \
    "$GUEST" | cut -d: -f1)
[ "$disconnect_line" -lt "$preconnect_line" ]
[ "$preconnect_line" -lt "$a06_client_line" ]
grep -F 'destination == "47.163.4.2" and destination_port == 443' "$GUEST" \
    >/dev/null
grep -F 'capture_native_mpquic_paths()' "$GUEST" >/dev/null
grep -F 'native daemon exposes an ACK/accounting counter' "$GUEST" >/dev/null
grep -F '"native_acked_bytes": int(user_bytes)' "$GUEST" >/dev/null
grep -F 'agent local-control native MPQUIC status' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A06",success:$success' "$GUEST" >/dev/null
grep -F 'hostname_policy:{hostname:$app.hostname,transport:"udp",port:443' "$GUEST" \
    >/dev/null
grep -F 'client_initial_inspected_before_route:true' "$GUEST" >/dev/null
grep -F 'exit_initial_reverified_before_egress:true' "$GUEST" >/dev/null
grep -F 'a06_http3_mpquic:{requested:$a06_requested,succeeded:$a06_succeeded' "$GUEST" \
    >/dev/null
grep -F 'ip -n "$R1" link set r1c down' "$GUEST" >/dev/null
grep -F 'a07-active.ready' "$GUEST" >/dev/null
grep -F 'ordinary_quic_fallback_allowed:false' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A07",success:$success' "$GUEST" >/dev/null
grep -F 'a07_http3_relay_failover:{requested:$a07_requested,succeeded:$a07_succeeded' "$GUEST" \
    >/dev/null
grep -F 'tls-policy-acceptance-fixture" allowed' "$GUEST" >/dev/null
grep -F 'tls-policy-acceptance-fixture" denied' "$GUEST" >/dev/null
grep -F '47.163.4.2:18443' "$GUEST" >/dev/null
grep -F '"$WORK/tls-policy/tls-policy-cert.der"' "$GUEST" >/dev/null
grep -F 'destination.volparossa.test' "$GUEST" >/dev/null
grep -F '"$WORK/bin/dns-policy-client.py" udp "$RUN_ID"' "$GUEST" >/dev/null
grep -F '"$WORK/bin/dns-policy-client.py" tcp "$RUN_ID"' "$GUEST" >/dev/null
grep -F "'47.163.4.2 destination.volparossa.test destination.volparossa.test.'" "$GUEST" >/dev/null
grep -F 'getent ahostsv4 destination.volparossa.test. |' "$GUEST" >/dev/null
# setpriv executes this fixture directly: without a shebang it becomes shell input.
awk '
    /^cat >"\$WORK\/bin\/dns-policy-client\.py"/ {
        if (getline <= 0 || $0 != "#!/usr/bin/python3") exit 1
        found = 1
    }
    END { if (!found) exit 1 }
' "$GUEST"
grep -F 'event=INGRESS_DNS_QUERY_COMPLETED' "$GUEST" >/dev/null
grep -F 'event=INGRESS_DNS_TCP_QUERY_COMPLETED' "$GUEST" >/dev/null
grep -F 'and ($dns_udp.response_source == $dns_udp.resolver)' "$GUEST" >/dev/null
grep -F 'and ($dns_tcp.response_source == $dns_tcp.resolver)' "$GUEST" >/dev/null
grep -F 'and ($dns_udp.answer_addresses == ["47.163.4.2"])' "$GUEST" >/dev/null
grep -F 'INGRESS_TCP_POLICY_DENIED' "$GUEST" >/dev/null
grep -F 'INGRESS_TCP_ECH_DENIED' "$GUEST" >/dev/null
grep -F 'INGRESS_TCP_CLIENT_HELLO_DENIED' "$GUEST" >/dev/null
grep -F 'INGRESS_TCP_STREAM_FAILED' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A08",success:$success' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A09",success:$success' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A10",success:$success' "$GUEST" >/dev/null
grep -F 'a08_allowed_destination:{requested:$a08_requested,succeeded:$a08_succeeded' \
    "$GUEST" >/dev/null
grep -F 'a09_forbidden_destinations:{requested:$a09_requested,succeeded:$a09_succeeded' \
    "$GUEST" >/dev/null
grep -F 'a10_unverifiable_ech:{requested:$a10_requested,succeeded:$a10_succeeded' \
    "$GUEST" >/dev/null
grep -F 'block_bootstrap_contact "$B1"' "$GUEST" >/dev/null
grep -F 'block_bootstrap_contact "$B2"' "$GUEST" >/dev/null
grep -F 'restart_advertiser relay2' "$GUEST" >/dev/null
grep -F 'restart_advertiser relay1' "$GUEST" >/dev/null
grep -F 'wait_fresh_advertisement "$R2_PEER"' "$GUEST" >/dev/null
grep -F 'wait_fresh_advertisement "$R1_PEER"' "$GUEST" >/dev/null
grep -F 'a01_select_route bootstrap1' "$GUEST" >/dev/null
grep -F 'a01_select_route bootstrap2' "$GUEST" >/dev/null
grep -F 'NATIVE_PROBE_PROOF_UNAVAILABLE' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A01",success:$success' "$GUEST" >/dev/null
grep -F 'a01_bootstrap_resilience:{requested:$a01_requested' "$GUEST" >/dev/null
grep -F 'Require successful A01-A15 evidence' "$WORKFLOW" >/dev/null
grep -F '.a01_bootstrap_resilience.evidence.bootstrap1_removed.fresh_advertisement.sequence_after' \
    "$WORKFLOW" >/dev/null
grep -F '.a06_http3_mpquic.evidence.native_mpquic.required_path_count == 2' "$WORKFLOW" \
    >/dev/null
grep -F '.a06_http3_mpquic.evidence.hostname_policy.hostname == "destination.volparossa.test"' \
    "$WORKFLOW" >/dev/null
grep -F '.a07_http3_relay_failover.evidence.application_flow_completed == true' "$WORKFLOW" \
    >/dev/null
grep -F '.a08_allowed_destination.evidence.protected_flow.tls_handshake_and_payload_completed == true' \
    "$WORKFLOW" >/dev/null
grep -F '.a08_allowed_destination.evidence.dns.udp.mode == "udp"' "$WORKFLOW" >/dev/null
grep -F '.a08_allowed_destination.evidence.dns.tcp.mode == "tcp"' "$WORKFLOW" >/dev/null
grep -F '.a08_allowed_destination.evidence.dns.answer_addresses == ["47.163.4.2"]' \
    "$WORKFLOW" >/dev/null
grep -F '.a09_forbidden_destinations.evidence.destination_egress_connections_for_denials == 0' \
    "$WORKFLOW" >/dev/null
grep -F '.a10_unverifiable_ech.evidence.destination_egress_connections_for_denials == 0' \
    "$WORKFLOW" >/dev/null
grep -F 'relay1_wireguard_data_bytes > 1048576' "$GUEST" >/dev/null
grep -F 'after_marker.relay2_wireguard_data_bytes > 1048576' "$GUEST" >/dev/null
grep -F 'def is_ipv4_multicast(address):' "$GUEST" >/dev/null
grep -F 'not is_ipv4_multicast(destination)' "$GUEST" >/dev/null
grep -F 'is_outbound_client_discovery_attempt = (' "$GUEST" >/dev/null
grep -F 'and interface == "underlay"' "$GUEST" >/dev/null
grep -F 'and source == "46.162.3.1"' "$GUEST" >/dev/null
grep -F 'and destination == "43.159.1.1"' "$GUEST" >/dev/null
grep -F 'and destination_port == 41000' "$GUEST" >/dev/null
grep -F 'outbound_client_discovery_attempt_packets"] += 1' "$GUEST" >/dev/null
grep -F 'topology_control_public = {' "$GUEST" >/dev/null
grep -F 'allowed = topology_control_public | {' "$GUEST" >/dev/null
for scaled_public in 48.164.4.1 49.165.5.1 50.166.6.1 51.167.7.1; do
    grep -F "\"$scaled_public\"," "$GUEST" >/dev/null
done
grep -F '47.163.4.2 whose appearance in an outer header is counted separately above' "$GUEST" \
    >/dev/null
grep -F 'cr0 cr1 cr2 cr3 cr4 cr5 cb1 cb2 underlay' "$GUEST" >/dev/null
grep -F 'xr0 xr1 xr2 xr3 xr4 xr5 xd underlay' "$GUEST" >/dev/null
grep -F '"10.241.23.2/32","10.241.24.2/32","10.241.25.2/32"' "$GUEST" \
    >/dev/null
grep -F '"51.167.7.1/32","52.168.8.1/32","52.168.8.2/32"' "$GUEST" >/dev/null
grep -F 'IN("cr0","cr1","cr2","cr3","cr4","cr5","cb1","cb2","underlay")' \
    "$GUEST" >/dev/null
grep -F 'acceptance_id:"A11",success:$success' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A12",success:$success' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A13",success:$success' "$GUEST" >/dev/null
grep -F 'refresh_a14_live_custody()' "$GUEST" >/dev/null
grep -F -- '--transport mptcp >"$WORK/a14-refresh-connect.out"' "$GUEST" >/dev/null
grep -F 'refresh_a14_live_custody || fail A14_LIVE_CUSTODY_REFRESH_FAILED' "$GUEST" \
    >/dev/null
grep -F 'systemctl kill --kill-whom=all --signal=KILL "$crash_unit"' "$GUEST" \
    >/dev/null
grep -F 'active_control_path_records:$control_path_records' "$GUEST" >/dev/null
grep -F 'record_a14_worker_custody_inventory()' "$GUEST" >/dev/null
grep -F 'scan_a14_worker_namespace_references()' "$GUEST" >/dev/null
grep -F 'remaining_a14_helper_fdstore_descriptors()' "$GUEST" >/dev/null
grep -F '.helper_worker_custody.worker_process_count >= 4' "$GUEST" >/dev/null
grep -F '.helper_worker_custody.helper_fdstore_descriptors >=' "$GUEST" >/dev/null
grep -F 'cleanup:{worker_custody_after:$worker_after' "$GUEST" >/dev/null
grep -F 'remaining_worker_network_namespaces:$worker_namespaces' "$GUEST" >/dev/null
grep -F 'remaining_worker_namespace_references:$worker_references' "$GUEST" >/dev/null
grep -F 'remaining_helper_fdstore_descriptors:$fdstore' "$GUEST" >/dev/null
grep -F '([.namespaces[] | select(.nftables_rules > 0)] | length) >= 1' "$GUEST" \
    >/dev/null
if grep -F '.active_mpquic_path_records >= 2' "$GUEST" >/dev/null; then
    printf '%s\n' 'A14 must not require a retired MPQUIC route after A08 switched to MPTCP' >&2
    exit 1
fi
grep -F 'acceptance_id:"A14",success:$success' "$GUEST" >/dev/null
grep -F 'capture_host_state "$WORK/host-state-before.json"' "$GUEST" >/dev/null
grep -F 'capture_host_state "$WORK/host-state-after.json"' "$GUEST" >/dev/null
grep -F 'acceptance_id:"A15",success:$unchanged' "$GUEST" >/dev/null
grep -F '.a14_forced_crash_cleanup.evidence.cleanup.remaining_owned_objects == 0' \
    "$WORKFLOW" >/dev/null
grep -F '.a14_forced_crash_cleanup.evidence.cleanup.worker_custody_after.referenced_namespace_count == 0' \
    "$WORKFLOW" >/dev/null
grep -F '.a14_forced_crash_cleanup.evidence.cleanup.remaining_helper_fdstore_descriptors == 0' \
    "$WORKFLOW" >/dev/null
grep -F '.a15_host_state_unchanged.evidence.before_sha256 ==' "$WORKFLOW" \
    >/dev/null
grep -F 'generate-alpha-acceptance-report.sh' "$GUEST" >/dev/null
grep -F '"$output_directory/acceptance-report.json"' "$GUEST" >/dev/null
grep -F 'Validate normative acceptance report before upload' "$WORKFLOW" >/dev/null
grep -F 'tests/integration/validate-report.sh "$report"' "$WORKFLOW" >/dev/null

[ -f "$RECIPROCITY" ] && [ ! -L "$RECIPROCITY" ]
"$HOST" --preview --scenario datapath | grep -F 'full A01-A15 functional topology' >/dev/null
grep -F 'default: datapath' "$WORKFLOW" >/dev/null
[ -f "$RECIPROCITY_PY" ] && [ ! -L "$RECIPROCITY_PY" ]
sh -n "$RECIPROCITY"
grep -F 'for native_node in client relay0 relay2 exit; do' "$GUEST" >/dev/null
grep -F 'launch_mpquic "$native_node" "$native_namespace" client' "$GUEST" >/dev/null
grep -F 'launch_mpquic "$native_node" "$native_namespace" exit' "$GUEST" >/dev/null
grep -F 'reciprocity_finalize_report "$original_status"' "$GUEST" >/dev/null
grep -F 'report_kind:"volparossa-reciprocal-node-runtime"' "$RECIPROCITY" >/dev/null
grep -F 'connect --transport single-path-udp' "$RECIPROCITY" >/dev/null
grep -F 'reciprocity_agent_snapshot before' "$RECIPROCITY" >/dev/null
grep -F 'reciprocity_agent_snapshot after' "$RECIPROCITY" >/dev/null
grep -F 'Require real reciprocal runtime evidence' "$WORKFLOW" >/dev/null

# Pure parser/report tests: synthetic evidence stays in a temporary directory and is not a live
# datapath result. Corrupting each essential witness must fail the same production report gate.
python3 - "$RECIPROCITY_PY" <<'PYTHON'
import copy
import hashlib
import pathlib
import socket
import struct
import sys
import tempfile

source = pathlib.Path(sys.argv[1])
fixture = {"__name__": "reciprocity_contract"}
exec(compile(source.read_text(encoding="utf-8"), str(source), "exec"), fixture)
nodes = fixture["NODES"]
run_id = "a" * 32
peers = {node: "peer-" + node for node in nodes}
records = {"a01-expected-peers.json": peers, "mpquic-units.json": [
    {"node": node, "mode": mode, "main_pid": index + 100, "socket_verified": True}
    for index, (node, mode) in enumerate((node, mode) for node in nodes for mode in ("client", "exit"))]}
echoes = {}
paths = {}
for index, (node, metadata) in enumerate(nodes.items()):
    for stage in ("before", "after"):
        records[f"reciprocity-node-{node}-{stage}.json"] = {
            "agent_pid": 1000 + index, "roles": {"client": True, "relay": True, "exit": True}}
    records[f"reciprocity-capture-{node}.json"] = {
        "truncated": False, "packet_socket_drops": 0, "direct_client_exit_packets": 0,
        "plaintext_leaks": 0, "wireguard_edges": {
            left["public"] + ">" + right["public"]: 4 for left in nodes.values() for right in nodes.values()},
        "destination_requests": {name: 4 for name in nodes},
        "destination_responses": {name: 4 for name in nodes}}
    payload = fixture["payload_for"](run_id, node)
    digest = hashlib.sha256(payload).hexdigest()
    records[f"reciprocity-app/{node}.json"] = {
        "success": True, "datagrams": 3, "destination": list(fixture["DESTINATION"]),
        "sent_sha256": digest, "response_sha256": digest, "sent_bytes": len(payload),
        "response_bytes": len(payload), "first_echo_ns": 100, "last_echo_ns": 3_000_000_100}
    echoes[node] = {"datagrams": 3, "sha256": digest, "bytes": len(payload),
                    "source_ips": [nodes[metadata["exit"]]["uplink"]]}
    paths[node] = f'context={index + 1:032x} path=1 relay={peers[metadata["relays"][0]]} exit={peers[metadata["exit"]]} state=2 rtt_us=1 bytes=300\n'
records["reciprocity-app/server.json"] = {"destination": list(fixture["DESTINATION"]), "flows": echoes}

with tempfile.TemporaryDirectory(prefix="volparossa-reciprocity-contract-") as temporary:
    root = pathlib.Path(temporary)
    (root / "reciprocity-app").mkdir()
    def evaluate(changed):
        for name, record in changed.items():
            fixture["write_json"](root / name, record)
        for node, path in paths.items():
            (root / f"reciprocity-paths-{node}.txt").write_text(path, encoding="ascii")
        return fixture["build_evidence"](root, run_id)
    result = evaluate(records)
    assert result["success"] and len(result["flows"]) == 4 and result["reciprocal_witnesses"]
    def rejected(name, mutate):
        changed = copy.deepcopy(records)
        mutate(changed)
        try:
            evaluate(changed)
        except ValueError:
            return
        raise AssertionError("accepted missing reciprocal evidence: " + name)
    rejected("PID replacement", lambda data: data["reciprocity-node-client-after.json"].update(agent_pid=99))
    rejected("role removed", lambda data: data["reciprocity-node-client-after.json"]["roles"].update(exit=False))
    rejected("echo substitution", lambda data: data["reciprocity-app/client.json"].update(response_sha256="bad"))
    rejected("direct source", lambda data: data["reciprocity-app/server.json"]["flows"]["client"].update(source_ips=[nodes["client"]["uplink"]]))
    rejected("native workers missing", lambda data: data["mpquic-units.json"].pop())
    rejected("native worker reused", lambda data: data["mpquic-units.json"][0].update(main_pid=data["mpquic-units.json"][1]["main_pid"]))
    rejected("one WireGuard leg missing", lambda data: data["reciprocity-capture-client.json"].update(wireguard_edges={}))
    rejected("nonconcurrent flows", lambda data: data["reciprocity-app/client.json"].update(first_echo_ns=3_000_000_000))
    for field in ("truncated", "packet_socket_drops", "direct_client_exit_packets", "plaintext_leaks"):
        rejected(field, lambda data, key=field: data["reciprocity-capture-client.json"].update({key: 1}))

assert fixture["parse_path"](paths["client"].replace("bytes=300", "bytes=0"))["native_reported_delivered_bytes"] == 0
for bad in ("", "context=" + "0" * 32 + " path=1 relay=a exit=b state=2 rtt_us=1 bytes=1", paths["client"].replace("path=1", "path=9"), paths["client"] * 2):
    try:
        fixture["parse_path"](bad)
    except ValueError:
        continue
    raise AssertionError("accepted invalid or ambiguous live path")

def frame(payload):
    udp = struct.pack("!HHHH", 50000, 50001, 8 + len(payload), 0) + payload
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                       socket.inet_aton("43.159.1.1"), socket.inet_aton("42.158.0.1"))
    return bytes(12) + b"\x08\x00" + ipv4 + udp
assert fixture["decode_frame"](frame(b"\x04\0\0\0" + bytes(40)))["wireguard_data"]
assert not fixture["decode_frame"](frame(b"\x04\0\0\0" + bytes(28)))["wireguard_data"]
assert not fixture["decode_frame"](frame(b"\x01\0\0\0" + bytes(40)))["wireguard_data"]
assert fixture["decode_frame"](frame(bytes(48))[:-1]) is None
assert fixture["decode_frame"](bytes(12)) is None
print("Reciprocity pure evidence/parser contract passed; no live datapath claim")
PYTHON

sh -n "$HERE/local-link-smoke.sh"
grep -F 'uplink=local_only; exit_role=false; exit_capacity=0' "$GUEST" >/dev/null
grep -F 'volparossa-local-link-runtime' "$WORKFLOW" >/dev/null
grep -F 'local_link_finalize_report' "$GUEST" >/dev/null
python3 -B "$HERE/test-local-link-smoke.py"
printf '%s\n' 'KVM alpha, reciprocity and local-link topology static contract passed'
