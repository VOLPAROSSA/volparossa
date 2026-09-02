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
grep -F 'native/volparossa-mpquic/scripts/fetch-upstream.sh --yes' "$WORKFLOW" \
    >/dev/null
grep -F 'native/volparossa-mpquic/scripts/build-upstream.sh' "$WORKFLOW" >/dev/null
grep -F 'VMP_BUILD_JOBS=2 VMP_RUN_TESTS=no' "$WORKFLOW" >/dev/null
grep -F -- '--mpquic "$VOLPAROSSA_ALPHA_MPQUIC"' "$WORKFLOW" >/dev/null
grep -F 'scp_to "$mpquic_path" /home/vpci/volparossa-mpquic' "$HOST" >/dev/null
grep -F -- '--mpquic /home/vpci/volparossa-mpquic' "$HOST" >/dev/null
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
[ "$(grep -Fc 'launch_helper exit "$EXIT_NODE"' "$GUEST")" -eq 1 ]
[ "$(grep -Fc 'launch_agent relay0 "$R0"' "$GUEST")" -eq 1 ]
grep -F 'launch_agent bootstrap1 "$B1"' "$GUEST" >/dev/null
grep -F 'launch_agent bootstrap2 "$B2"' "$GUEST" >/dev/null
grep -F 'verify_helper relay0 "$R0"' "$GUEST" >/dev/null
grep -F 'for cleanup_ns in "$DEST" "$EXIT_NODE" "$R2" "$R1" "$R0" "$B2" "$B1"' \
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
if grep -Eq 'launch_mpquic relay[012]' "$GUEST"; then exit 1; fi
grep -F -- '--socket /run/volparossa/native/mpquic.sock' "$GUEST" >/dev/null
grep -F 'native_mpquic:{ready:$mpquic,api_version:6,instances:$mpquic_records}' \
    "$GUEST" >/dev/null
grep -F 'DIRECT_CLIENT_EXIT_REACHABLE' "$GUEST" >/dev/null
grep -F 'ip -n "$underlay_ns" link add underlay type dummy' "$GUEST" >/dev/null
grep -F 'ip -n "$underlay_ns" route add default dev underlay scope global' "$GUEST" >/dev/null
[ "$(grep -Fc 'add_public_underlay ' "$GUEST")" -eq 7 ]
grep -F 'ip -n "$CLIENT" route add unreachable "$forbidden/32"' "$GUEST" >/dev/null
grep -F '10.241.20.2 10.241.21.2 10.241.22.2 10.241.31.1' "$GUEST" >/dev/null
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
grep -F 'bootstrap1|bootstrap2) required_active_peers=4' "$GUEST" >/dev/null
grep -F 'relay0) required_active_peers=3' "$GUEST" >/dev/null
grep -F 'relay1|relay2) required_active_peers=2' "$GUEST" >/dev/null
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
grep -F 'http3-acceptance-fixture" server' "$GUEST" >/dev/null
grep -F 'http3-acceptance-fixture" client a06' "$GUEST" >/dev/null
grep -F 'http3-acceptance-fixture" client a07' "$GUEST" >/dev/null
grep -F '43.159.1.1:52006 47.163.4.2:443' "$GUEST" >/dev/null
grep -F '43.159.1.1:52007 47.163.4.2:443' "$GUEST" >/dev/null
grep -F '"$WORK/client-fixtures/http3-cert.der"' "$GUEST" >/dev/null
grep -F 'connected: false' "$GUEST" >/dev/null
grep -F 'active contexts: 0' "$GUEST" >/dev/null
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
grep -F '.a09_forbidden_destinations.evidence.destination_egress_connections_for_denials == 0' \
    "$WORKFLOW" >/dev/null
grep -F '.a10_unverifiable_ech.evidence.destination_egress_connections_for_denials == 0' \
    "$WORKFLOW" >/dev/null
grep -F 'relay1_wireguard_data_bytes > 1048576' "$GUEST" >/dev/null
grep -F 'after_marker.relay2_wireguard_data_bytes > 1048576' "$GUEST" >/dev/null
grep -F 'def is_ipv4_multicast(address):' "$GUEST" >/dev/null
grep -F 'not is_ipv4_multicast(destination)' "$GUEST" >/dev/null
grep -F 'topology_control_public = {' "$GUEST" >/dev/null
grep -F 'allowed = topology_control_public | {' "$GUEST" >/dev/null
grep -F '47.163.4.2 whose appearance in an outer header is counted separately above' "$GUEST" \
    >/dev/null
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

printf '%s\n' 'KVM alpha topology static contract passed'
