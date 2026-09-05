#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Concurrent local-only consumption and LAN relay contribution; bounded real UDP evidence."""

import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time


spec = importlib.util.spec_from_file_location("reciprocal_fixture", Path(__file__).with_name("reciprocity-smoke.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.NODES["client"]["public"] = "10.241.10.1"
CLIENT_ADDRESSES = {"10.241.10.1", "10.241.12.1"}
LAN_EDGES = {"relay0": ("10.241.10.1", "10.241.10.2"),
             "relay2": ("10.241.12.1", "10.241.12.2")}
INTERFACES = {"client": ["cr0", "cr2"],
              "relay0": "r0c r0x r0x2 r0b1 r0b2 underlay".split(),
              "relay2": "r2c r2x r2b1 r2b2 r2d underlay".split(),
              "exit": "xr0 xr1 xr2 xr3 xr4 xr5 xd underlay".split()}
FLOWS = {"client": {"exit": "exit", "relays": {"relay0", "relay2"},
                    "sources": CLIENT_ADDRESSES, "exit_addresses": {"46.162.3.1", "10.241.31.2"},
                    "uplink": "10.241.31.1", "egress_interface": "xd"},
         "relay0": {"exit": "relay2", "relays": {"client"},
                    "sources": {"42.158.0.1", "10.241.10.2"},
                    "exit_addresses": {"45.161.2.1", "10.241.12.2", "10.241.31.2"},
                    "uplink": "10.241.35.1", "egress_interface": "r2d"}}


def capture(directory, run_id, node):
    sockets = {}
    for interface in INTERFACES[node]:
        observer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        observer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        observer.bind((interface, 0))
        observer.setblocking(False)
        sockets[observer] = interface
    markers = {fixture.payload_for(run_id, name): name for name in FLOWS}
    record = {"node": node, "interfaces": INTERFACES[node], "observed_frames": 0,
              "truncated": False, "packet_socket_drops": 0, "wireguard_edges": {},
              "direct_client_exit_packets": 0, "plaintext_leaks": 0,
              "destination_requests": {name: 0 for name in FLOWS},
              "destination_responses": {name: 0 for name in FLOWS}}
    (directory / f"local-link-capture-{node}.ready").write_text("ready\n", encoding="ascii")
    deadline = time.monotonic() + 110
    while fixture.running and time.monotonic() < deadline:
        readable, _, _ = select.select(list(sockets), [], [], 0.2)
        for observer in readable:
            for _ in range(128):
                try:
                    frame = observer.recv(65535)
                except BlockingIOError:
                    break
                record["observed_frames"] += 1
                if record["observed_frames"] > 131072:
                    record["truncated"] = True
                    fixture.stop()
                    break
                packet = fixture.decode_frame(frame)
                if packet is None:
                    continue
                if any(packet["source"] in flow["sources"] and packet["destination"] in flow["exit_addresses"]
                       for flow in FLOWS.values()):
                    record["direct_client_exit_packets"] += 1
                if packet["wireguard_data"]:
                    edge = packet["source"] + ">" + packet["destination"]
                    if len(record["wireguard_edges"]) >= 64 and edge not in record["wireguard_edges"]:
                        record["truncated"] = True
                        fixture.stop()
                        break
                    record["wireguard_edges"][edge] = record["wireguard_edges"].get(edge, 0) + 1
                flow_name = markers.get(packet["payload"])
                if flow_name is None:
                    continue
                flow = FLOWS[flow_name]
                if node != flow["exit"] or sockets[observer] != flow["egress_interface"]:
                    record["plaintext_leaks"] += 1
                elif (packet["source"], packet["destination"], packet["destination_port"]) == (
                        flow["uplink"], *fixture.DESTINATION):
                    record["destination_requests"][flow_name] += 1
                elif packet["source"] == fixture.DESTINATION[0] and packet["destination"] == flow["uplink"]:
                    record["destination_responses"][flow_name] += 1
                else:
                    record["plaintext_leaks"] += 1
    for observer in sockets:
        _, drops = struct.unpack("II", observer.getsockopt(263, 6, 8))
        record["packet_socket_drops"] += drops
        observer.close()
    fixture.write_json(directory / f"local-link-capture-{node}.json", record)


def local_only_state(addresses, routes):
    assigned = []
    for interface in addresses:
        for address in interface.get("addr_info", []):
            value = ipaddress.ip_address(address["local"])
            if value.is_loopback or value.is_link_local:
                continue
            if not any(value in prefix for prefix in (
                    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("fc00::/7"))
                    if value.version == prefix.version):
                raise ValueError("local-only consumer acquired a non-LAN address")
            assigned.append(address["local"])
    if not CLIENT_ADDRESSES.issubset(assigned):
        raise ValueError("the two independent local contacts were not retained")
    if any(route.get("dst") in ("default", "0.0.0.0/0", "::/0") for route in routes):
        raise ValueError("local-only consumer acquired a main-table default route")
    return {"assigned_lan_addresses": sorted(assigned), "main_table_default_routes": 0,
            "independent_internet": False}


def build_evidence(directory, run_id):
    def read(name):
        path = directory / name
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError("unsafe or oversized evidence")
        return json.loads(path.read_text(encoding="ascii"))

    peers = read("a01-expected-peers.json")
    nodes = []
    for node in INTERFACES:
        before = read(f"local-link-node-{node}-before.json")
        after = read(f"local-link-node-{node}-after.json")
        roles = {"client": True, "relay": True, "exit": node != "client"}
        if before["roles"] != roles or after["roles"] != roles or before["agent_pid"] <= 0 or before["agent_pid"] != after["agent_pid"]:
            raise ValueError("capability roles changed or the daemon was replaced")
        nodes.append({"node": node, "peer_id": peers[node], "roles": roles,
                      "agent_pid_before": before["agent_pid"], "agent_pid_after": after["agent_pid"],
                      "same_agent_pid": True})
    offline = {stage: local_only_state(read(f"local-link-addresses-{stage}.json"),
                                      read(f"local-link-routes-{stage}.json"))
               for stage in ("before", "after")}
    native = read("mpquic-units.json")
    expected_native = {(node, mode) for node in INTERFACES for mode in ("client", "exit")
                       if (node, mode) != ("client", "exit")}
    if len(native) != 7 or {(item["node"], item["mode"]) for item in native} != expected_native or len({item["main_pid"] for item in native}) != 7 or not all(item["socket_verified"] and item["main_pid"] > 0 for item in native):
        raise ValueError("native worker roles do not match actual node capabilities")
    server = read("local-link-app/server.json")
    if server["destination"] != list(fixture.DESTINATION):
        raise ValueError("wrong exact destination")
    captures = {node: read(f"local-link-capture-{node}.json") for node in INTERFACES}
    flows = []
    for name, flow in FLOWS.items():
        path = fixture.parse_path((directory / f"local-link-paths-{name}.txt").read_text(encoding="ascii"))
        relay = next((node for node in flow["relays"] if peers[node] == path["relay_peer_id"]), None)
        exit_node = flow["exit"]
        if relay is None or path["exit_peer_id"] != peers[exit_node] or path["state"] != 3:
            raise ValueError("actual selected active route does not match the reciprocal local geometry")
        app = read(f"local-link-app/{name}.json")
        echo = server["flows"][name]
        digest = hashlib.sha256(fixture.payload_for(run_id, name)).hexdigest()
        if not app["success"] or app["datagrams"] < 2 or app["destination"] != list(fixture.DESTINATION) or app["sent_sha256"] != digest or app["response_sha256"] != digest or echo["sha256"] != digest or app["sent_bytes"] != app["response_bytes"] or app["sent_bytes"] != echo["bytes"] or echo["datagrams"] < app["datagrams"] or echo["source_ips"] != [flow["uplink"]]:
            raise ValueError("exact UDP echo or independent Exit source not proven")
        if name == "client":
            lan_source, lan_peer = LAN_EDGES[relay]
            second_source, second_peer = fixture.NODES[relay]["public"], fixture.NODES[exit_node]["public"]
            second_scope = "PublicInternet"
        else:
            lan_source, lan_peer = "10.241.10.2", "10.241.10.1"
            second_source, second_peer = "10.241.12.1", "10.241.12.2"
            second_scope = "DirectLocalLan"
        first_edge, second_edge = f"{lan_source}>{lan_peer}", f"{second_source}>{second_peer}"
        counts = {"client_tx": captures[name]["wireguard_edges"].get(first_edge, 0),
                  "relay_rx": captures[relay]["wireguard_edges"].get(first_edge, 0),
                  "relay_tx": captures[relay]["wireguard_edges"].get(second_edge, 0),
                  "exit_rx": captures[exit_node]["wireguard_edges"].get(second_edge, 0)}
        if not all(value > 0 for value in counts.values()) or captures[exit_node]["destination_requests"][name] <= 0 or captures[exit_node]["destination_responses"][name] <= 0:
            raise ValueError("both real WireGuard legs and Exit uplink must carry each application")
        flows.append({"success": True, "client_node": name, "relay_node": relay, "exit_node": exit_node,
                      **path, "transport": "single-path QUIC MASQUE UDP", "application": app,
                      "destination_echo": echo, "path_evidence": {"wireguard_both_legs": counts,
                          "client_relay_scope": "DirectLocalLan", "client_relay_source": lan_source,
                          "client_relay_peer": lan_peer, "relay_exit_scope": second_scope,
                          "relay_exit_source": second_source, "relay_exit_peer": second_peer,
                          "selected_exit_source_ip": flow["uplink"]}})
    if any(value["truncated"] or value["packet_socket_drops"] or value["direct_client_exit_packets"] or value["plaintext_leaks"] for value in captures.values()):
        raise ValueError("incomplete capture or direct/plaintext route leak")
    overlap = min(flow["application"]["last_echo_ns"] for flow in flows) - max(
        flow["application"]["first_echo_ns"] for flow in flows)
    if overlap < 2_000_000_000 or len({flow["route_context_id"] for flow in flows}) != 2:
        raise ValueError("consumption and contribution must overlap on distinct contexts")
    witness = {"node": "client", "peer_id": peers["client"], "same_agent_pid": True,
               "consuming_context": flows[0]["route_context_id"], "relaying_context": flows[1]["route_context_id"],
               "independent_internet": False, "exit_enabled": False}
    return {"success": True, "nodes": nodes, "flows": flows, "local_only": offline,
            "packet_captures": captures, "native_workers": native,
            "contribution_witness": witness, "concurrent_echo_overlap_ns": overlap,
            "contribution_scope": "the same local-only daemon simultaneously consumes and forwards another participant's end-to-end encrypted traffic between its LAN links"}


def main():
    if len(sys.argv) not in (4, 5):
        raise ValueError("expected mode, absolute directory, run ID, optional node")
    mode, directory, run_id = sys.argv[1:4]
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("unsafe fixture directory")
    signal.signal(signal.SIGTERM, fixture.stop)
    signal.signal(signal.SIGINT, fixture.stop)
    if mode == "server" and len(sys.argv) == 4:
        fixture.server(directory, run_id)
    elif mode == "client" and len(sys.argv) == 5 and sys.argv[4] in FLOWS:
        fixture.client(directory, run_id, sys.argv[4])
    elif mode == "capture" and len(sys.argv) == 5 and sys.argv[4] in INTERFACES:
        capture(directory, run_id, sys.argv[4])
    elif mode == "evidence" and len(sys.argv) == 4:
        fixture.write_json(directory / "local-link-evidence.json", build_evidence(directory, run_id))
    else:
        raise ValueError("invalid bounded fixture operation")


if __name__ == "__main__":
    main()
