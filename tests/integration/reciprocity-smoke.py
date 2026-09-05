#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded disposable UDP fixtures and evidence validation; no production networking."""

import hashlib
import json
from pathlib import Path
import re
import select
import signal
import socket
import struct
import sys
import time


NODES = {
    "client": {
        "public": "43.159.1.1", "exit": "exit", "uplink": "10.241.33.1",
        "interfaces": "cr0 cr1 cr2 cr3 cr4 cr5 cb1 cb2 cd underlay".split(),
        "egress_interface": "cd", "relays": ["relay0", "relay2"],
    },
    "relay0": {
        "public": "42.158.0.1", "exit": "relay2", "uplink": "10.241.34.1",
        "interfaces": "r0c r0x r0x2 r0b1 r0b2 r0d underlay".split(),
        "egress_interface": "r0d", "relays": ["client", "exit"],
    },
    "relay2": {
        "public": "45.161.2.1", "exit": "relay0", "uplink": "10.241.35.1",
        "interfaces": "r2c r2x r2b1 r2b2 r2d underlay".split(),
        "egress_interface": "r2d", "relays": ["client", "exit"],
    },
    "exit": {
        "public": "46.162.3.1", "exit": "client", "uplink": "10.241.31.1",
        "interfaces": "xr0 xr1 xr2 xr3 xr4 xr5 xd underlay".split(),
        "egress_interface": "xd", "relays": ["relay0", "relay2"],
    },
}
DESTINATION = ("10.241.31.2", 18081)
PATH_PATTERN = re.compile(
    r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) "
    r"state=([0-9]+) rtt_us=([0-9]+) bytes=([0-9]+)"
)
running = True


def stop(*_unused):
    global running
    running = False


def write_json(path, value):
    # Atomic replacement lets the root observer read only complete bounded fixture records.
    temporary = Path(str(path) + ".new")
    with temporary.open("w", encoding="ascii") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    temporary.replace(path)


def payload_for(run_id, node):
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("invalid run ID")
    seed = b"volparossa-reciprocity:" + run_id.encode("ascii") + b":" + node.encode("ascii")
    return seed + b":" + hashlib.sha256(seed).digest() * 8


def server(directory, run_id):
    expected = {payload_for(run_id, node): node for node in NODES}
    evidence = {node: {"datagrams": 0, "source_ips": [], "sha256":
                         hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
                for payload, node in expected.items()}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(DESTINATION)
        udp.settimeout(0.2)
        (directory / "server.ready").write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 360
        while running and time.monotonic() < deadline:
            try:
                payload, source = udp.recvfrom(2048)
            except TimeoutError:
                continue
            node = expected.get(payload)
            if node is None:
                raise ValueError("unexpected destination datagram")
            record = evidence[node]
            record["datagrams"] += 1
            if record["datagrams"] > 1024:
                raise ValueError("destination datagram limit")
            if source[0] not in record["source_ips"]:
                record["source_ips"].append(source[0])
            if len(record["source_ips"]) > 4:
                raise ValueError("destination source bound")
            if udp.sendto(payload, source) != len(payload):
                raise ValueError("short destination echo")
    write_json(directory / "server.json", {"destination": list(DESTINATION), "flows": evidence})


def client(directory, run_id, node):
    payload = payload_for(run_id, node)
    deadline = time.monotonic() + 100
    while running and not (directory / "go").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not (directory / "go").exists():
        raise ValueError("application start barrier expired")
    record = {"node": node, "destination": list(DESTINATION), "datagrams": 0,
              "sent_bytes": len(payload), "sent_sha256": hashlib.sha256(payload).hexdigest(),
              "response_bytes": 0, "response_sha256": None, "first_echo_ns": None,
              "last_echo_ns": None, "success": False}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as application:
        application.bind((NODES[node]["public"], 0))
        application.settimeout(2)
        deadline = time.monotonic() + 90
        while running and time.monotonic() < deadline and not (directory / "stop").exists():
            if application.sendto(payload, DESTINATION) != len(payload):
                raise ValueError("short application UDP send")
            try:
                response, source = application.recvfrom(2048)
            except TimeoutError:
                # Real route admission is asynchronous; retry the same pinned application tuple.
                continue
            if source != DESTINATION or response != payload:
                raise ValueError("application received a substituted UDP response")
            record["datagrams"] += 1
            record["response_bytes"] = len(response)
            record["response_sha256"] = hashlib.sha256(response).hexdigest()
            record["last_echo_ns"] = time.monotonic_ns()
            if record["first_echo_ns"] is None:
                record["first_echo_ns"] = record["last_echo_ns"]
                (directory / f"{node}.active").write_text("echo\n", encoding="ascii")
            time.sleep(0.2)
        record["application"] = list(application.getsockname())
    record["success"] = record["datagrams"] >= 2 and (directory / "stop").exists()
    write_json(directory / f"{node}.json", record)
    if not record["success"]:
        raise ValueError("bounded concurrent echo did not complete")


def decode_frame(frame):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    header_length = (frame[14] & 15) * 4
    total_length = struct.unpack_from("!H", frame, 16)[0]
    if frame[14] >> 4 != 4 or header_length < 20 or total_length < header_length:
        return None
    if len(frame) < 14 + total_length or struct.unpack_from("!H", frame, 20)[0] & 0x3FFF:
        return None
    result = {"source": socket.inet_ntoa(frame[26:30]),
              "destination": socket.inet_ntoa(frame[30:34]), "protocol": frame[23],
              "wireguard_data": False, "payload": b"", "destination_port": 0}
    if result["protocol"] != socket.IPPROTO_UDP or total_length < header_length + 8:
        return result
    offset = 14 + header_length
    udp_length = struct.unpack_from("!H", frame, offset + 4)[0]
    if udp_length < 8 or udp_length > total_length - header_length:
        return None
    result["destination_port"] = struct.unpack_from("!H", frame, offset + 2)[0]
    result["payload"] = frame[offset + 8:offset + udp_length]
    result["wireguard_data"] = udp_length > 40 and result["payload"][:4] == b"\x04\0\0\0"
    return result


def capture(directory, run_id, node):
    metadata = NODES[node]
    sockets = {}
    for interface in metadata["interfaces"]:
        observer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        observer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        observer.bind((interface, 0))
        observer.setblocking(False)
        sockets[observer] = interface
    markers = {payload_for(run_id, name): name for name in NODES}
    record = {"node": node, "interfaces": metadata["interfaces"], "observed_frames": 0,
              "truncated": False, "packet_socket_drops": 0, "wireguard_edges": {},
              "direct_client_exit_packets": 0, "plaintext_leaks": 0,
              "destination_requests": {name: 0 for name in NODES},
              "destination_responses": {name: 0 for name in NODES}}
    (directory / f"reciprocity-capture-{node}.ready").write_text("ready\n", encoding="ascii")
    deadline = time.monotonic() + 110
    while running and time.monotonic() < deadline:
        readable, _, _ = select.select(list(sockets), [], [], 0.2)
        for observer in readable:
            # Bound each drain so signals/deadlines remain responsive during a flood.
            for _ in range(128):
                try:
                    frame = observer.recv(65535)
                except BlockingIOError:
                    break
                record["observed_frames"] += 1
                if record["observed_frames"] > 131072:
                    record["truncated"] = True
                    stop()
                    break
                packet = decode_frame(frame)
                if packet is None:
                    continue
                if packet["source"] == metadata["public"] and packet["destination"] == NODES[metadata["exit"]]["public"]:
                    record["direct_client_exit_packets"] += 1
                if packet["wireguard_data"]:
                    edge = packet["source"] + ">" + packet["destination"]
                    if len(record["wireguard_edges"]) >= 64 and edge not in record["wireguard_edges"]:
                        record["truncated"] = True
                        stop()
                        break
                    record["wireguard_edges"][edge] = record["wireguard_edges"].get(edge, 0) + 1
                flow = markers.get(packet["payload"])
                if flow is not None:
                    expected_exit = NODES[flow]["exit"]
                    if node != expected_exit or sockets[observer] != metadata["egress_interface"]:
                        record["plaintext_leaks"] += 1
                    elif packet["source"] == metadata["uplink"] and packet["destination"] == DESTINATION[0] and packet["destination_port"] == DESTINATION[1]:
                        record["destination_requests"][flow] += 1
                    elif packet["source"] == DESTINATION[0] and packet["destination"] == metadata["uplink"]:
                        record["destination_responses"][flow] += 1
                    else:
                        record["plaintext_leaks"] += 1
    for observer in sockets:
        # Linux PACKET_STATISTICS is read/reset per socket and reports dropped capture frames.
        _, drops = struct.unpack("II", observer.getsockopt(263, 6, 8))
        record["packet_socket_drops"] += drops
        observer.close()
    write_json(directory / f"reciprocity-capture-{node}.json", record)


def parse_path(source):
    paths = [match.groups() for line in source.splitlines()
             if (match := PATH_PATTERN.fullmatch(line))]
    if len(paths) != 1:
        raise ValueError("each consuming node must have exactly one live selected UDP path")
    context, path_id, relay, exit_peer, state, rtt, byte_count = paths[0]
    if context == "0" * 32:
        raise ValueError("selected native UDP context is invalid")
    return {"route_context_id": context, "path_id": int(path_id), "relay_peer_id": relay,
            "exit_peer_id": exit_peer, "state": int(state), "smoothed_rtt_us": int(rtt),
            "native_reported_delivered_bytes": int(byte_count)}


def build_evidence(directory, run_id):
    def read(name):
        path = directory / name
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError("unsafe or oversized evidence")
        return json.loads(path.read_text(encoding="ascii"))

    peers = read("a01-expected-peers.json")
    native = read("mpquic-units.json")
    if len(native) != 8 or {(entry["node"], entry["mode"]) for entry in native} != {
        (node, mode) for node in NODES for mode in ("client", "exit")
    } or len({entry["main_pid"] for entry in native}) != 8 or not all(
        entry["socket_verified"] and entry["main_pid"] > 0 for entry in native
    ):
        raise ValueError("eight distinct immutable-mode native workers were not verified")
    captures = {node: read(f"reciprocity-capture-{node}.json") for node in NODES}
    destination = read("reciprocity-app/server.json")
    if destination["destination"] != list(DESTINATION):
        raise ValueError("wrong policy-pinned destination")
    nodes, flows = [], []
    for node, metadata in NODES.items():
        before = read(f"reciprocity-node-{node}-before.json")
        after = read(f"reciprocity-node-{node}-after.json")
        roles = {"client": True, "relay": True, "exit": True}
        if before["roles"] != roles or after["roles"] != roles or before["agent_pid"] <= 0 or before["agent_pid"] != after["agent_pid"]:
            raise ValueError("contribution and consumption did not retain the same combined-role daemon")
        nodes.append({"node": node, "peer_id": peers[node], "roles": roles,
                      "agent_pid_before": before["agent_pid"], "agent_pid_after": after["agent_pid"],
                      "same_agent_pid": True})
        path = parse_path((directory / f"reciprocity-paths-{node}.txt").read_text(encoding="ascii"))
        exit_node = metadata["exit"]
        relays = [name for name in metadata["relays"] if peers[name] == path["relay_peer_id"]]
        if path["exit_peer_id"] != peers[exit_node] or len(relays) != 1:
            raise ValueError("real selected path does not match one-relay reciprocal square")
        relay = relays[0]
        app = read(f"reciprocity-app/{node}.json")
        echo = destination["flows"][node]
        digest = hashlib.sha256(payload_for(run_id, node)).hexdigest()
        if not app["success"] or app["datagrams"] < 2 or app["destination"] != list(DESTINATION) or app["sent_sha256"] != digest or app["response_sha256"] != digest or echo["sha256"] != digest or app["sent_bytes"] != app["response_bytes"] or app["sent_bytes"] != echo["bytes"] or echo["datagrams"] < app["datagrams"] or echo["source_ips"] != [NODES[exit_node]["uplink"]]:
            raise ValueError("UDP echo hash, bytes or selected Exit source address mismatch")
        client_edge = metadata["public"] + ">" + NODES[relay]["public"]
        exit_edge = NODES[relay]["public"] + ">" + NODES[exit_node]["public"]
        edge_counts = {
            "client_tx": captures[node]["wireguard_edges"].get(client_edge, 0),
            "relay_rx": captures[relay]["wireguard_edges"].get(client_edge, 0),
            "relay_tx": captures[relay]["wireguard_edges"].get(exit_edge, 0),
            "exit_rx": captures[exit_node]["wireguard_edges"].get(exit_edge, 0),
        }
        if not all(value > 0 for value in edge_counts.values()):
            raise ValueError("selected WireGuard path did not carry packets on both legs")
        if captures[exit_node]["destination_requests"][node] <= 0 or captures[exit_node]["destination_responses"][node] <= 0:
            raise ValueError("selected Exit did not carry the exact application echo on its uplink")
        flows.append({"success": True, "client_node": node, "client_peer_id": peers[node],
                      "relay_node": relay, "exit_node": exit_node, **path,
                      "transport": "single-path QUIC MASQUE UDP", "application": app,
                      "destination_echo": echo, "path_evidence": {
                          "wireguard_both_legs": edge_counts,
                          "native_reported_delivered_bytes": path["native_reported_delivered_bytes"],
                          "native_counter_note": "observed status counter; may omit QUIC DATAGRAM bytes and is not an application byte counter",
                          "selected_exit_source_ip": NODES[exit_node]["uplink"],
                          "destination_request_datagrams": captures[exit_node]["destination_requests"][node],
                          "destination_response_datagrams": captures[exit_node]["destination_responses"][node],
                      }})
    for capture_record in captures.values():
        if capture_record["truncated"] or capture_record["packet_socket_drops"] or capture_record["direct_client_exit_packets"] or capture_record["plaintext_leaks"]:
            raise ValueError("incomplete capture or direct/plaintext path leak")
    overlap = min(flow["application"]["last_echo_ns"] for flow in flows) - max(
        flow["application"]["first_echo_ns"] for flow in flows)
    if overlap < 2_000_000_000:
        raise ValueError("four genuine application streams did not overlap for two seconds")
    witnesses = [{"node": node, "peer_id": peers[node],
                  "consuming_context": next(flow["route_context_id"] for flow in flows if flow["client_node"] == node),
                  "relaying_contexts": [flow["route_context_id"] for flow in flows if flow["relay_node"] == node],
                  "exiting_contexts": [flow["route_context_id"] for flow in flows if flow["exit_node"] == node],
                  "same_agent_pid": True} for node in NODES
                 if any(flow["relay_node"] == node for flow in flows)
                 and any(flow["exit_node"] == node for flow in flows)]
    if not witnesses or len({flow["route_context_id"] for flow in flows}) != 4:
        raise ValueError("no distinct-context simultaneous reciprocal witness")
    return {"success": True, "flows": flows, "nodes": nodes, "reciprocal_witnesses": witnesses,
            "concurrent_echo_overlap_ns": overlap, "packet_captures": captures, "native_workers": native}


def main():
    if len(sys.argv) not in (4, 5):
        raise ValueError("expected mode, directory, run ID, and optional node")
    mode, directory, run_id = sys.argv[1:4]
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("fixture directory must be absolute and not a symlink")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if mode == "server" and len(sys.argv) == 4:
        server(directory, run_id)
    elif mode == "client" and len(sys.argv) == 5 and sys.argv[4] in NODES:
        client(directory, run_id, sys.argv[4])
    elif mode == "capture" and len(sys.argv) == 5 and sys.argv[4] in NODES:
        capture(directory, run_id, sys.argv[4])
    elif mode == "evidence" and len(sys.argv) == 4:
        write_json(directory / "reciprocity-evidence.json", build_evidence(directory, run_id))
    else:
        raise ValueError("invalid bounded fixture operation")


if __name__ == "__main__":
    main()
