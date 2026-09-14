#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real protected download and owner traffic on one disposable receive bottleneck."""

import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time

SPEC = importlib.util.spec_from_file_location(
    "reciprocity_fixture", Path(__file__).with_name("reciprocity-smoke.py"))
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
for node, removed in (("relay0", "r0x"), ("relay2", "r2x")):
    BASE.NODES[node]["interfaces"].remove(removed)
    BASE.NODES[node]["interfaces"].append("down0")
PHASES = ("baseline", "idle", "owner", "recovery", "expiry")
running = True


def stop(*_args):
    global running
    running = False


def read_json(path):
    if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("unsafe or oversized download evidence")
    return json.loads(path.read_text(encoding="ascii"))


def payload_for(run_id, owner=False):
    seed = BASE.payload_for(run_id, "client")
    return (b"owner:" if owner else b"") + (seed + hashlib.sha256(seed).digest() * 40)[:1150]


def phase(directory):
    try:
        value = (directory / "phase").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return "waiting"
    if value not in (*PHASES, "waiting", "done"):
        raise ValueError("invalid download phase")
    return value


def endpoints(directory, owner):
    if not owner:
        return BASE.NODES["client"]["public"], BASE.DESTINATION
    relay = read_json(directory.parent / "download-sharing-selection.json")["relay_node"]
    if relay not in ("relay0", "relay2"):
        raise ValueError("unexpected selected Relay")
    prefix = "10.241.37." if relay == "relay0" else "10.241.38."
    return prefix + "2", (prefix + "1", 18082)


def application(directory, run_id, mode):
    owner = mode in ("owner", "owner-sink")
    sender = mode in ("client", "owner")
    payload = payload_for(run_id, owner)
    source, destination = endpoints(directory, owner)
    records = {name: {"sent": 0, "received": 0, "bytes": 0, "source_ips": []}
               for name in PHASES}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((source, 0) if sender else destination)
        udp.setblocking(False)
        priority = udp.getsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY)
        BASE.write_json(directory / f"{mode}.live.json", {"phases": records})
        (directory / f"{mode}.ready").write_text("ready\n", encoding="ascii")
        deadline, next_send, next_record = time.monotonic() + 100, time.monotonic(), 0
        offered_mbps = 24 if owner else 8
        spacing = len(payload) * 8 / (offered_mbps * 1e6)
        while running and time.monotonic() < deadline:
            current, now = phase(directory), time.monotonic()
            if current == "done":
                break
            sending = current in ("baseline", "owner") if owner else current in PHASES[1:]
            if sender and sending:
                next_send = max(next_send, now - 8 * spacing)
                for _ in range(8):
                    if next_send > now:
                        break
                    try:
                        udp.sendto(payload, destination)
                    except BlockingIOError:
                        break
                    records[current]["sent"] += 1
                    next_send += spacing
            else:
                next_send = now
            readable, _, _ = select.select([udp] if mode != "owner" else [], [], [], .001)
            for _ in range(128 if readable else 0):
                try:
                    response, peer = udp.recvfrom(2048)
                except BlockingIOError:
                    break
                if response != payload or (mode == "client" and peer != destination):
                    raise ValueError("protected payload or pinned destination substituted")
                if current in PHASES:
                    record = records[current]
                    record["received"] += 1
                    record["bytes"] += len(response)
                    if peer[0] not in record["source_ips"]:
                        record["source_ips"].append(peer[0])
                    if record["received"] > 200_000 or len(record["source_ips"]) > 2:
                        raise ValueError("download fixture receive limit")
                if mode == "server":
                    try:
                        udp.sendto(response, peer)
                    except BlockingIOError:
                        pass  # Offered UDP overload is loss, never a fabricated echo.
                if mode == "client" and not (directory / "client.active").exists():
                    (directory / "client.active").write_text("echo\n", encoding="ascii")
            if now >= next_record:
                BASE.write_json(directory / f"{mode}.live.json", {
                    "monotonic_ns": time.monotonic_ns(), "phases": records})
                next_record = now + .1
        BASE.write_json(directory / f"{mode}.json", {
            "phases": records, "sha256": hashlib.sha256(payload).hexdigest(),
            "payload_bytes": len(payload), "application": list(udp.getsockname()),
            "socket_priority": priority, "completed": phase(directory) == "done"})


def stop_intake(observer):
    class Instruction(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    program = (Instruction * 1)(Instruction(6, 0, 0, 0))
    observer.setsockopt(socket.SOL_SOCKET, 26, struct.pack("@HP", 1, ctypes.addressof(program)))


def capture(directory, run_id, node):
    metadata = BASE.NODES[node]
    observers, statistics = {}, {}
    for interface in metadata["interfaces"]:
        # Start with no protocol: there must be no wildcard intake before the exact bind.
        observer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        observer.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)
        observer.bind((interface, 3))
        observer.setblocking(False)
        observers[observer] = interface
        statistics[interface] = {"observed_frames": 0, "intake_stopped": False}
    marker = payload_for(run_id)
    record = {"node": node, "truncated": False, "direct_client_exit_packets": 0,
              "plaintext_leaks": 0, "wireguard_edges": {}, "wireguard_bytes": {}}
    def receive(observer):
        try:
            frame = observer.recv(65535)
        except BlockingIOError:
            return False
        row = statistics[observers[observer]]
        row["observed_frames"] += 1
        if row["observed_frames"] > 250_000:
            record["truncated"] = True
            raise ValueError("download capture frame bound")
        packet = BASE.decode_frame(frame)
        if packet is None:
            return True
        if packet["source"] == BASE.NODES["client"]["public"] and packet["destination"] == BASE.NODES["exit"]["public"]:
            record["direct_client_exit_packets"] += 1
        if packet["wireguard_data"]:
            edge = packet["source"] + ">" + packet["destination"]
            if len(record["wireguard_edges"]) > 64:
                raise ValueError("capture edge bound")
            record["wireguard_edges"][edge] = record["wireguard_edges"].get(edge, 0) + 1
            record["wireguard_bytes"][edge] = record["wireguard_bytes"].get(edge, 0) + len(frame)
        if packet["payload"] == marker and (node != "exit" or observers[observer] != "xd"):
            record["plaintext_leaks"] += 1
        return True
    (directory / f"download-sharing-capture-{node}.ready").write_text("ready\n", encoding="ascii")
    deadline = time.monotonic() + 100
    while running and time.monotonic() < deadline:
        readable, _, _ = select.select(list(observers), [], [], .1)
        for observer in readable:
            for _ in range(128):
                if not receive(observer):
                    break
    # Stop new intake first, then empty each finite pre-stop queue and require exact stats.
    for observer, interface in observers.items():
        stop_intake(observer)
        statistics[interface]["intake_stopped"] = True
    drain_deadline = time.monotonic() + 3
    for observer, interface in observers.items():
        while time.monotonic() < drain_deadline and receive(observer):
            pass
        packets, drops = struct.unpack("II", observer.getsockopt(263, 6, 8))
        statistics[interface].update(packet_socket_packets=packets, packet_socket_drops=drops)
        observer.close()
    record["interfaces"] = statistics
    record["complete"] = not record["truncated"] and all(
        row["intake_stopped"] and row["packet_socket_drops"] == 0 and
        row["observed_frames"] == row["packet_socket_packets"] for row in statistics.values())
    BASE.write_json(directory / f"download-sharing-capture-{node}.json", record)
    if not record["complete"]:
        raise ValueError("download capture did not account for every admitted frame")


def selection(directory):
    path = BASE.parse_path((directory / "download-sharing-paths-before.txt").read_text(encoding="ascii"))
    peers = read_json(directory / "a01-expected-peers.json")
    relays = [node for node in ("relay0", "relay2") if peers[node] == path["relay_peer_id"]]
    if len(relays) != 1 or path["exit_peer_id"] != peers["exit"]:
        raise ValueError("unexpected protected download route")
    BASE.write_json(directory / "download-sharing-selection.json", {**path, "relay_node": relays[0]})


def app_snapshot(directory, label):
    records = {mode: read_json(directory / "download-sharing-app" / f"{mode}.live.json")
               for mode in ("client", "server", "owner", "owner-sink")}
    BASE.write_json(directory / f"download-sharing-app-{label}.json", {
        "monotonic_ns": time.monotonic_ns(), "records": records})


def evidence(directory, run_id):
    windows = {}
    for name in PHASES:
        before, after = (read_json(directory / f"download-sharing-{name}-{stage}.json")
                         for stage in ("before", "after"))
        apps = [read_json(directory / f"download-sharing-app-{name}-{stage}.json")
                for stage in ("before", "after")]
        seconds = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
        app_seconds = (apps[1]["monotonic_ns"] - apps[0]["monotonic_ns"]) / 1e9
        if not 4 <= seconds <= 9 or not 4 <= app_seconds <= 9:
            raise ValueError("invalid bounded download measurement window")
        def app_rate(mode):
            values = [row["records"][mode]["phases"][name]["bytes"] for row in apps]
            return (values[1] - values[0]) * 8 / app_seconds / 1e6
        values = {"receiver_wire_mbps": (after["receiver_total_bytes"] - before["receiver_total_bytes"]) * 8 / seconds / 1e6,
                  "sender_queue_mbps": (after["sender_queue"]["bytes"] - before["sender_queue"]["bytes"]) * 8 / seconds / 1e6,
                  "owner_application_mbps": app_rate("owner-sink"),
                  "contribution_application_mbps": app_rate("client"), "seconds": seconds}
        if any(value < 0 for value in values.values()) or values["receiver_wire_mbps"] > 14:
            raise ValueError("counter reset or physical receive bottleneck violated")
        if before["sender_identity"] != after["sender_identity"] or before["receiver_ifindex"] != after["receiver_ifindex"]:
            raise ValueError("the measured sender or receiver was replaced")
        windows[name] = values
    baseline, idle, owner, recovery = (windows[name] for name in PHASES[:4])
    if baseline["owner_application_mbps"] < 8 or owner["owner_application_mbps"] < .8 * baseline["owner_application_mbps"]:
        raise ValueError("shared download displaced too much node-owned download")
    if min(idle["contribution_application_mbps"], recovery["contribution_application_mbps"]) < 1:
        raise ValueError("real protected download did not use or recover idle capacity")
    if owner["contribution_application_mbps"] >= .5 * idle["contribution_application_mbps"]:
        raise ValueError("sender did not yield before the receiver bottleneck")
    if idle["sender_queue_mbps"] <= 0 or recovery["sender_queue_mbps"] <= 0:
        raise ValueError("real production sender queue carried no contribution")
    expire_before, expire_after = (read_json(directory / f"download-sharing-expiry-{stage}.json")
                                    for stage in ("before", "after"))
    stale = expire_after["sender_queue"]["bytes"] - expire_before["sender_queue"]["bytes"]
    if stale != 0 or windows["expiry"]["contribution_application_mbps"] != 0:
        raise ValueError("expired signed budget still transmits new contribution")
    stopped, drained = (read_json(directory / f"download-sharing-stopped-{stage}.json")
                        for stage in ("before", "after"))
    # The stop window includes up to the remaining 5-second valid allowance, not just queue tail.
    bound = stopped["sender_maximum_queued_bytes"] + 5 * 1_250_000 + 65_536
    tail = drained["sender_queue"]["bytes"] - stopped["sender_queue"]["bytes"]
    if not 0 <= tail <= bound:
        raise ValueError("sender exceeded remaining validity plus its finite queued tail")
    path = read_json(directory / "download-sharing-selection.json")
    after_path = BASE.parse_path((directory / "download-sharing-paths-after.txt").read_text(encoding="ascii"))
    if any(path[key] != after_path[key] for key in ("route_context_id", "path_id", "relay_peer_id", "exit_peer_id")):
        raise ValueError("download proof replaced its route context")
    captures = {node: read_json(directory / f"download-sharing-capture-{node}.json") for node in BASE.NODES}
    if not all(row["complete"] and not row["direct_client_exit_packets"] and not row["plaintext_leaks"] for row in captures.values()):
        raise ValueError("privacy capture incomplete or leaked direct/plaintext traffic")
    relay = path["relay_node"]
    c, r, x = (BASE.NODES[node]["public"] for node in ("client", relay, "exit"))
    legs = {"client_to_relay": captures["client"]["wireguard_edges"].get(c + ">" + r, 0),
            "relay_to_exit": captures[relay]["wireguard_edges"].get(r + ">" + x, 0),
            "exit_to_relay": captures["exit"]["wireguard_edges"].get(x + ">" + r, 0),
            "relay_to_client": captures[relay]["wireguard_edges"].get(r + ">" + c, 0)}
    if not all(legs.values()):
        raise ValueError("protected download did not cross both real WireGuard legs")
    nodes = []
    for node in BASE.NODES:
        before, after = (read_json(directory / f"reciprocity-node-{node}-{stage}.json") for stage in ("before", "after"))
        if before != after or before["agent_pid"] <= 0 or not all(before["roles"].values()):
            raise ValueError("combined-role daemon changed")
        nodes.append(before)
    app = read_json(directory / "download-sharing-app/client.json")
    server = read_json(directory / "download-sharing-app/server.json")
    owner_app = read_json(directory / "download-sharing-app/owner.json")
    sink = read_json(directory / "download-sharing-app/owner-sink.json")
    digest = hashlib.sha256(payload_for(run_id)).hexdigest()
    if app["sha256"] != digest or server["sha256"] != digest or not all(
        row["completed"] for row in (app, server, owner_app, sink)) or owner_app["socket_priority"] != 0:
        raise ValueError("download application did not finish with checked content")
    if any(server["phases"][name]["source_ips"] != ["10.241.31.1"] for name in ("idle", "recovery")):
        raise ValueError("protected destination did not see only the selected Exit")
    BASE.write_json(directory / "download-sharing-evidence.json", {
        "success": True, "windows": windows, "nodes": nodes,
        "flow": {**path, "same_route_context": True, "wireguard_both_legs": legs, "sha256": digest},
        "expiry": {"refresh_paused": True, "drained_tail_bytes": tail, "bounded_tail_bytes": bound,
                   "contribution_after_expiry_bytes": stale, "grace_seconds": 7},
        "privacy": {"complete": True, "drops": 0},
        "scope": "one manually configured IPv4 receive interface, cooperative Exit sender, real owner UDP; no automatic capacity, ISP or Wi-Fi airtime guarantee"})


def main():
    mode, raw_directory, run_id, *extra = sys.argv[1:]
    directory = Path(raw_directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("unsafe fixture directory")
    payload_for(run_id)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if mode in ("client", "server", "owner", "owner-sink") and not extra:
        application(directory, run_id, mode)
    elif mode == "capture" and len(extra) == 1 and extra[0] in BASE.NODES:
        capture(directory, run_id, extra[0])
    elif mode == "selection" and not extra:
        selection(directory)
    elif mode == "app-snapshot" and len(extra) == 1 and extra[0] in (
            f"{phase}-{stage}" for phase in PHASES for stage in ("before", "after")):
        app_snapshot(directory, extra[0])
    elif mode == "evidence" and not extra:
        evidence(directory, run_id)
    else:
        raise ValueError("invalid bounded download fixture operation")


if __name__ == "__main__":
    main()
