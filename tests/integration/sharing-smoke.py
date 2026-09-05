#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable upload-sharing pressure/evidence fixture; never installs a scheduler."""

import hashlib
import importlib.util
import json
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time


SPEC = importlib.util.spec_from_file_location(
    "reciprocity_fixture", Path(__file__).with_name("reciprocity-smoke.py"))
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
BASE.NODES["exit"]["interfaces"] = [
    name for name in BASE.NODES["exit"]["interfaces"] if name not in ("xr0", "xr2", "xd")
] + ["sharing0"]
BASE.NODES["exit"].update(uplink="10.241.36.1", egress_interface="sharing0")
ORIGINAL_PAYLOAD = BASE.payload_for


def payload_for(run_id, node):
    seed = ORIGINAL_PAYLOAD(run_id, node)
    return (seed + hashlib.sha256(seed).digest() * 40)[:1150]


BASE.payload_for = payload_for
PHASES = ("idle", "owner", "recovery")
OWNER_DESTINATION = ("10.241.36.2", 18082)
running = True


def stop(*_args):
    global running
    running = False
    BASE.stop()


def read_json(path):
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("unsafe or oversized fixture evidence")
    return json.loads(path.read_text(encoding="ascii"))


def phase(directory):
    try:
        value = (directory / "phase").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return "waiting"
    if value not in (*PHASES, "waiting", "done"):
        raise ValueError("unknown bounded traffic phase")
    return value


class FirstEchoGate:
    """Hold exactly the first two same-flow echoes; never queue arbitrary payloads."""

    def __init__(self):
        self.source = None
        self.requests_before_first_echo = 0
        self.unlocked = False

    def receive(self, source):
        if self.unlocked:
            return 1
        if self.source is None:
            self.source = source
        elif source != self.source:
            raise ValueError("pipeline probe changed its exact Exit flow tuple")
        self.requests_before_first_echo += 1
        if self.requests_before_first_echo < 2:
            return 0
        self.unlocked = True
        return 2


def serve(directory, run_id, owner=False):
    expected = b"owner:" + payload_for(run_id, "exit") if owner else payload_for(run_id, "client")
    destination = OWNER_DESTINATION if owner else BASE.DESTINATION
    name = "owner-sink" if owner else "server"
    records = {name: {"datagrams": 0, "bytes": 0, "source_ips": []} for name in PHASES}
    pipeline = FirstEchoGate()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(destination)
        udp.settimeout(0.1)
        (directory / f"{name}.ready").write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 70
        while running and time.monotonic() < deadline:
            current = phase(directory)
            if current == "done":
                break
            try:
                payload, source = udp.recvfrom(2048)
            except TimeoutError:
                continue
            if payload != expected:
                raise ValueError("unexpected destination marker")
            if current in PHASES:
                record = records[current]
                record["datagrams"] += 1
                record["bytes"] += len(payload)
                if source[0] not in record["source_ips"]:
                    record["source_ips"].append(source[0])
                if record["datagrams"] > 150_000 or len(record["source_ips"]) > 2:
                    raise ValueError("fixture receive resource bound")
            if not owner:
                # A stop-and-wait Client cannot deliver the second datagram here. The two
                # responses correspond to two received requests, not transport duplication.
                for _ in range(pipeline.receive(source)):
                    udp.sendto(payload, source)
    BASE.write_json(directory / f"{name}.json", {
        "phases": records, "sha256": hashlib.sha256(expected).hexdigest(),
        "destination": list(destination), "payload_bytes": len(expected),
        "requests_before_first_echo": pipeline.requests_before_first_echo,
        "pipeline_source": list(pipeline.source) if pipeline.source is not None else None})


def pressure(directory, run_id, owner=False):
    payload = b"owner:" + payload_for(run_id, "exit") if owner else payload_for(run_id, "client")
    destination = OWNER_DESTINATION if owner else BASE.DESTINATION
    name = "owner" if owner else "client"
    offered_mbps = 24 if owner else 8
    records = {name: {"sent": 0, "echoes": 0} for name in PHASES}
    active_reported = False
    sent_before_first_echo = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("10.241.36.1" if owner else BASE.NODES["client"]["public"], 0))
        # Owner is a normal, unprivileged non-intercepted fixture socket. Contribution NEVER
        # sets SO_PRIORITY or SO_MARK: only the production Exit/WireGuard path classifies it.
        if owner:
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0)
        priority = udp.getsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY)
        udp.setblocking(False)
        deadline = time.monotonic() + 70
        next_send = time.monotonic()
        while running and time.monotonic() < deadline:
            current = phase(directory)
            if current == "done":
                break
            active = current in PHASES and (not owner or current == "owner")
            now = time.monotonic()
            if active:
                # At most eight packets per poll; never accumulate unlimited catch-up debt.
                next_send = max(next_send, now - 8 * len(payload) * 8 / (offered_mbps * 1e6))
                for _ in range(8):
                    if next_send > now:
                        break
                    try:
                        udp.sendto(payload, destination)
                    except BlockingIOError:
                        break
                    records[current]["sent"] += 1
                    if records[current]["sent"] > 150_000:
                        raise ValueError("fixture send resource bound")
                    next_send += len(payload) * 8 / (offered_mbps * 1e6)
            else:
                next_send = now
            readable, _, _ = select.select([udp] if not owner else [], [], [], 0.001)
            for _ in range(128 if readable else 0):
                try:
                    response, source = udp.recvfrom(2048)
                except BlockingIOError:
                    break
                if response != payload or source != destination:
                    raise ValueError("substituted protected application echo")
                if current in PHASES:
                    records[current]["echoes"] += 1
                    if not active_reported:
                        sent_before_first_echo = sum(record["sent"] for record in records.values())
                        (directory / "client.active").write_text("echo\n", encoding="ascii")
                        active_reported = True
        application = list(udp.getsockname())
    BASE.write_json(directory / f"{name}.json", {
        "phases": records, "application": application, "socket_priority": priority,
        "offered_mbps": offered_mbps, "payload_bytes": len(payload),
        "sent_before_first_echo": sent_before_first_echo,
        "sha256": hashlib.sha256(payload).hexdigest(), "completed": phase(directory) == "done"})


def diagnostic(namespace, arguments):
    result = subprocess.run(["ip", "netns", "exec", namespace, *arguments],
                            capture_output=True, check=True, timeout=5)
    if len(result.stdout) > 256 * 1024:
        raise ValueError("oversized kernel diagnostic")
    return json.loads(result.stdout)


def queue_snapshot(records):
    if len(records) != 5:
        raise ValueError("complete production sharing qdisc tree absent")
    def one(predicate):
        matches = [record for record in records if predicate(record)]
        if len(matches) != 1:
            raise ValueError("ambiguous sharing qdisc tree")
        return matches[0]
    total = one(lambda record: record["kind"] == "tbf" and record.get("root"))
    prio = one(lambda record: record["kind"] == "prio")
    owner = one(lambda record: record["kind"] == "bfifo" and
                record.get("parent") == prio["handle"] + "1")
    contribution = one(lambda record: record["kind"] == "tbf" and
                       record.get("parent") == prio["handle"] + "2")
    if prio.get("parent") != total["handle"] + "1":
        raise ValueError("owner priority tree is not below the physical upload cap")
    one(lambda record: record["kind"] == "bfifo" and
        record.get("parent") == contribution["handle"] + "1")
    return {name: {key: int(record[key]) for key in ("bytes", "packets", "drops", "overlimits")}
            for name, record in (("total", total), ("owner", owner), ("contribution", contribution))}


def snapshot(directory, namespace, label):
    qdiscs = diagnostic(namespace, ["tc", "-s", "-j", "qdisc", "show", "dev", "sharing0"])
    links = diagnostic(namespace, ["ip", "-s", "-j", "link", "show", "dev", "sharing0"])
    value = {"monotonic_ns": time.monotonic_ns(), "qdiscs": qdiscs,
             "egress_ifindex": links[0]["ifindex"],
             "physical_tx_bytes": links[0].get("stats64", links[0].get("stats"))["tx"]["bytes"]}
    if label not in ("baseline", "cleanup"):
        value["queues"] = queue_snapshot(qdiscs)
    BASE.write_json(directory / f"sharing-{label}.json", value)


def baseline_shape(records):
    return sorted([{key: value for key, value in record.items()
                    if key in ("kind", "handle", "root", "parent", "options")}
                   for record in records], key=lambda value: json.dumps(value, sort_keys=True))


def cleanup_evidence(directory):
    before = read_json(directory / "sharing-baseline.json")
    after = read_json(directory / "sharing-cleanup.json")
    exact = before["egress_ifindex"] == after["egress_ifindex"] and baseline_shape(
        before["qdiscs"]) == baseline_shape(after["qdiscs"])
    BASE.write_json(directory / "sharing-cleanup-evidence.json", {"baseline_restored": exact})
    if not exact:
        raise ValueError("sharing baseline was not exactly restored before namespace deletion")


def evaluate_windows(snapshots):
    windows = {}
    for name in PHASES:
        before, after = snapshots[name + "-before"], snapshots[name + "-after"]
        seconds = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
        if not 4 <= seconds <= 8 or before["egress_ifindex"] != after["egress_ifindex"]:
            raise ValueError("unstable egress or measurement interval")
        rates = {role: (after["queues"][role]["bytes"] - before["queues"][role]["bytes"]) * 8 / seconds / 1e6
                 for role in ("total", "owner", "contribution")}
        if any(rate < 0 for rate in rates.values()):
            raise ValueError("kernel counters reset during traffic")
        physical = (after["physical_tx_bytes"] - before["physical_tx_bytes"]) * 8 / seconds / 1e6
        if not 0 < physical <= 14 or rates["total"] > 14 or rates["contribution"] > 11.5:
            raise ValueError("real physical upload or contribution ceiling violated")
        windows[name] = {"seconds": seconds, "queue_mbps": rates, "physical_tx_mbps": physical}
    idle, owner, recovery = (windows[name]["queue_mbps"] for name in PHASES)
    if idle["contribution"] < 4 or recovery["contribution"] < max(4, idle["contribution"] * .6):
        raise ValueError("genuine contribution did not use idle upload or recover")
    if owner["owner"] < 8 or owner["contribution"] >= idle["contribution"] * .5:
        raise ValueError("real contribution did not yield to node-owned upload")
    return windows


def evidence(directory, run_id):
    windows = evaluate_windows({f"{phase}-{stage}": read_json(directory / f"sharing-{phase}-{stage}.json")
                                for phase in PHASES for stage in ("before", "after")})
    active_tree = read_json(directory / "sharing-recovery-after.json")
    route_cleanup = read_json(directory / "sharing-route-cleanup.json")
    if active_tree["egress_ifindex"] != route_cleanup["egress_ifindex"] or baseline_shape(
            active_tree["qdiscs"]) != baseline_shape(route_cleanup["qdiscs"]):
        raise ValueError("route-context cleanup retired or changed runtime-long sharing")
    peers = read_json(directory / "a01-expected-peers.json")
    path = BASE.parse_path((directory / "sharing-paths-client.txt").read_text(encoding="ascii"))
    relays = [node for node in ("relay0", "relay2") if peers[node] == path["relay_peer_id"]]
    if path["exit_peer_id"] != peers["exit"] or len(relays) != 1:
        raise ValueError("unexpected genuine selected one-relay route")
    captures = {node: read_json(directory / f"reciprocity-capture-{node}.json") for node in BASE.NODES}
    for record in captures.values():
        if any(record[field] for field in ("truncated", "packet_socket_drops", "direct_client_exit_packets", "plaintext_leaks")):
            raise ValueError("incomplete capture or direct/plaintext leakage")
    relay = relays[0]
    edge1 = BASE.NODES["client"]["public"] + ">" + BASE.NODES[relay]["public"]
    edge2 = BASE.NODES[relay]["public"] + ">" + BASE.NODES["exit"]["public"]
    legs = {"client_tx": captures["client"]["wireguard_edges"].get(edge1, 0),
            "relay_rx": captures[relay]["wireguard_edges"].get(edge1, 0),
            "relay_tx": captures[relay]["wireguard_edges"].get(edge2, 0),
            "exit_rx": captures["exit"]["wireguard_edges"].get(edge2, 0)}
    if not all(legs.values()):
        raise ValueError("genuine selected WireGuard legs absent")
    app = read_json(directory / "sharing-app/client.json")
    server = read_json(directory / "sharing-app/server.json")
    owner = read_json(directory / "sharing-app/owner.json")
    sink = read_json(directory / "sharing-app/owner-sink.json")
    digest = hashlib.sha256(payload_for(run_id, "client")).hexdigest()
    if not app["completed"] or not owner["completed"] or owner["socket_priority"] != 0 or app["sha256"] != digest or server["sha256"] != digest:
        raise ValueError("application/owner completion or echo hash mismatch")
    if server.get("requests_before_first_echo") != 2 or not isinstance(app.get("sent_before_first_echo"), int) or app["sent_before_first_echo"] < 2 or server.get("pipeline_source", [None])[0] != "10.241.36.1":
        raise ValueError("two real protected requests did not reach the exact Exit flow before its first echo")
    for name in ("idle", "recovery"):
        if app["phases"][name]["echoes"] < 8 or server["phases"][name]["source_ips"] != ["10.241.36.1"]:
            raise ValueError("protected echo or exact Exit source missing")
    if sink["phases"]["owner"]["bytes"] < 4_000_000 or sink["phases"]["owner"]["source_ips"] != ["10.241.36.1"]:
        raise ValueError("node-owned traffic did not reach its underlay sink")
    nodes = []
    for node in BASE.NODES:
        before = read_json(directory / f"reciprocity-node-{node}-before.json")
        after = read_json(directory / f"reciprocity-node-{node}-after.json")
        if before != after or before["agent_pid"] <= 0 or not all(before["roles"].values()):
            raise ValueError("combined-role daemon changed during pressure")
        nodes.append({**before, "same_agent_pid": True})
    BASE.write_json(directory / "sharing-evidence.json", {
        "success": True, "windows": windows, "nodes": nodes,
        "flow": {**path, "client_node": "client", "relay_node": relay, "exit_node": "exit",
                 "wireguard_both_legs": legs, "selected_exit_source_ip": "10.241.36.1",
                 "pipelining": {"destination_requests_before_first_echo": server["requests_before_first_echo"],
                                "application_sends_before_first_echo": app["sent_before_first_echo"],
                                "exact_exit_flow_source": server["pipeline_source"],
                                "every_echo_payload_and_source_checked": True},
                 "echo_sha256": digest, "application": app, "destination": server},
        "owner": {"traffic": "unprivileged node-owned underlay UDP, not protected browsing", "application": owner, "sink": sink},
        "scheduler": {"installed_by": "production node helper via sharing config", "interface": "sharing0",
                      "total_upload_mbps": 12, "contribution_upload_ceiling_mbps": 10,
                      "survived_route_context_cleanup": True},
        "scope": "actual Exit contribution and owner upload priority; no Relay contribution, download, WiFi airtime or multipath capacity claim"})


def main():
    mode, raw_directory, run_id, *extra = sys.argv[1:]
    directory = Path(raw_directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("unsafe fixture directory")
    payload_for(run_id, "client")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if mode in ("server", "owner-sink") and not extra:
        serve(directory, run_id, mode == "owner-sink")
    elif mode in ("client", "owner") and not extra:
        pressure(directory, run_id, mode == "owner")
    elif mode == "capture" and len(extra) == 1 and extra[0] in BASE.NODES:
        BASE.capture(directory, run_id, extra[0])
    elif mode == "snapshot" and len(extra) == 2 and extra[1] in ("baseline", "cleanup", "route-cleanup", *(f"{phase}-{stage}" for phase in PHASES for stage in ("before", "after"))):
        snapshot(directory, extra[0], extra[1])
    elif mode == "cleanup-evidence" and not extra:
        cleanup_evidence(directory)
    elif mode == "evidence" and not extra:
        evidence(directory, run_id)
    else:
        raise ValueError("invalid bounded sharing fixture operation")


if __name__ == "__main__":
    main()
