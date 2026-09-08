#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded independent-uplink transition evidence; run only in the disposable VM."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import signal
import socket
import sys
import time

spec = importlib.util.spec_from_file_location("local_fixture", Path(__file__).with_name("local-link-smoke.py"))
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)
fixture = local.fixture
PHASES = ("initial", "lost", "restored")
NODES = ("client", "relay0", "relay2", "exit")
LOSS_MARKERS = tuple(f"uplink-loss-{index}" for index in range(3))
EDGES = {"client": ("10.241.10.1>10.241.10.2", "42.158.0.1>46.162.3.1"),
         "relay0": ("10.241.10.2>10.241.10.1", "10.241.12.1>10.241.12.2"),
         "relay2": ("10.241.12.2>10.241.12.1", "10.241.10.1>10.241.10.2")}


def phase_id(run_id, phase):
    fixture.payload_for(run_id, "client")  # Validate the exact parent run identity.
    if phase not in PHASES:
        raise ValueError("unknown uplink transition phase")
    return hashlib.sha256((run_id + ":" + phase).encode("ascii")).hexdigest()[:32]


def configure(phase):
    if phase not in PHASES:
        raise ValueError("unknown transition phase")
    # The existing exact-marker server also echoes these three distinct challenges. Keeping
    # them separate prevents a delayed pre-loss response from masquerading as a new echo.
    for marker in LOSS_MARKERS:
        fixture.NODES.pop(marker, None)
        if phase == "initial":
            fixture.NODES[marker] = {}
    local.INTERFACES["relay0"] = "r0c r0x r0x2 r0b1 r0b2 r0d underlay".split()
    local.FLOWS = {"client": {"exit": "exit", "relays": {"relay0"},
        "sources": local.CLIENT_ADDRESSES, "exit_addresses": {"46.162.3.1", "10.241.31.2"},
        "uplink": "10.241.31.1", "egress_interface": "xd"}}
    source, target = ("relay2", "relay0") if phase == "lost" else ("relay0", "relay2")
    local.FLOWS[source] = {"exit": target, "relays": {"client"},
        "sources": {fixture.NODES[source]["public"], "10.241.12.2" if source == "relay2" else "10.241.10.2"},
        "exit_addresses": {fixture.NODES[target]["public"], "10.241.10.2" if target == "relay0" else "10.241.12.2", "10.241.31.2"},
        "uplink": fixture.NODES[target]["uplink"], "egress_interface": fixture.NODES[target]["egress_interface"]}
    return local.FLOWS


def read_json(path):
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("unsafe or oversized evidence")
    return json.loads(path.read_text(encoding="ascii"))


def configure_capture(phase):
    configure(phase)
    if phase == "initial":
        # The same source/Exit/uplink privacy predicates apply to every negative challenge.
        for marker in LOSS_MARKERS:
            local.FLOWS[marker] = dict(local.FLOWS["relay0"])


def held_client(directory, run_id):
    """Keep the SAME ordinary application socket alive through the actual uplink loss."""
    payload = fixture.payload_for(run_id, "relay0")
    digest = hashlib.sha256(payload).hexdigest()
    record = {"node": "relay0", "destination": list(fixture.DESTINATION), "datagrams": 0,
        "sent_bytes": len(payload), "sent_sha256": digest, "response_bytes": 0,
        "response_sha256": None, "first_echo_ns": None, "last_echo_ns": None, "success": False,
        "loss_attempts": 0, "loss_replies": 0, "loss_errors": [], "loss_markers": [],
        "stale_pre_loss_replies": 0, "same_application_socket": True}
    deadline = time.monotonic() + 110
    while fixture.running and not (directory / "go").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as application:
        application.bind((fixture.NODES["relay0"]["public"], 0))
        application.settimeout(2)
        record["application"] = list(application.getsockname())
        while fixture.running and time.monotonic() < deadline and not (directory / "loss.go").exists():
            application.sendto(payload, fixture.DESTINATION)
            try:
                response, source = application.recvfrom(2048)
            except (TimeoutError, OSError):
                continue
            if response != payload or source != fixture.DESTINATION:
                raise ValueError("substituted echo on retained application")
            record["datagrams"] += 1
            record["response_bytes"], record["response_sha256"] = len(response), digest
            record["last_echo_ns"] = time.monotonic_ns()
            if record["first_echo_ns"] is None:
                record["first_echo_ns"] = record["last_echo_ns"]
                (directory / "relay0.active").write_text("echo\n", encoding="ascii")
            time.sleep(0.2)
        if record["datagrams"] < 2 or not (directory / "loss.go").exists():
            raise ValueError("retained flow never reached a real echo and loss barrier")
        # Loss.go is written only after the real actor withdrawal, not merely after link down.
        record["loss_barrier_ns"] = time.monotonic_ns()
        loss_payloads = [fixture.payload_for(run_id, marker) for marker in LOSS_MARKERS]
        for marker_payload in loss_payloads:
            record["loss_attempts"] += 1
            record["loss_markers"].append({"sha256": hashlib.sha256(marker_payload).hexdigest(),
                "attempted_ns": time.monotonic_ns()})
            try:
                application.sendto(marker_payload, fixture.DESTINATION)
                response_deadline = time.monotonic() + 2
                while time.monotonic() < response_deadline:
                    application.settimeout(max(0.001, response_deadline - time.monotonic()))
                    response, source = application.recvfrom(2048)
                    if source != fixture.DESTINATION:
                        raise ValueError("substituted post-loss source")
                    if response in loss_payloads:
                        record["loss_replies"] += 1
                        break
                    if response != payload or record["stale_pre_loss_replies"] >= 32:
                        raise ValueError("unbounded or substituted stale response")
                    record["stale_pre_loss_replies"] += 1
            except (TimeoutError, OSError) as error:
                record["loss_errors"].append(type(error).__name__)
        record["loss_complete_ns"] = time.monotonic_ns()
    record["success"] = record["loss_attempts"] == 3 and record["loss_replies"] == 0
    fixture.write_json(directory / "relay0.json", record)
    (directory / "loss.complete").write_text("complete\n", encoding="ascii")
    if not record["success"]:
        raise ValueError("old exact application still received an echo after Exit withdrawal")


def phase_evidence(directory, run_id, phase, peers):
    flows = configure(phase)
    identifier = phase_id(run_id, phase)
    phase_dir = directory / ("uplink-" + phase)
    captures = {node: read_json(phase_dir / f"local-link-capture-{node}.json") for node in NODES}
    if any(not item.get("capture_complete") or item["truncated"] or item["packet_socket_drops"] or item["direct_client_exit_packets"] or item["plaintext_leaks"] for item in captures.values()):
        raise ValueError("incomplete packet capture or direct/plaintext leak")
    transition = captures["relay2"]["interface_lifecycle"]["r2d"]
    expected = [True, False] if phase == "initial" else [phase == "restored"]
    if not transition["complete"] or not transition["same_packet_socket"] or [event["up"] for event in transition["events"]] != expected:
        raise ValueError("exact uplink capture transition was not proven")
    server = read_json(phase_dir / "app/server.json")
    if server["destination"] != list(fixture.DESTINATION):
        raise ValueError("substituted destination")
    if phase == "initial" and any(server["flows"][marker]["datagrams"] != 0 for marker in LOSS_MARKERS):
        raise ValueError("a new post-withdraw marker reached the Internet destination")
    proven = []
    for source, flow in flows.items():
        selected = fixture.parse_path((phase_dir / f"paths-{source}.txt").read_text(encoding="ascii"))
        relay, target = next(iter(flow["relays"])), flow["exit"]
        if selected["relay_peer_id"] != peers[relay] or selected["exit_peer_id"] != peers[target] or selected["state"] != 3:
            raise ValueError("wrong actual selected route")
        app = read_json(phase_dir / f"app/{source}.json")
        echo = server["flows"][source]
        digest = hashlib.sha256(fixture.payload_for(identifier, source)).hexdigest()
        if not app["success"] or app["datagrams"] < 2 or app["destination"] != list(fixture.DESTINATION) or app["sent_sha256"] != digest or app["response_sha256"] != digest or echo["sha256"] != digest or app["sent_bytes"] != app["response_bytes"] or app["sent_bytes"] != echo["bytes"] or echo["datagrams"] < app["datagrams"] or echo["source_ips"] != [flow["uplink"]]:
            raise ValueError("exact echo or independently sourced Exit payload not proven")
        first, second = EDGES[source]
        counts = {"client_tx": captures[source]["wireguard_edges"].get(first, 0),
            "relay_rx": captures[relay]["wireguard_edges"].get(first, 0),
            "relay_tx": captures[relay]["wireguard_edges"].get(second, 0),
            "exit_rx": captures[target]["wireguard_edges"].get(second, 0)}
        if not all(count > 0 for count in counts.values()) or captures[target]["destination_requests"][source] <= 0 or captures[target]["destination_responses"][source] <= 0:
            raise ValueError("missing real payload on one of the two WireGuard legs or Exit uplink")
        proven.append({"success": True, "phase": phase, "client_node": source, "relay_node": relay,
            "exit_node": target, **selected, "application": app, "destination_echo": echo,
            "path_evidence": {"wireguard_both_legs": counts, "first_edge": first, "second_edge": second,
                "selected_exit_source_ip": flow["uplink"]}})
    overlap = min(item["application"]["last_echo_ns"] for item in proven) - max(item["application"]["first_echo_ns"] for item in proven)
    if overlap < 2_000_000_000 or len({item["route_context_id"] for item in proven}) != 2:
        raise ValueError("local-only consumption and contribution did not genuinely overlap")
    return {"phase": phase, "success": True, "flows": proven, "packet_captures": captures,
            "concurrent_echo_overlap_ns": overlap}


def egress_state(addresses, routes, available):
    links = [item for item in addresses if item["ifname"] == "r2d"]
    defaults = [item for item in routes if item.get("dst") == "default"]
    if len(links) != 1 or not any(item.get("local") == "10.241.35.1" for item in links[0].get("addr_info", [])):
        raise ValueError("exact configured independent egress disappeared or changed address")
    if available:
        if "UP" not in links[0]["flags"] or len(defaults) != 1 or defaults[0].get("dev") != "r2d" or defaults[0].get("gateway") != "10.241.35.2":
            raise ValueError("configured egress was not actually restored")
    elif "UP" in links[0]["flags"] or defaults:
        raise ValueError("configured independent uplink loss was not real")
    return {"available": available, "interface": "r2d", "ifindex": links[0]["ifindex"],
            "address": "10.241.35.1", "default_routes": defaults}


def build_evidence(directory, run_id):
    peers = read_json(directory / "a01-expected-peers.json")
    phases = [phase_evidence(directory, run_id, phase, peers) for phase in PHASES]
    nodes = []
    for node in NODES:
        snapshots = [read_json(directory / f"local-link-node-{node}-{phase}.json") for phase in PHASES]
        roles = {"client": True, "relay": True, "exit": node != "client"}
        pids = {item["agent_pid"] for item in snapshots}
        if len(pids) != 1 or min(pids) <= 0 or any(item["roles"] != roles for item in snapshots):
            raise ValueError("transition changed role consent or restarted an agent")
        nodes.append({"node": node, "peer_id": peers[node], "roles": roles,
                      "same_agent_pid": True, "agent_pid": next(iter(pids))})
    uplink = {phase: egress_state(read_json(directory / f"uplink-egress-{phase}-addresses.json"),
        read_json(directory / f"uplink-egress-{phase}-routes.json"), phase != "lost") for phase in PHASES}
    if len({item["ifindex"] for item in uplink.values()}) != 1:
        raise ValueError("uplink was replaced rather than recovered")
    if any(phase["packet_captures"]["relay2"]["interface_lifecycle"]["r2d"]["ifindex"] != uplink[phase["phase"]]["ifindex"] for phase in phases):
        raise ValueError("packet observer did not retain the exact monitored uplink")
    offline = {phase: local.local_only_state(read_json(directory / f"uplink-client-{phase}-addresses.json"),
        read_json(directory / f"uplink-client-{phase}-routes.json")) for phase in PHASES}
    for phase in PHASES:
        lines = (directory / f"uplink-peers-{phase}.txt").read_text(encoding="ascii").splitlines()
        expected = "roles=0b011" if phase == "lost" else "roles=0b111"
        matching = [line.split() for line in lines if line.split() and line.split()[0] == peers["relay2"]]
        if len(matching) != 1 or matching[0][1] != expected:
            raise ValueError("verified peer role withdrawal/recovery absent")
    events = (directory / "uplink-withdraw-events.txt").read_text(encoding="ascii")
    if "INDEPENDENT_EGRESS_WITHDRAWN" not in events:
        raise ValueError("no actual egress-withdrawal actor event")
    fresh = (directory / "uplink-fresh-loss-paths.txt").read_text(encoding="ascii").splitlines()
    admission = read_json(directory / "uplink-fresh-loss-attempt.json")
    if admission["node"] != "relay0" or admission["transport"] != "single-path-udp" or admission["exit_code"] not in (0, 1, 124) or not 0 <= admission["finished_ms"] - admission["started_ms"] <= 55_000:
        raise ValueError("no completed bounded ordinary post-withdraw Connect attempt")
    if any(f"exit={peers['relay2']}" in line and ("state=2" in line or "state=3" in line) for line in fresh):
        raise ValueError("ordinary post-withdraw Connect acquired a ready route to unavailable Exit")
    held = phases[0]["flows"][1]["application"]
    if not held["same_application_socket"] or held["loss_attempts"] != 3 or held["loss_replies"] != 0:
        raise ValueError("old exact application did not stop")
    expected_loss_hashes = [hashlib.sha256(fixture.payload_for(phase_id(run_id, "initial"), marker)).hexdigest() for marker in LOSS_MARKERS]
    if [item["sha256"] for item in held["loss_markers"]] != expected_loss_hashes or any(
            not held["loss_barrier_ns"] <= item["attempted_ns"] <= held["loss_complete_ns"] for item in held["loss_markers"]):
        raise ValueError("new post-withdraw challenges were not distinct and barrier-bound")
    before, after = phases[0]["flows"][1], phases[2]["flows"][1]
    if before["route_context_id"] == after["route_context_id"]:
        raise ValueError("recovered Exit reused the retired context")
    reject_events = (directory / "uplink-rejection-events.txt").read_text(encoding="ascii")
    loss_baseline = int((directory / "uplink-loss-baseline-ms.txt").read_text(encoding="ascii"))
    reject_observed = any(int(match[1]) > loss_baseline for match in re.finditer(
        r"(?m)^(\d+)\tlevel=\d+\tevent=(?:EXIT_FORWARD_EXIT_SCOPE_REJECTED|NATIVE_PROBE_PERMIT_EXIT_REJECTED|NATIVE_PROBE_READY_EXIT_SCOPE_REJECTED)\t", reject_events))
    return {"success": True, "nodes": nodes, "phases": phases, "flows": [flow for phase in phases for flow in phase["flows"]],
        "local_only": offline, "independent_egress": uplink,
        "transition": {"monitored_node": "relay2", "interface": "r2d", "withdrawal_observed": True,
            "verified_exit_role_withdrawn": True, "old_application_stopped": True,
            "new_ready_route_to_withdrawn_exit": False, "restored_new_context": True,
            "ordinary_post_withdraw_admission": admission,
            "incoming_grant_rejection_observed": reject_observed,
            "denial_stage": "verified advertisement withdrawal and ordinary Client admission; incoming Exit rejection only if separately observed"},
        "scope": "one explicitly monitored uplink; A is an unmonitored alternative, not automatic all-interface detection or end-to-end Internet availability"}


def main():
    if len(sys.argv) < 4:
        raise ValueError("expected mode, absolute directory, run ID, phase and optional node")
    mode, directory, run_id = sys.argv[1:4]
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("unsafe fixture directory")
    signal.signal(signal.SIGTERM, fixture.stop)
    signal.signal(signal.SIGINT, fixture.stop)
    if mode == "evidence" and len(sys.argv) == 4:
        fixture.write_json(directory / "uplink-link-evidence.json", build_evidence(directory, run_id))
        return
    phase = sys.argv[4]
    configure(phase)
    identifier = phase_id(run_id, phase)
    if mode == "server" and len(sys.argv) == 5:
        fixture.server(directory, identifier)
    elif mode == "held-client" and phase == "initial" and len(sys.argv) == 5:
        held_client(directory, identifier)
    elif mode == "client" and len(sys.argv) == 6 and sys.argv[5] in local.FLOWS:
        fixture.client(directory, identifier, sys.argv[5])
    elif mode == "capture" and len(sys.argv) == 6 and sys.argv[5] in NODES:
        configure_capture(phase)
        expected = [True, False] if phase == "initial" else [phase == "restored"]
        local.capture(directory, identifier, sys.argv[5],
                      {"r2d": expected} if sys.argv[5] == "relay2" else None)
    else:
        raise ValueError("invalid bounded operation")


if __name__ == "__main__":
    main()
