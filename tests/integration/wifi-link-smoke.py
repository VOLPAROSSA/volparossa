#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded simulated-radio evidence for the actual agent-created local-link overlay."""

import json
from pathlib import Path
import re
import select
import signal
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
MESH_NAME = re.compile(r"vw[0-9a-f]{13}\Z")


def read(directory, name):
    path = directory / name
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("unbounded evidence")
    return path.read_text(encoding="ascii")


def load(directory, name):
    return json.loads(read(directory, name))


def write(directory, name, value):
    (directory / name).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")


def parse_snapshot(links, info, stations):
    owned = [link for link in links if link.get("ifalias", "").startswith("volparossa-mesh:")]
    if len(owned) != 1 or not MESH_NAME.fullmatch(owned[0]["ifname"]):
        raise ValueError("one runtime-owned mesh required")
    link = owned[0]
    if not re.fullmatch(r"volparossa-mesh:[0-9a-f]{32}", link["ifalias"]):
        raise ValueError("missing full runtime alias")
    def number(pattern, text):
        matches = re.findall(pattern, text, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("missing or ambiguous kernel field")
        return int(matches[0])
    if "type mesh point" not in info or number(r"^\s*ifindex (\d+)$", info) != link["ifindex"]:
        raise ValueError("not the exact kernel mesh interface")
    if number(r"^\s*channel \d+ \((\d+) MHz\)", info) != 2412:
        raise ValueError("wrong explicit channel")
    peers = re.findall(r"^Station ([0-9a-f:]{17}) \(on ([^)]+)\)$", stations, re.MULTILINE)
    if (len(peers) != 1 or peers[0][1] != link["ifname"]
            or not re.search(r"^\s*mesh plink:\s*ESTAB$", stations, re.MULTILINE)):
        raise ValueError("one actually established mesh peer required")
    result = {"interface": link["ifname"], "ifindex": link["ifindex"],
              "runtime_alias": link["ifalias"], "wiphy": number(r"^\s*wiphy (\d+)$", info),
              "frequency_mhz": 2412, "peer_established": True,
              "local_mac": link["address"], "peer_mac": peers[0][0]}
    for field in ("rx bytes", "rx packets", "tx bytes", "tx packets"):
        result[field.replace(" ", "_")] = number(r"^\s*" + field + r":\s*(\d+)$", stations)
    return result


def snapshot(directory, node, stage):
    if node not in ("client", "relay0") or stage not in (
            "associated", "payload-before", "payload-after", "disconnected"):
        raise ValueError("invalid snapshot selector")
    value = parse_snapshot(load(directory, f"wifi-link-links-{node}-{stage}.json"),
                           read(directory, f"wifi-link-info-{node}-{stage}.txt"),
                           read(directory, f"wifi-link-stations-{node}-{stage}.txt"))
    write(directory, f"wifi-link-mesh-{node}-{stage}.json", value)


def mdns_packet(frame, interface, remote_peer):
    if not MESH_NAME.fullmatch(interface) or len(frame) < 42 or frame[12:14] != b"\x08\x00":
        return False
    ihl = (frame[14] & 15) * 4
    if ihl < 20 or len(frame) < 14 + ihl + 20 or frame[23] != 17:
        return False
    if socket.inet_ntoa(frame[26:30]) != "10.241.10.2" or socket.inet_ntoa(frame[30:34]) != "224.0.0.251":
        return False
    source, destination = struct.unpack_from("!HH", frame, 14 + ihl)
    dns = frame[14 + ihl + 8:]
    return (source == destination == 5353 and bool(dns[2] & 128)
            and b"dnsaddr=" in dns and (b"/p2p/" + remote_peer.encode("ascii")) in dns)


def observe_mdns(directory, peer):
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,100}", peer):
        raise ValueError("invalid expected peer")
    observer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    observer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    observer.setblocking(False)
    running = True
    def stop(*_args):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    (directory / "wifi-link-mdns.ready").write_text("ready\n", encoding="ascii")
    record = {"peer_id": peer, "remote_peer_records": 0, "mesh_interfaces": [],
              "observed_frames": 0, "truncated": False, "packet_socket_drops": 0}
    deadline = time.monotonic() + 100
    while running and time.monotonic() < deadline:
        if not select.select([observer], [], [], 0.2)[0]:
            continue
        frame, address = observer.recvfrom(65535)
        record["observed_frames"] += 1
        if record["observed_frames"] > 32768:
            record["truncated"] = True
            break
        if mdns_packet(frame, address[0], peer):
            record["remote_peer_records"] += 1
            if address[0] not in record["mesh_interfaces"]:
                record["mesh_interfaces"].append(address[0])
    _, record["packet_socket_drops"] = struct.unpack("II", observer.getsockopt(263, 6, 8))
    observer.close()
    write(directory, "wifi-link-mdns.json", record)


def association(directory):
    pair = {node: load(directory, f"wifi-link-mesh-{node}-associated.json") for node in ("client", "relay0")}
    a, b = pair["client"], pair["relay0"]
    if a["wiphy"] == b["wiphy"] or a["local_mac"] != b["peer_mac"] or b["local_mac"] != a["peer_mac"]:
        raise ValueError("kernel station is not the exact other simulated radio")
    mdns = load(directory, "wifi-link-mdns.json")
    if (mdns["truncated"] or mdns["packet_socket_drops"] or mdns["remote_peer_records"] <= 0
            or mdns["mesh_interfaces"] != [a["interface"]]):
        raise ValueError("no exact mesh mDNS discovery evidence")
    peers = load(directory, "a01-expected-peers.json")
    for node, remote, roles in (("client", "relay0", "0b111"), ("relay0", "client", "0b011")):
        if not any(line.split()[:2] == [peers[remote], "roles=" + roles]
                   for line in read(directory, f"wifi-link-mdns-peers-{node}.txt").splitlines()):
            raise ValueError("mDNS peer has no authenticated signed capability view")
    if mdns["peer_id"] != peers["relay0"]:
        raise ValueError("wrong mDNS remote peer")
    write(directory, "wifi-link-interfaces.json", {node: item["interface"] for node, item in pair.items()})
    write(directory, "wifi-link-association.json", {"success": True,
          "other_agents_not_started": True, "mutual_mesh_bootstrap_contacts": 0,
          "authenticated_signed_peers": 2, "mdns_remote_peer_records": mdns["remote_peer_records"]})


def build_report(directory):
    base = load(directory, "local-link-smoke.json")
    if not base["success"]:
        raise ValueError("protected consume/GIVE evidence failed")
    association_proof = load(directory, "wifi-link-association.json")
    meshes = []
    for node in ("client", "relay0"):
        stages = {stage: load(directory, f"wifi-link-mesh-{node}-{stage}.json") for stage in (
            "associated", "payload-before", "payload-after", "disconnected")}
        first = stages["associated"]
        for item in stages.values():
            for key in ("interface", "ifindex", "wiphy", "runtime_alias", "local_mac", "peer_mac"):
                if item[key] != first[key]:
                    raise ValueError("mesh runtime changed during participation or route cleanup")
        counters = {key: stages["payload-after"][key] - stages["payload-before"][key]
                    for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")}
        if not all(value > 0 for value in counters.values()):
            raise ValueError("mesh carried no bidirectional traffic during the application phase")
        capture = load(directory, f"local-link-capture-{node}.json")
        mesh_packets = capture["wireguard_interfaces"].get(first["interface"], {})
        edges = ("10.241.10.1>10.241.10.2", "10.241.10.2>10.241.10.1")
        if not all(mesh_packets.get(edge, 0) > 0 for edge in edges):
            raise ValueError("actual protected payload did not traverse the mesh in both directions")
        meshes.append({"node": node, "interface": first["interface"], "ifindex": first["ifindex"],
                       "wiphy": first["wiphy"], "peer_established": True, "frequency_mhz": 2412,
                       "application_phase_counter_delta": counters,
                       "wireguard_transport_packets": {edge: mesh_packets[edge] for edge in edges},
                       "same_mesh_after_route_disconnect": True})
    shutdown = load(directory, "wifi-link-shutdown.json")
    if shutdown != {"remaining_mesh_interfaces": 0, "agents_stopped_before_helpers": True}:
        raise ValueError("agent shutdown did not release the mesh before helper shutdown")
    radio_cleanup = load(directory, "wifi-link-radio-cleanup.json")
    if radio_cleanup != {"hwsim_module_unloaded": True, "remaining_radios": 0}:
        raise ValueError("owned simulated radio cleanup incomplete")
    flows = [{**flow, "client_relay_underlay": (
        "simulated_80211s_mesh" if flow["client_node"] == "relay0" or flow["relay_node"] == "relay0"
        else "ethernet_veth")} for flow in base["flows"]]
    return {**base, "report_kind": "volparossa-wifi-local-link-runtime", "flows": flows,
            "discovery": association_proof, "mesh_nodes": meshes, "mesh_shutdown": shutdown,
            "radio_cleanup": radio_cleanup,
            "agent_created_mesh": True, "open_l2_underlay": True,
            "retained_ethernet_contact": "10.241.12.0/30", "physical_radio_proven": False,
            "wifi_only_proven": False, "independent_bandwidth_aggregation_proven": False,
            "scope": "agent-created simulated mesh plus Ethernet; actual protected LocalOnly consume/GIVE; not physical radio, WiFi-only, aggregate capacity or A01-A15"}


def report(directory, status):
    try:
        result = build_report(directory)
        result["success"] = result["success"] and int(status) == 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        try:
            base = load(directory, "local-link-smoke.json")
        except (OSError, ValueError):
            base = load(directory, "wifi-link-runner.json")
        result = {**base, "report_kind": "volparossa-wifi-local-link-runtime", "success": False,
                  "observed_blocker": base.get("observed_blocker") or str(error),
                  "mesh_nodes": []}
    write(directory, "wifi-link-smoke.json", result)


if __name__ == "__main__":
    action, root, *args = sys.argv[1:]
    directory = Path(root)
    {"snapshot": snapshot, "mdns": observe_mdns, "association": association, "report": report}[action](directory, *args)
