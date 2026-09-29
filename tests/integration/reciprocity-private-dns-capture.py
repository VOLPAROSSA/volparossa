#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Drained physical DNS privacy counters beside four concurrent reciprocal UDP flows."""
import importlib.util
import ipaddress
from pathlib import Path
import socket
import struct
import sys


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("reciprocity-smoke.py", "private_dns_reciprocity")
ENGINE = load("content-replication-capture.py", "private_dns_capture_engine")
NODES = BASE.NODES
TAP_ADDRESS = "10.242.93.100"
TAP = "dnsup0"


def validate_layout(layout):
    if set(layout) != {"phase", "exit_node", "relays", "run_id"} or layout["phase"] not in ("warm", "local") \
            or layout["exit_node"] not in NODES or layout["exit_node"] == "client" \
            or len(layout["relays"]) != 1 or any(name not in NODES or name in ("client", layout["exit_node"])
                or value != NODES[name]["public"] for name, value in layout["relays"].items()):
        raise ValueError("private DNS selected route shape")
    BASE.payload_for(layout["run_id"], "client")
    return layout


def role_node(_layout, role):
    if role not in NODES:
        raise ValueError("private DNS capture role")
    return role


def classify(layout, role, protocol, src, sport, dst, dport, payload, iface, *, frame=None):
    metadata = NODES[role]
    pair = {src, dst}
    if protocol in (socket.IPPROTO_UDP, socket.IPPROTO_TCP) and 53 in (sport, dport):
        if role == layout["exit_node"] and iface == TAP:
            if src == TAP_ADDRESS and dport == 53 and ipaddress.ip_address(dst).is_global:
                return {"recursive_request_packets": 1, "recursive_request_payload_bytes": len(payload)}
            if dst == TAP_ADDRESS and sport == 53 and ipaddress.ip_address(src).is_global:
                return {"recursive_response_packets": 1, "recursive_response_payload_bytes": len(payload)}
        return {"forbidden_packets": 1, "plaintext_dns_packets": 1}
    if pair == {metadata["public"], NODES[metadata["exit"]]["public"]}:
        return {"forbidden_packets": 1, "direct_client_exit_packets": 1}
    # Native application echoes remain active on all four original reciprocal paths.
    for client, node in NODES.items():
        if payload == BASE.payload_for(layout["run_id"], client):
            actual_exit = node["exit"]
            if role == actual_exit and iface == metadata["egress_interface"] and protocol == socket.IPPROTO_UDP \
                    and ((src == metadata["uplink"] and (dst, dport) == BASE.DESTINATION)
                         or (dst == metadata["uplink"] and (src, sport) == BASE.DESTINATION)):
                return {"concurrent_echo_packets": 1}
            return {"forbidden_packets": 1, "plaintext_echo_packets": 1}
    if protocol == socket.IPPROTO_UDP and 41000 in (sport, dport) and sport and dport:
        # This counter is not route authority. Adjacent control includes the fixture's
        # authenticated public /32s and their exact known veth addresses, never the TAP.
        if iface != TAP and (pair <= ENGINE.CONTROL_PEERS or ENGINE.exact_control_pair(role, iface, src, dst)):
            return {"control_packets": 1}
    if protocol == socket.IPPROTO_UDP and dport == 5353 and dst in ("224.0.0.251", "ff02::fb"):
        if iface in {*metadata["interfaces"], TAP} and (
                src in ENGINE.MDNS_INTERFACE_ADDRESSES.get((role, iface), ())
                or (iface == TAP and src == TAP_ADDRESS) or ipaddress.ip_address(src).is_link_local):
            return {"mdns_packets": 1}
    if protocol == socket.IPPROTO_ICMPV6 and payload and payload[0] in (130, 131, 132, 133, 134, 135, 136, 143) \
            and (ipaddress.ip_address(src).is_link_local or ipaddress.ip_address(src).is_unspecified):
        return {"neighbor_packets": 1}
    if protocol == socket.IPPROTO_UDP and sport and dport and iface != TAP and len(payload) >= 4:
        # All original reciprocal WG flows run concurrently. These aggregate packets are
        # deliberately NOT attributed exclusively to DNS or advertised as DNS payload bytes.
        adjacent = any(pair == {NODES[node]["public"], NODES[relay]["public"]}
                       for node in NODES for relay in NODES[node]["relays"])
        if adjacent:
            kind = struct.unpack_from("<I", payload)[0]
            if kind in (1, 2, 3) and len(payload) == {1: 148, 2: 92, 3: 64}[kind]:
                return {"wireguard_handshake_packets": 1}
            if kind == 4 and 32 <= len(payload) <= ENGINE.MAX_WIREGUARD_DATA_BYTES \
                    and (len(payload) % 16 == 0 or len(payload) == ENGINE.MAX_WIREGUARD_DATA_BYTES):
                return {"concurrent_wireguard_packets": 1}
    if protocol == socket.IPPROTO_ICMP and payload[:2] == b"\x03\x03":
        quoted = ENGINE.quoted_udp(payload)
        if iface != TAP and quoted and 41000 in (quoted[1], quoted[3]) \
                and (pair <= ENGINE.CONTROL_PEERS or ENGINE.exact_control_pair(role, iface, src, dst)):
            return {"control_port_unreachable_packets": 1}
    return {"forbidden_packets": 1}


ENGINE.validate_layout = validate_layout
ENGINE.role_node = role_node
ENGINE.classify = classify
ENGINE.COUNTERS += ("recursive_request_packets", "recursive_response_packets",
    "recursive_request_payload_bytes", "recursive_response_payload_bytes", "plaintext_dns_packets",
    "concurrent_echo_packets", "plaintext_echo_packets", "concurrent_wireguard_packets")
for node, metadata in NODES.items():
    ENGINE.MDNS_INTERFACE_ADDRESSES[node, metadata["egress_interface"]] = {
        metadata["uplink"], metadata["uplink"].rsplit(".", 1)[0] + ".2"}

if __name__ == "__main__":
    ENGINE.main(sys.argv[1:])
