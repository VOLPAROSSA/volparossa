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
TAP_GATEWAY = "10.242.93.2"
TAP = "dnsup0"
_BASE_HEADER_SAMPLE = ENGINE.fixture_header_sample


def decode_frame_on_interface(frame, iface):
    # Only this owned TAP's ARP is outside the original 10.241 fixture. Keep the
    # common parser unchanged, including fragment rejection on all IP traffic.
    if len(frame) >= 14 and frame[12:14] == b"\x08\x06" and iface == TAP:
        if not 42 <= len(frame) <= 60 or any(frame[42:]) \
                or frame[14:20] != b"\x00\x01\x08\x00\x06\x04" \
                or struct.unpack_from("!H", frame, 20)[0] not in (1, 2):
            raise ValueError("private DNS TAP ARP shape")
        source, destination = (socket.inet_ntoa(frame[offset:offset + 4]) for offset in (28, 38))
        if {source, destination} != {TAP_ADDRESS, TAP_GATEWAY}:
            raise ValueError("private DNS TAP ARP endpoints")
        if frame[6:12] != frame[22:28] or not any(frame[6:12]) or frame[6] & 1:
            raise ValueError("private DNS TAP ARP sender")
        return None  # Neighbour traffic, not IP/DNS/application data.
    return ENGINE.decode_frame(frame)


def fixture_header_sample(packet, iface, frame):
    if packet is not None:
        return _BASE_HEADER_SAMPLE(packet, iface, frame)
    # These are fixed parse categories and known fixture aliases only. They do
    # not admit packets and do not export raw bytes or unrecognized addresses.
    result = {"interface": iface, "parse": "unavailable"}
    result["ethernet_kind"] = ({b"\x08\x06": "arp", b"\x08\x00": "ipv4", b"\x86\xdd": "ipv6"}
                               .get(frame[12:14], "other") if len(frame) >= 14 else "short")
    reasons = {
        "private DNS TAP ARP shape": "tap_arp_shape",
        "private DNS TAP ARP endpoints": "tap_arp_endpoints",
        "private DNS TAP ARP sender": "tap_arp_sender",
        "short Ethernet frame": "ethernet_short",
        "unsupported ARP frame": "arp_shape",
        "ARP endpoint outside the disposable fixture": "arp_endpoints",
        "short IPv4 header": "ipv4_short",
        "invalid or fragmented IPv4 capture": "ipv4_invalid_or_fragmented",
        "short IPv6 header": "ipv6_short",
        "truncated IPv6 capture": "ipv6_truncated",
        "short IPv6 hop-by-hop header": "ipv6_extension_short",
        "invalid IPv6 hop-by-hop header": "ipv6_extension_invalid",
        "unexpected Ethernet protocol": "ethernet_protocol",
        "short UDP header": "udp_short",
        "truncated UDP datagram": "udp_truncated",
        "short TCP header": "tcp_short",
        "invalid TCP data offset": "tcp_offset",
    }
    try:
        decode_frame_on_interface(frame, iface)
    except ValueError as error:
        result["reason"] = reasons.get(str(error), "unclassified")
    else:
        result["reason"] = "unclassified"
    if result["ethernet_kind"] == "arp" and len(frame) >= 42:
        result["arp_operation"] = {1: "request", 2: "reply"}.get(struct.unpack_from("!H", frame, 20)[0], "other")
        for field, offset in (("source", 28), ("destination", 38)):
            result[field] = ENGINE.FIXTURE_ADDRESS_LABELS.get(
                socket.inet_ntoa(frame[offset:offset + 4]), "outside_fixed_fixture")
    return result


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
ENGINE.decode_frame_on_interface = decode_frame_on_interface
ENGINE.fixture_header_sample = fixture_header_sample
ENGINE.COUNTERS += ("recursive_request_packets", "recursive_response_packets",
    "recursive_request_payload_bytes", "recursive_response_payload_bytes", "plaintext_dns_packets",
    "concurrent_echo_packets", "plaintext_echo_packets", "concurrent_wireguard_packets")
for node, metadata in NODES.items():
    ENGINE.MDNS_INTERFACE_ADDRESSES.setdefault((node, metadata["egress_interface"]), set()).update({
        metadata["uplink"], metadata["uplink"].rsplit(".", 1)[0] + ".2"})
ENGINE.FIXTURE_ADDRESS_LABELS.update({
    TAP_ADDRESS: "private_dns.tap", TAP_GATEWAY: "private_dns.gateway",
    "47.163.4.1": "exit.xd.alias", "47.163.4.2": "destination.dx.alias",
})

if __name__ == "__main__":
    ENGINE.main(sys.argv[1:])
