#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""DNS scenario classification with the existing bounded, drained packet-capture engine."""
import importlib.util
import ipaddress
from pathlib import Path
import socket
import struct
import sys

SPEC = importlib.util.spec_from_file_location("dns_capture_engine", Path(__file__).with_name("content-replication-capture.py"))
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)
PUBLIC = {**ENGINE.PUBLIC, "relay3": "48.164.4.1", "exit2": "51.167.7.1", "destination": "47.163.4.2",
          "bootstrap1": "40.156.1.1", "bootstrap2": "41.157.2.1"}
PHASES = ("warm-a-a", "warm-a-aaaa", "peer-b-a", "peer-b-aaaa", "unsigned-b", "local-b-a", "local-b-aaaa")
PHYSICAL_INTERFACES = {
    "client": {"underlay", "cb1", "cb2", *(f"cr{index}" for index in range(6))},
    "exit": {"underlay", "xd", "xc0", *(f"xr{index}" for index in range(6))},
    "exit2": {"underlay", "x2r0", "x2r1", "x2r2", "x2d", "xc1"},
    "destination": {"dx", "dx2"},
    **{f"relay{index}": {"underlay", f"r{index}c", f"r{index}x", f"r{index}b1", f"r{index}b2"}
       for index in range(3)},
}
for INDEX in range(3):
    PHYSICAL_INTERFACES[f"relay{INDEX}"].add(f"r{INDEX}x2")
METADATA = dict(ENGINE.MDNS_INTERFACE_ADDRESSES)
METADATA.update({("exit2", "underlay"): {"51.167.7.1"},
                 ("exit2", "x2d"): {"10.241.32.1", "10.241.32.2", "52.168.8.1", "52.168.8.2"},
                 ("destination", "dx2"): {"10.241.32.1", "10.241.32.2", "52.168.8.1", "52.168.8.2"},
                 ("destination", "dx"): {"10.241.31.1", "10.241.31.2", "47.163.4.1", "47.163.4.2"},
                 ("exit", "xc0"): {"10.241.96.1", "10.241.96.2"},
                 ("exit2", "xc1"): {"10.241.96.1", "10.241.96.2"}})
# Normal Identify/mDNS may learn a directly adjacent private address. Scope that
# control traffic to the exact fixture link and its two assigned endpoints, not
# arbitrary RFC1918 peers, DNS datagrams, or any WireGuard/application exception.
def control_link(left, lif, right, rif, segment):
    lhs, rhs = {PUBLIC[left], f"10.241.{segment}.1"}, {PUBLIC[right], f"10.241.{segment}.2"}
    ENGINE.EXACT_CONTROL_LINKS[left, lif] = lhs, rhs
    ENGINE.EXACT_CONTROL_LINKS[right, rif] = rhs, lhs

for INDEX in range(6):
    control_link("client", f"cr{INDEX}", f"relay{INDEX}", f"r{INDEX}c", 10 + INDEX)
    control_link(f"relay{INDEX}", f"r{INDEX}x", "exit", f"xr{INDEX}", 20 + INDEX)
    for BOOTSTRAP in (1, 2):
        control_link(f"relay{INDEX}", f"r{INDEX}b{BOOTSTRAP}", f"bootstrap{BOOTSTRAP}",
                     f"b{BOOTSTRAP}r{INDEX}", 41 + INDEX * 2 + BOOTSTRAP)
for BOOTSTRAP in (1, 2):
    control_link("client", f"cb{BOOTSTRAP}", f"bootstrap{BOOTSTRAP}", f"b{BOOTSTRAP}c", 39 + BOOTSTRAP)
control_link("relay0", "r0x2", "exit2", "x2r0", 26)
for INDEX, SEGMENT in ((1, 97), (2, 98)):
    control_link(f"relay{INDEX}", f"r{INDEX}x2", "exit2", f"x2r{INDEX}", SEGMENT)
    PAIR = {f"10.241.{SEGMENT}.1", f"10.241.{SEGMENT}.2"}
    METADATA[f"relay{INDEX}", f"r{INDEX}x2"] = PAIR
    METADATA["exit2", f"x2r{INDEX}"] = PAIR
control_link("exit", "xc0", "exit2", "xc1", 96)
CONTROL_IDENTITIES = frozenset(ENGINE.CONTROL_PEERS)


def validate_layout(layout):
    if layout.get("phase") not in PHASES:
        raise ValueError("DNS capture phase")
    expected_exit = "exit" if layout["phase"].startswith("warm-") else "exit2"
    relays = layout.get("relays", {})
    if layout.get("exit_node") != expected_exit or len(relays) != 1 or any(
            relay not in ("relay0", "relay1", "relay2") or PUBLIC[relay] != address
            for relay, address in relays.items()):
        raise ValueError("DNS exact route endpoints")
    return layout


def role_node(layout, role):
    if role not in ("client", "exit", "exit2", "destination", *layout["relays"]):
        raise ValueError("DNS physical capture role")
    return role


def classify(layout, role, protocol, src, sport, dst, dport, payload, iface):
    node = role_node(layout, role)
    pair = {src, dst}
    source = ipaddress.ip_address(src)
    if source.version == 6:
        if (source.is_link_local or source.is_unspecified) and (
                ipaddress.ip_address(dst).is_link_local or dst.startswith("ff02:")) \
                and protocol == socket.IPPROTO_ICMPV6 and payload and payload[0] in (130, 131, 132, 133, 134, 135, 136, 143):
            return {"neighbor_packets": 1}
        if source.is_link_local and dst == "ff02::fb" and protocol == socket.IPPROTO_UDP and sport and dport == 5353:
            return {"mdns_packets": 1, "control_packets": 1}
        return {"forbidden_packets": 1}
    direct_control = pair == {PUBLIC["exit"], PUBLIC["exit2"]} and (node, iface) in (("exit", "xc0"), ("exit2", "xc1"))
    scoped_private = ENGINE.exact_control_pair(node, iface, src, dst)
    if protocol == socket.IPPROTO_UDP and sport and dport and 41000 in (sport, dport) \
            and ((src in CONTROL_IDENTITIES and dst in CONTROL_IDENTITIES and src != dst) or scoped_private):
        return {"control_packets": 1, "cross_exit_control_packets": int(direct_control)}
    if protocol == socket.IPPROTO_ICMP and payload[:2] == b"\x03\x03":
        quoted = ENGINE.quoted_udp(payload)
        if quoted and (scoped_private or direct_control) and quoted[0] == dst and quoted[2] == src \
                and 41000 in (quoted[1], quoted[3]):
            return {"control_packets": 1, "control_port_unreachable_packets": 1}
    if protocol == socket.IPPROTO_UDP and sport and dport == 5353 and dst == "224.0.0.251" \
            and src in METADATA.get((node, iface), ()):
        return {"mdns_packets": 1, "control_packets": 1}
    if PUBLIC["client"] in pair and pair.intersection((PUBLIC["exit"], PUBLIC["exit2"])):
        return {"forbidden_packets": 1, "direct_client_exit_packets": 1}
    if protocol in (socket.IPPROTO_TCP, socket.IPPROTO_UDP) and 53 in (sport, dport):
        if protocol == socket.IPPROTO_TCP and pair == {"47.163.4.1", "47.163.4.2"} and node in ("exit", "destination"):
            if src == "47.163.4.1" and dport == 53:
                return {"upstream_request_packets": 1, "upstream_request_payload_bytes": len(payload)}
            if dst == "47.163.4.1" and sport == 53:
                return {"upstream_response_packets": 1, "upstream_response_payload_bytes": len(payload)}
        return {"forbidden_packets": 1, "unexpected_dns_packets": 1}
    if protocol == socket.IPPROTO_UDP and sport and dport and len(payload) >= 4:
        exit_node = layout["exit_node"]
        for relay, address in layout["relays"].items():
            leg = ("client_leg" if pair == {PUBLIC["client"], address} and node in ("client", relay) else
                   "exit_leg" if pair == {address, PUBLIC[exit_node]} and node in (relay, exit_node) else None)
            if leg is None:
                continue
            kind = struct.unpack_from("<I", payload)[0]
            if kind in (1, 2, 3) and len(payload) == {1: 148, 2: 92, 3: 64}[kind]:
                return {"wireguard_handshake_packets": 1}
            if kind == 4 and 32 <= len(payload) <= ENGINE.MAX_WIREGUARD_DATA_BYTES and (
                    len(payload) % 16 == 0 or len(payload) == ENGINE.MAX_WIREGUARD_DATA_BYTES):
                if len(payload) == 32:
                    return {"wireguard_keepalive_packets": 1}
                return {f"{leg}_wireguard_data_datagrams": 1, f"{leg}_wireguard_data_bytes": len(payload),
                        f"{relay}_{leg}_wireguard_data_datagrams": 1}
    return {"forbidden_packets": 1}


ENGINE.validate_layout = validate_layout
ENGINE.role_node = role_node
ENGINE.classify = classify
ENGINE.CONTROL_PEERS.update(("47.163.4.1", "47.163.4.2", "52.168.8.1", "52.168.8.2"))
ENGINE.COUNTERS += ("cross_exit_control_packets", "upstream_request_packets", "upstream_response_packets",
                    "upstream_request_payload_bytes", "upstream_response_payload_bytes", "unexpected_dns_packets")

if __name__ == "__main__":
    ENGINE.main(sys.argv[1:])
