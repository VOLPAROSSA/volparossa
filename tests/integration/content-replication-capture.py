#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded physical-packet evidence for the disposable C03 replication topology.

This records counters only, never packet bodies. TCP payload counters include observed
framing/retransmissions and are not useful-content or throughput claims. The application
and helper reports independently prove content hashes and genuine MPTCP subflows.
"""

import ctypes
import ipaddress
import json
from pathlib import Path
import re
import select
import signal
import socket
import struct
import sys
import time


PUBLIC = {"client": "43.159.1.1", "relay0": "42.158.0.1",
          "relay1": "44.160.1.1", "relay2": "45.161.2.1",
          "relay4": "49.165.5.1", "relay5": "50.166.6.1", "exit": "46.162.3.1"}
CONTROL_PEERS = {*PUBLIC.values(), "40.156.1.1", "41.157.2.1", "48.164.4.1", "51.167.7.1"}
FIXTURE_LINKS = ipaddress.ip_network("10.241.0.0/16")
COUNTERS = (
    "client_leg_wireguard_data_datagrams", "exit_leg_wireguard_data_datagrams",
    "client_leg_wireguard_data_bytes", "exit_leg_wireguard_data_bytes",
    "wireguard_handshake_packets", "wireguard_keepalive_packets",
    "provider_request_packets", "provider_response_packets", "provider_response_payload_bytes",
    "control_packets", "control_port_unreachable_packets", "mdns_packets", "neighbor_packets", "ipv4_frames", "ipv6_frames",
    "forbidden_packets", "direct_client_exit_packets", "direct_provider_packets",
    "malformed_packets",
    "owner_fixture_packets", "owner_fixture_payload_bytes",
)
# Fixed labels only: no packet-derived address, port, type number or payload is persisted.
PROTOCOL_LABELS = {socket.IPPROTO_TCP: "tcp", socket.IPPROTO_UDP: "udp",
                   socket.IPPROTO_ICMP: "icmp", socket.IPPROTO_ICMPV6: "icmpv6"}
UDP_LABELS = ("control_port", "mdns_multicast", "wireguard_header", "fixture_pair_other", "outside_fixture")
ICMP_LABELS = ("port_unreachable", "fragmentation_needed", "destination_unreachable", "time_exceeded", "other")
DIAGNOSTIC_COUNTERS = (
    *(f"classified_{label}_packets" for label in (*PROTOCOL_LABELS.values(), "other_ip", "arp")),
    *(f"forbidden_{label}_packets" for label in (*PROTOCOL_LABELS.values(), "other_ip", "unparsed")),
    "forbidden_ipv4_unmatched_packets", "forbidden_ipv6_unmatched_packets",
    *(f"forbidden_udp_{label}_packets" for label in UDP_LABELS),
    *(f"forbidden_icmp_{label}_packets" for label in ICMP_LABELS),
    *(f"forbidden_icmp_quoted_udp_{label}_packets" for label in UDP_LABELS),
    "forbidden_icmp_unparsed_quote_packets",
)
# This disposable topology's observed WireGuard MTU is 1420. Linux v6.12 send.c
# calculate_skb_padding() clamps alignment padding to that MTU; full data messages
# therefore contain 1420 plaintext + 16 header + 16 tag = 1452, not a multiple of 16.
# https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/wireguard/send.c
WIREGUARD_MTU = 1420
MAX_WIREGUARD_DATA_BYTES = WIREGUARD_MTU + 32
MAX_FRAMES = 1_048_576
MAX_FRAME_BYTES = 65_589  # Ethernet + IPv6 header + maximum non-jumbo IPv6 payload.
MAX_SECONDS = 1800
DRAIN_SECONDS = 3


def fixture_mdns_addresses():
    """Exact assigned addresses from kvm-alpha-topology + replication link_nodes calls."""
    addresses = {(node, "underlay"): {ip} for node, ip in PUBLIC.items()}

    def link(left, lif, right, rif, segment):
        pair = {f"10.241.{segment}.1", f"10.241.{segment}.2"}
        addresses[left, lif] = pair
        addresses[right, rif] = pair

    for index in range(6):
        relay = f"relay{index}"
        link("client", f"cr{index}", relay, f"r{index}c", 10 + index)
        link(relay, f"r{index}x", "exit", f"xr{index}", 20 + index)
        for bootstrap in (1, 2):
            link(relay, f"r{index}b{bootstrap}", f"bootstrap{bootstrap}",
                 f"b{bootstrap}r{index}", 41 + 2 * index + bootstrap)
    for bootstrap in (1, 2):
        link("client", f"cb{bootstrap}", f"bootstrap{bootstrap}", f"b{bootstrap}c", 39 + bootstrap)
    link("relay0", "r0x2", "exit2", "x2r0", 26)
    link("exit", "xd", "destination", "dx", 31)
    addresses["exit", "xd"].update(("47.163.4.1", "47.163.4.2"))
    for index, segment in enumerate((90, 94, 92)):
        link("relay4", f"ar{index}", f"relay{index}", f"r{index}a", segment)
        link(f"relay{index}", f"rp{index}", "relay5", f"pr{index}", segment + 1)
    return addresses


MDNS_INTERFACE_ADDRESSES = fixture_mdns_addresses()
# Only the observed unused-Relay3 and stopped-provider5 control links. Each side
# lists its actual private interface address and its assigned public source alias.
# These addresses do not authorize an application or a WireGuard dataplane pair.
EXACT_CONTROL_LINKS = {
    ("exit", "xr3"): ({"10.241.23.2", "46.162.3.1"}, {"10.241.23.1", "48.164.4.1"}),
    ("exit", "xr5"): ({"10.241.25.2", "46.162.3.1"}, {"10.241.25.1", "50.166.6.1"}),
}


def exact_control_pair(node, iface, source, destination):
    local, remote = EXACT_CONTROL_LINKS.get((node, iface), ((), ()))
    return ((source in local and destination in remote)
            or (source in remote and destination in local))


def quoted_udp(payload):
    """Read only the bounded quoted IPv4/UDP headers; malformed quotations stay invalid."""
    quote = payload[8:]
    offset = (quote[0] & 15) * 4 if quote else 0
    if len(quote) < 20 or quote[0] >> 4 != 4 or not 20 <= offset <= 60 \
            or len(quote) < offset + 8 or quote[9] != socket.IPPROTO_UDP \
            or struct.unpack("!H", quote[6:8])[0] & 0x3fff \
            or struct.unpack("!H", quote[2:4])[0] < offset + 8:
        return None
    sport, dport, length = struct.unpack("!HHH", quote[offset:offset + 6])
    if length < 8 or offset + length > struct.unpack("!H", quote[2:4])[0]:
        return None
    return (socket.inet_ntoa(quote[12:16]), sport, socket.inet_ntoa(quote[16:20]), dport)


def exact_control_port_unreachable(node, iface, source, destination, payload):
    if len(payload) < 8 or payload[:2] != b"\x03\x03" \
            or not exact_control_pair(node, iface, source, destination):
        return False
    quoted = quoted_udp(payload)
    if quoted is None:
        return False
    qsource, sport, qdestination, dport = quoted
    return (qsource == destination and qdestination == source and sport != 0 and dport != 0
            and 41000 in (sport, dport))


def validate_layout(layout):
    if not isinstance(layout, dict) or layout.get("phase") not in ("uptake", "reserve-fetch"):
        raise ValueError("invalid replication capture phase")
    expected = (("relay4", "relay5") if layout["phase"] == "uptake" else ("client", "relay4"))
    for field, node in (("client", expected[0]), ("provider", expected[1]), ("exit", "exit")):
        if layout.get(field) != {"node": node, "ip": PUBLIC[node]}:
            raise ValueError("substituted replication capture endpoint")
    relays = layout.get("relays")
    if not isinstance(relays, dict) or len(relays) != 2 or any(
            node not in ("relay0", "relay1", "relay2") or PUBLIC[node] != address
            for node, address in relays.items()):
        raise ValueError("capture requires two exact selected relay endpoints")
    return layout


def role_node(layout, role):
    node = layout["provider"]["node"] if role == "provider" else role
    if node not in {layout["client"]["node"], layout["provider"]["node"],
                    layout["exit"]["node"], *layout["relays"]}:
        raise ValueError("capture role is not a participant in this phase")
    return node


def classify(layout, role, protocol, src, sport, dst, dport, payload, iface):
    """Return increments for one decoded IP packet on an explicitly captured interface.

    The layout is prevalidated by capture(). Neither a control-port exception nor an
    observed WireGuard-shaped datagram grants a content endpoint or publisher authority.
    """
    node = role_node(layout, role)
    if not isinstance(iface, str) or not iface:
        raise ValueError("missing physical capture interface")
    client, exit_ip, provider = (layout[name]["ip"] for name in ("client", "exit", "provider"))
    pair = {src, dst}
    source, destination = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if source.version != destination.version:
        return {"forbidden_packets": 1, "malformed_packets": 1}
    if source.version == 6:
        link_local = (source.is_link_local or source.is_unspecified) and (
            destination.is_link_local or dst.startswith("ff02:"))
        if link_local and protocol == socket.IPPROTO_ICMPV6 and payload and payload[0] in (
                130, 131, 132, 133, 134, 135, 136, 143):
            return {"neighbor_packets": 1}
        if source.is_link_local and dst == "ff02::fb" and protocol == socket.IPPROTO_UDP \
                and sport != 0 and dport == 5353:
            return {"mdns_packets": 1, "control_packets": 1}
        return {"forbidden_packets": 1}
    # Only this uptake fixture's independent local owner socket; never an Exit/provider
    # bypass. The exact bound tuple, interface, payload shape and phase are mandatory.
    if layout["phase"] == "uptake" and protocol == socket.IPPROTO_UDP \
            and (node, iface) in (("relay4", "ar0"), ("relay0", "r0a")) \
            and (src, sport, dst, dport) == ("10.241.90.1", 19004, "10.241.90.2", 19004) \
            and len(payload) == 1200 and payload[:8] == b"VPC04OWN":
        return {"owner_fixture_packets": 1, "owner_fixture_payload_bytes": len(payload)}
    if protocol == socket.IPPROTO_UDP and 41000 in (sport, dport) \
            and src in CONTROL_PEERS and dst in CONTROL_PEERS and src != dst:
        return {"control_packets": 1}
    if protocol == socket.IPPROTO_UDP and sport != 0 and dport != 0 \
            and 41000 in (sport, dport) and exact_control_pair(node, iface, src, dst):
        return {"control_packets": 1}
    if protocol == socket.IPPROTO_ICMP and exact_control_port_unreachable(node, iface, src, dst, payload):
        return {"control_packets": 1, "control_port_unreachable_packets": 1}
    # Control connectivity is distinct from directly reaching an Exit dataplane.
    if pair == {client, exit_ip}:
        return {"forbidden_packets": 1, "direct_client_exit_packets": 1}
    # Pinned libp2p-mdns uses a separate ephemeral-port send socket, not source5353.
    if protocol == socket.IPPROTO_UDP and sport != 0 and dport == 5353 \
            and dst == "224.0.0.251" and src in MDNS_INTERFACE_ADDRESSES.get((node, iface), ()):
        return {"mdns_packets": 1, "control_packets": 1}
    if protocol == socket.IPPROTO_TCP and pair == {exit_ip, provider} and node in (
            layout["exit"]["node"], layout["provider"]["node"]):
        if src == exit_ip and dst == provider and dport == 18080 and sport != 0:
            return {"provider_request_packets": 1}
        if src == provider and dst == exit_ip and sport == 18080 and dport != 0:
            return {"provider_response_packets": 1, "provider_response_payload_bytes": len(payload)}
    if provider in pair and pair.intersection({client, *layout["relays"].values()}):
        return {"forbidden_packets": 1, "direct_provider_packets": 1}
    if protocol == socket.IPPROTO_UDP and sport != 0 and dport != 0:
        for relay, address in layout["relays"].items():
            leg = None
            if pair == {client, address} and node in (layout["client"]["node"], relay):
                leg = "client_leg"
            elif pair == {address, exit_ip} and node in (relay, layout["exit"]["node"]):
                leg = "exit_leg"
            if leg is None or len(payload) < 4:
                continue
            message_type = struct.unpack("<I", payload[:4])[0]
            if message_type in (1, 2, 3) and len(payload) == {1: 148, 2: 92, 3: 64}[message_type]:
                return {"wireguard_handshake_packets": 1}
            if message_type == 4 and 32 <= len(payload) <= MAX_WIREGUARD_DATA_BYTES \
                    and (len(payload) % 16 == 0 or len(payload) == MAX_WIREGUARD_DATA_BYTES):
                if len(payload) == 32:
                    return {"wireguard_keepalive_packets": 1}
                return {f"{leg}_wireguard_data_datagrams": 1,
                        f"{leg}_wireguard_data_bytes": len(payload),
                        f"{relay}_{leg}_wireguard_data_datagrams": 1}
    return {"forbidden_packets": 1}


def decode_frame(frame):
    """Decode bounded Ethernet IPv4/IPv6 headers; reject fragments and opaque extensions."""
    if len(frame) < 14:
        raise ValueError("short Ethernet frame")
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type == 0x0806:
        if len(frame) < 42 or frame[14:20] != b"\x00\x01\x08\x00\x06\x04" \
                or struct.unpack("!H", frame[20:22])[0] not in (1, 2):
            raise ValueError("unsupported ARP frame")
        source, destination = (ipaddress.ip_address(frame[offset:offset + 4]) for offset in (28, 38))
        if not (str(source) in CONTROL_PEERS or source in FIXTURE_LINKS or source.is_unspecified) \
                or not (str(destination) in CONTROL_PEERS or destination in FIXTURE_LINKS):
            raise ValueError("ARP endpoint outside the disposable fixture")
        return None
    packet = frame[14:]
    if ether_type == 0x0800:
        if len(packet) < 20 or packet[0] >> 4 != 4:
            raise ValueError("short IPv4 header")
        offset = (packet[0] & 15) * 4
        total = struct.unpack("!H", packet[2:4])[0]
        if offset < 20 or total < offset or total > len(packet) \
                or struct.unpack("!H", packet[6:8])[0] & 0x3fff:
            raise ValueError("invalid or fragmented IPv4 capture")
        source, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
        protocol = packet[9]
        version = 4
    elif ether_type == 0x86dd:
        if len(packet) < 40 or packet[0] >> 4 != 6:
            raise ValueError("short IPv6 header")
        total = 40 + struct.unpack("!H", packet[4:6])[0]
        if total > len(packet):
            raise ValueError("truncated IPv6 capture")
        source = socket.inet_ntop(socket.AF_INET6, packet[8:24])
        destination = socket.inet_ntop(socket.AF_INET6, packet[24:40])
        protocol, offset, version = packet[6], 40, 6
        # MLD uses a Hop-by-Hop Router Alert. No routing/fragment/ESP path is admitted.
        if protocol == 0:
            if offset + 2 > total:
                raise ValueError("short IPv6 hop-by-hop header")
            protocol, length = packet[offset], (packet[offset + 1] + 1) * 8
            offset += length
            if offset > total or protocol != socket.IPPROTO_ICMPV6:
                raise ValueError("invalid IPv6 hop-by-hop header")
    else:
        raise ValueError("unexpected Ethernet protocol")
    transport = packet[offset:total]
    sport = dport = 0
    if protocol == socket.IPPROTO_UDP:
        if len(transport) < 8:
            raise ValueError("short UDP header")
        sport, dport, length = struct.unpack("!HHH", transport[:6])
        if length < 8 or length > len(transport):
            raise ValueError("truncated UDP datagram")
        payload = transport[8:length]
    elif protocol == socket.IPPROTO_TCP:
        if len(transport) < 20:
            raise ValueError("short TCP header")
        sport, dport = struct.unpack("!HH", transport[:4])
        offset = (transport[12] >> 4) * 4
        if offset < 20 or offset > len(transport):
            raise ValueError("invalid TCP data offset")
        payload = transport[offset:]
    else:
        payload = transport
    return version, protocol, source, sport, destination, dport, payload


def udp_diagnostic_label(source, sport, destination, dport, payload):
    """One fixed explanatory class; never a packet admission or an authority decision."""
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    fixture_pair = (source in CONTROL_PEERS or src in FIXTURE_LINKS) and (
        destination in CONTROL_PEERS or dst in FIXTURE_LINKS)
    if fixture_pair and 41000 in (sport, dport):
        return "control_port"
    if dport == 5353 and destination in ("224.0.0.251", "ff02::fb"):
        return "mdns_multicast"
    if fixture_pair and len(payload) >= 4 and payload[:4] in (
            b"\x01\x00\x00\x00", b"\x02\x00\x00\x00", b"\x03\x00\x00\x00", b"\x04\x00\x00\x00"):
        return "wireguard_header"
    return "fixture_pair_other" if fixture_pair else "outside_fixture"


def icmp_diagnostics(payload):
    """Fixed ICMPv4 type/code and quoted UDP class, with no allowlist exception."""
    kind = payload[0] if payload else None
    code = payload[1] if len(payload) >= 2 else None
    label = ("port_unreachable" if (kind, code) == (3, 3) else
             "fragmentation_needed" if (kind, code) == (3, 4) else
             "destination_unreachable" if kind == 3 else
             "time_exceeded" if kind == 11 else "other")
    result = {f"forbidden_icmp_{label}_packets": 1}
    quote = payload[8:]
    offset = (quote[0] & 15) * 4 if quote else 0
    # ICMP normally quotes only the original IP header and first eight UDP bytes.
    # Its original total length can legitimately exceed the quoted bounded prefix.
    if kind not in (3, 11) or len(quote) < 20 or quote[0] >> 4 != 4 \
            or not 20 <= offset <= 60 or len(quote) < offset + 8 \
            or quote[9] != socket.IPPROTO_UDP or struct.unpack("!H", quote[6:8])[0] & 0x3fff:
        result["forbidden_icmp_unparsed_quote_packets"] = 1
        return result
    source, destination = socket.inet_ntoa(quote[12:16]), socket.inet_ntoa(quote[16:20])
    sport, dport, length = struct.unpack("!HHH", quote[offset:offset + 6])
    if length < 8:
        result["forbidden_icmp_unparsed_quote_packets"] = 1
        return result
    label = udp_diagnostic_label(source, sport, destination, dport, quote[offset + 8:offset + length])
    result[f"forbidden_icmp_quoted_udp_{label}_packets"] = 1
    return result


def diagnostic_updates(packet, classification):
    """Describe the existing decision with bounded counters, without changing that decision."""
    if packet is None:
        return ({"forbidden_unparsed_packets": 1} if classification.get("forbidden_packets")
                else {"classified_arp_packets": 1})
    version, protocol, source, sport, destination, dport, payload = packet
    label = PROTOCOL_LABELS.get(protocol, "other_ip")
    updates = {f"classified_{label}_packets": 1}
    if classification.get("forbidden_packets"):
        updates[f"forbidden_{label}_packets"] = 1
        if not any(classification.get(reason) for reason in (
                "direct_client_exit_packets", "direct_provider_packets", "malformed_packets")):
            updates[f"forbidden_ipv{version}_unmatched_packets"] = 1
        if protocol == socket.IPPROTO_UDP:
            detail = udp_diagnostic_label(source, sport, destination, dport, payload)
            updates[f"forbidden_udp_{detail}_packets"] = 1
        elif version == 4 and protocol == socket.IPPROTO_ICMP:
            updates.update(icmp_diagnostics(payload))
    return updates


def stop_capture_intake(observer):
    """Keep the existing queue while atomically rejecting future packet-socket intake."""
    class Instruction(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.POINTER(Instruction))]

    instructions = (Instruction * 1)(Instruction(0x06, 0, 0, 0))
    observer.setsockopt(socket.SOL_SOCKET, 26, bytes(Program(1, instructions)))


def capture(layout, output, ready, role, interfaces):
    validate_layout(layout)
    role_node(layout, role)
    if not 1 <= len(interfaces) <= 16 or len(set(interfaces)) != len(interfaces) \
            or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) for name in interfaces):
        raise ValueError("invalid physical interface set")
    record = dict(schema_version=1, phase=layout["phase"], capture_role=role,
                  node=role_node(layout, role), interfaces=interfaces, interface_statistics={},
                  observed_frames=0, packet_socket_drops=0, truncated=False, complete=False,
                  **dict.fromkeys((*COUNTERS, *DIAGNOSTIC_COUNTERS), 0))
    for relay in layout["relays"]:
        for leg in ("client_leg", "exit_leg"):
            record[f"{relay}_{leg}_wireguard_data_datagrams"] = 0
    sockets = {}
    provider_flows = {}
    record["provider_payload_timeline"] = []
    running = True

    def stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def receive(observer):
        frame, _ancillary, flags, _address = observer.recvmsg(MAX_FRAME_BYTES)
        record["observed_frames"] += 1
        record["interface_statistics"][sockets[observer]]["observed_frames"] += 1
        if flags & socket.MSG_TRUNC or record["observed_frames"] > MAX_FRAMES:
            record["truncated"] = True
            return
        packet = None
        try:
            packet = decode_frame(frame)
            if packet is None:
                updates = {"neighbor_packets": 1}
            else:
                record[f"ipv{packet[0]}_frames"] += 1
                updates = classify(layout, role, *packet[1:], sockets[observer])
                if layout["phase"] == "uptake" and updates.get("provider_response_payload_bytes", 0):
                    flow = packet[2:6]
                    provider_flows.setdefault(flow, len(provider_flows))
                    timeline = record["provider_payload_timeline"]
                    if len(provider_flows) > 16 or len(timeline) >= 4096:
                        record["truncated"] = True
                    else:
                        # No addresses, TCP sequence numbers, or body bytes are retained.
                        timeline.append(dict(at_ns=time.monotonic_ns(), flow=provider_flows[flow],
                                             bytes=updates["provider_response_payload_bytes"]))
        except ValueError:
            updates = {"malformed_packets": 1, "forbidden_packets": 1}
        record["interface_statistics"][sockets[observer]]["forbidden_packets"] += updates.get(
            "forbidden_packets", 0)
        for name, count in diagnostic_updates(packet, updates).items():
            record[name] += count
            record["interface_statistics"][sockets[observer]][name] += count
        for name, count in updates.items():
            record[name] += count

    try:
        for interface in interfaces:
            observer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
            sockets[observer] = interface
            observer.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)
            actual = observer.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            if not 4 * 1024 * 1024 <= actual <= 8 * 1024 * 1024:
                raise ValueError("bounded capture buffer unavailable")
            record["interface_statistics"][interface] = dict(
                receive_buffer_bytes=actual, observed_frames=0, intake_stopped=False,
                drained=False, packet_socket_packets=0, packet_socket_drops=0, forbidden_packets=0,
                **dict.fromkeys(DIAGNOSTIC_COUNTERS, 0))
            observer.bind((interface, 3))
            observer.setblocking(False)
        with Path(ready).open("x", encoding="ascii") as marker:
            marker.write("ready\n")
        deadline, drain_deadline = time.monotonic() + MAX_SECONDS, None
        while True:
            current = time.monotonic()
            if current >= deadline:
                record["truncated"], running = True, False
            if record["truncated"]:
                running = False
            if not running and drain_deadline is None:
                for observer, interface in sockets.items():
                    stop_capture_intake(observer)
                    record["interface_statistics"][interface]["intake_stopped"] = True
                drain_deadline = current + DRAIN_SECONDS
            if drain_deadline is not None and current >= drain_deadline:
                record["truncated"] = True
                break
            readable, _, _ = select.select(list(sockets), [], [], 0.2 if running else 0)
            if not readable and not running:
                if drain_deadline is None:  # Signal delivered while select() was waiting.
                    continue
                for statistics in record["interface_statistics"].values():
                    statistics["drained"] = True
                break
            for observer in readable:
                for _ in range(128):
                    try:
                        receive(observer)
                    except BlockingIOError:
                        break
        for observer, interface in sockets.items():
            packets, drops = struct.unpack("II", observer.getsockopt(263, 6, 8))
            statistics = record["interface_statistics"][interface]
            statistics.update(packet_socket_packets=packets, packet_socket_drops=drops)
            record["packet_socket_drops"] += drops
            if packets != statistics["observed_frames"] + drops:
                record["truncated"] = True
        record["complete"] = not record["truncated"] and record["packet_socket_drops"] == 0 and all(
            row["intake_stopped"] and row["drained"] and
            row["packet_socket_packets"] == row["observed_frames"]
            for row in record["interface_statistics"].values())
        with Path(output).open("x", encoding="ascii") as report:
            json.dump(record, report, sort_keys=True, separators=(",", ":"))
            report.write("\n")
    finally:
        for observer in sockets:
            observer.close()
    if not record["complete"]:
        raise ValueError("replication capture incomplete or dropped frames")
    return record


def main(arguments):
    if len(arguments) < 6 or arguments[0] != "capture":
        raise ValueError("usage: capture LAYOUT_JSON OUTPUT READY ROLE IFACE...")
    layout_path, output, ready, role, *interfaces = arguments[1:]
    with Path(layout_path).open("rb") as source:
        data = source.read(8193)
    if len(data) > 8192:
        raise ValueError("oversized capture layout")
    capture(json.loads(data), output, ready, role, interfaces)


if __name__ == "__main__":
    main(sys.argv[1:])
