#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Focused synthetic classifier/drain checks, not a real network acceptance claim."""

import copy
import ctypes
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "replication_capture", Path(__file__).with_name("content-replication-capture.py"))
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def layout(phase="uptake"):
    client, provider = ("relay4", "relay5") if phase == "uptake" else ("client", "relay4")
    return dict(phase=phase, client=dict(node=client, ip=CAPTURE.PUBLIC[client]),
                provider=dict(node=provider, ip=CAPTURE.PUBLIC[provider]),
                exit=dict(node="exit", ip=CAPTURE.PUBLIC["exit"]),
                relays={name: CAPTURE.PUBLIC[name] for name in ("relay0", "relay2")})


def classify(current, role, source, destination, protocol=socket.IPPROTO_UDP,
             sport=22000, dport=23000, payload=struct.pack("<I", 4) + bytes(44), iface="physical0"):
    return CAPTURE.classify(current, role, protocol, source, sport, destination,
                            dport, payload, iface)


def udp_frame(source, destination, payload):
    transport = struct.pack("!HHHH", 22000, 23000, len(payload) + 8, 0) + payload
    return ipv4_frame(source, destination, socket.IPPROTO_UDP, transport)


def ipv4_frame(source, destination, protocol, transport):
    header = bytearray(20)
    header[0], header[9] = 0x45, protocol
    header[2:4] = struct.pack("!H", len(header) + len(transport))
    header[12:16], header[16:20] = socket.inet_aton(source), socket.inet_aton(destination)
    return bytes(12) + b"\x08\x00" + header + transport


def checksummed(payload):
    payload = bytearray(payload)
    payload[2:4] = b"\0\0"
    padded = payload + (b"\0" if len(payload) % 2 else b"")
    total = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    payload[2:4] = struct.pack("!H", total ^ 0xffff)
    return bytes(payload)


def repair_layout():
    current = layout()
    current["phase"] = "repair-uptake"
    current["relays"]["relay1"] = CAPTURE.PUBLIC["relay1"]
    return CAPTURE.validate_layout(current)


def membership_frame(source, destination="224.0.0.22", payload=None, ttl=1, options=b"\x94\x04\0\0"):
    if payload is None:
        payload = checksummed(bytes([0x22, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0])
                              + socket.inet_aton("224.0.0.251"))
    frame = bytearray(ipv4_frame(source, destination, socket.IPPROTO_IGMP, payload))
    frame[14] = 0x46
    frame[22] = ttl
    frame[16:18] = struct.pack("!H", 24 + len(payload))
    frame[34:34] = options
    return bytes(frame)


class ReplicationCaptureTests(unittest.TestCase):
    def test_duration_is_explicit_bounded_and_preserves_default_capture_contract(self):
        self.assertEqual(CAPTURE.MAX_SECONDS, 1800)
        self.assertEqual(CAPTURE.capture_seconds("4200"), 4200)
        with patch.object(CAPTURE.socket, "socket") as create_socket:
            for invalid in (0, -1, 4201, True, 1.0, "", "04200", "1e3", "9" * 100):
                with self.assertRaises(ValueError):
                    CAPTURE.capture(layout(), "unused", "unused", "relay4", ["underlay"], invalid)
            create_socket.assert_not_called()
        with tempfile.TemporaryDirectory(prefix="volparossa-capture-duration-") as temporary:
            source = Path(temporary) / "layout.json"
            source.write_text(json.dumps(layout()))
            with patch.object(CAPTURE, "capture") as run_capture:
                for duration in (None, "4200"):
                    extra = [] if duration is None else ["--max-seconds", duration]
                    CAPTURE.main(["capture", str(source), "output", "ready", "relay4", *extra, "underlay"])
                    self.assertEqual(run_capture.call_args.args[-2:], (["underlay"], 1800 if duration is None else 4200))
                for extra in (["--max-seconds"], ["--max-seconds", "4200"], ["--max-seconds", "4201", "underlay"]):
                    with self.assertRaises(ValueError):
                        CAPTURE.main(["capture", str(source), "output", "ready", "relay4", *extra])
        old, _ = buffered_capture()
        extended, _ = buffered_capture(max_seconds=4200)
        self.assertNotIn("max_seconds", old)
        self.assertEqual(extended.pop("max_seconds"), 4200)
        self.assertEqual(extended, old)

    def test_repair_membership_requires_exact_mdns_group_link_and_actual_ip_header(self):
        current = repair_layout()
        expected = {"control_packets": 1, "mdns_membership_packets": 1}
        for node, iface, source in (("relay4", "underlay", "49.165.5.1"),
                ("relay4", "ar0", "10.241.90.1"), ("relay0", "r0a", "10.241.90.1"),
                ("relay1", "r1a", "10.241.94.1"), ("relay2", "r2a", "10.241.92.1"),
                ("exit", "xr5", "10.241.25.1"), ("relay5", "r5b1", "10.241.52.1")):
            frame = membership_frame(source)
            packet = CAPTURE.decode_frame(frame)
            self.assertEqual(CAPTURE.classify(current, node, *packet[1:], iface, frame=frame), expected)
            self.assertEqual(CAPTURE.classify(current, node, *packet[1:], iface), {"forbidden_packets": 1})
            self.assertEqual(CAPTURE.classify(current, node, *packet[1:], "wrong0", frame=frame),
                             {"forbidden_packets": 1})
        for frame in (membership_frame("203.0.113.1"), membership_frame("10.241.94.1"),
                membership_frame("10.241.90.1", destination="224.0.0.2"),
                membership_frame("10.241.90.1", ttl=2),
                membership_frame("10.241.90.1", options=bytes(4))):
            self.assertEqual(CAPTURE.classify(current, "relay4", *CAPTURE.decode_frame(frame)[1:],
                                              "ar0", frame=frame), {"forbidden_packets": 1})
        valid = membership_frame("10.241.90.1")
        for position, value in ((0, 0x16), (1, 1), (4, 1), (7, 2), (8, 1),
                                 (9, 1), (11, 1), (15, 252)):
            payload = bytearray(CAPTURE.decode_frame(valid)[-1])
            payload[position] = value
            frame = membership_frame("10.241.90.1", payload=checksummed(payload))
            self.assertEqual(CAPTURE.classify(current, "relay4", *CAPTURE.decode_frame(frame)[1:],
                                              "ar0", frame=frame), {"forbidden_packets": 1})
        bad = bytearray(valid)
        bad[40] ^= 1  # IGMP checksum, not application bytes.
        for phase, frame in (("uptake", valid), ("repair-uptake", bytes(bad)),
                              ("repair-uptake", membership_frame("10.241.90.1",
                               payload=CAPTURE.decode_frame(valid)[-1] + b"extra"))):
            current["phase"] = phase
            self.assertEqual(CAPTURE.classify(current, "relay4", *CAPTURE.decode_frame(frame)[1:],
                                              "ar0", frame=frame), {"forbidden_packets": 1})

    def test_repair_wireguard_error_is_reverse_exact_client_leg_quote_not_delivered_data(self):
        current = repair_layout()
        expected = {"control_packets": 1, "wireguard_port_unreachable_packets": 1}
        for relay in ("relay0", "relay1", "relay2"):
            remote = CAPTURE.PUBLIC[relay]
            for kind, length in ((1, 148), (2, 92), (3, 64), (4, 32), (4, 1452)):
                transport = struct.pack("!HHHH", 43001, 44001, length + 8, 0)
                transport += struct.pack("<I", kind) + bytes(length - 4)
                original = ipv4_frame("49.165.5.1", remote, socket.IPPROTO_UDP, transport)[14:]
                # A legal bounded ICMP quotation can omit the encrypted datagram's tail.
                error = checksummed(b"\x03\x03" + bytes(6) + original[:44])
                for node, iface in (("relay4", "ar" + relay[-1]), (relay, "r" + relay[-1] + "a")):
                    self.assertEqual(classify(current, node, remote, "49.165.5.1", socket.IPPROTO_ICMP,
                                              payload=error, iface=iface), expected)
                    self.assertEqual(classify(current, node, remote, "49.165.5.1", socket.IPPROTO_ICMP,
                                              payload=error, iface="wrong0"), {"forbidden_packets": 1})
        # Preserve privacy denials even if an ICMP body resembles the newly recognized error.
        for role, source, destination, iface in (("exit", "46.162.3.1", "49.165.5.1", "xr0"),
                ("relay4", "50.166.6.1", "49.165.5.1", "r4c"),
                ("relay4", "10.241.90.2", "49.165.5.1", "ar0"),
                ("relay4", "49.165.5.1", "42.158.0.1", "ar0")):
            self.assertEqual(classify(current, role, source, destination, socket.IPPROTO_ICMP,
                                      payload=error, iface=iface).get("forbidden_packets"), 1)
        original = ipv4_frame("49.165.5.1", "42.158.0.1", socket.IPPROTO_UDP,
                             struct.pack("!HHHH", 43001, 44001, 156, 0) + b"\x01\0\0\0" + bytes(144))[14:]
        valid = checksummed(b"\x03\x03" + bytes(6) + original)
        for position, value in ((0, 11), (1, 4), (4, 1), (8, 0x46), (14, 0x20),
                                 (17, socket.IPPROTO_TCP), (24, 203), (33, 8), (36, 5)):
            invalid = bytearray(valid)
            invalid[position] = value
            self.assertEqual(classify(current, "relay4", "42.158.0.1", "49.165.5.1", socket.IPPROTO_ICMP,
                                      payload=checksummed(invalid), iface="ar0"), {"forbidden_packets": 1}, position)
        corrupted = bytearray(valid)
        corrupted[2] ^= 1
        for invalid in (bytes(corrupted), checksummed(valid[:51]), checksummed(valid + b"extra")):
            self.assertEqual(classify(current, "relay4", "42.158.0.1", "49.165.5.1", socket.IPPROTO_ICMP,
                                      payload=invalid, iface="ar0"), {"forbidden_packets": 1})
        self.assertEqual(classify(layout(), "relay4", "42.158.0.1", "49.165.5.1", socket.IPPROTO_ICMP,
                                  payload=valid, iface="ar0"), {"forbidden_packets": 1})

    def test_autonomous_repair_records_three_candidates_without_widening_other_phases(self):
        current = layout()
        current["phase"] = "repair-uptake"
        current["relays"]["relay1"] = CAPTURE.PUBLIC["relay1"]
        self.assertEqual(CAPTURE.validate_layout(current), current)
        for relay, address in current["relays"].items():
            result = classify(current, relay, CAPTURE.PUBLIC["relay4"], address)
            self.assertEqual(result[f"{relay}_client_leg_wireguard_data_datagrams"], 1)
            result = classify(current, relay, address, CAPTURE.PUBLIC["exit"])
            self.assertEqual(result[f"{relay}_exit_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(classify(current, "relay4", CAPTURE.PUBLIC["relay4"],
                                  CAPTURE.PUBLIC["exit"])["direct_client_exit_packets"], 1)
        self.assertEqual(classify(current, "relay4", CAPTURE.PUBLIC["relay4"],
                                  CAPTURE.PUBLIC["relay5"], socket.IPPROTO_TCP,
                                  dport=18080)["direct_provider_packets"], 1)
        for phase in ("uptake", "reserve-fetch"):
            invalid = layout(phase)
            invalid["relays"]["relay1"] = CAPTURE.PUBLIC["relay1"]
            with self.assertRaises(ValueError):
                CAPTURE.validate_layout(invalid)
        for field in ("client", "provider", "exit", "relays"):
            invalid = copy.deepcopy(current)
            if field == "relays":
                del invalid[field]["relay1"]
            else:
                invalid[field]["ip"] = "203.0.113.1"
            with self.assertRaises(ValueError):
                CAPTURE.validate_layout(invalid)

    def test_both_phase_roles_count_only_selected_encrypted_legs(self):
        for phase in ("uptake", "reserve-fetch"):
            current = CAPTURE.validate_layout(layout(phase))
            client, exit_ip = current["client"]["ip"], current["exit"]["ip"]
            for relay, address in current["relays"].items():
                for source, destination in ((client, address), (address, client)):
                    for node in (current["client"]["node"], relay):
                        result = classify(current, node, source, destination)
                        self.assertEqual(result["client_leg_wireguard_data_datagrams"], 1)
                        self.assertEqual(result[f"{relay}_client_leg_wireguard_data_datagrams"], 1)
                for source, destination in ((address, exit_ip), (exit_ip, address)):
                    self.assertEqual(classify(current, relay, source, destination)[
                        "exit_leg_wireguard_data_datagrams"], 1)
            self.assertEqual(classify(current, "provider", client, current["relays"]["relay0"]),
                             {"forbidden_packets": 1})
            self.assertEqual(classify(current, current["client"]["node"], client,
                                      CAPTURE.PUBLIC["relay1"]), {"forbidden_packets": 1})

    def test_exact_provider_tcp_and_direct_exit_denials_include_control_exception(self):
        for phase in ("uptake", "reserve-fetch"):
            current = layout(phase)
            client, exit_ip, provider = (current[key]["ip"] for key in ("client", "exit", "provider"))
            for role in ("exit", "provider", current["provider"]["node"]):
                self.assertEqual(classify(current, role, exit_ip, provider, socket.IPPROTO_TCP,
                                          dport=18080, payload=b"request"),
                                 {"provider_request_packets": 1})
                self.assertEqual(classify(current, role, provider, exit_ip, socket.IPPROTO_TCP,
                                          sport=18080, payload=b"body"),
                                 {"provider_response_packets": 1, "provider_response_payload_bytes": 4})
            for endpoint in (client, *current["relays"].values()):
                self.assertEqual(classify(current, "provider", endpoint, provider,
                                          socket.IPPROTO_TCP, dport=18080)["direct_provider_packets"], 1)
            self.assertEqual(classify(current, "exit", client, exit_ip, dport=41000),
                             {"control_packets": 1})
            self.assertEqual(classify(current, "exit", exit_ip, client, sport=41000),
                             {"control_packets": 1})
            for protocol in (socket.IPPROTO_UDP, socket.IPPROTO_TCP):
                self.assertEqual(classify(current, "exit", client, exit_ip, protocol, dport=22000)[
                    "direct_client_exit_packets"], 1)
            self.assertEqual(classify(current, "exit", client, exit_ip, socket.IPPROTO_TCP,
                                      dport=41000)["direct_client_exit_packets"], 1)
            self.assertEqual(classify(current, "exit", exit_ip, provider, socket.IPPROTO_TCP,
                                      dport=18081), {"forbidden_packets": 1})

    def test_control_neighbor_and_keepalive_never_count_content_or_data(self):
        current = layout()
        self.assertEqual(classify(current, "relay4", "49.165.5.1", "40.156.1.1", dport=41000),
                         {"control_packets": 1})
        self.assertEqual(classify(current, "relay4", "49.165.5.1", "203.0.113.1", dport=41000),
                         {"forbidden_packets": 1})
        self.assertEqual(classify(current, "relay4", "49.165.5.1", "203.0.113.1", sport=5353, dport=5353),
                         {"forbidden_packets": 1})
        self.assertEqual(classify(current, "relay4", "10.241.90.1", "224.0.0.251", sport=5353, dport=5353, iface="ar0"),
                         {"mdns_packets": 1, "control_packets": 1})
        self.assertEqual(classify(current, "relay4", "10.241.90.1", "224.0.0.251", sport=45678, dport=5353, iface="ar0"),
                         {"mdns_packets": 1, "control_packets": 1})
        self.assertEqual(classify(current, "relay4", "10.241.90.1", "224.0.0.251", sport=0, dport=5353),
                         {"forbidden_packets": 1})
        self.assertEqual(classify(current, "relay4", "203.0.113.1", "224.0.0.251", sport=45678, dport=5353),
                         {"forbidden_packets": 1})
        self.assertEqual(classify(current, "relay4", "fe80::1", "ff02::fb", sport=5353, dport=5353),
                         {"mdns_packets": 1, "control_packets": 1})
        self.assertEqual(classify(current, "relay4", "fe80::1", "ff02::fb", sport=45678, dport=5353),
                         {"mdns_packets": 1, "control_packets": 1})
        for destination in ("ff02::1", "fe80::2"):
            self.assertEqual(classify(current, "relay4", "fe80::1", destination,
                                      socket.IPPROTO_ICMPV6, payload=bytes([136]) + bytes(23)),
                             {"neighbor_packets": 1})
        self.assertEqual(classify(current, "relay4", "fe80::1", "fe80::2", dport=41000),
                         {"forbidden_packets": 1})
        for payload, counter in ((struct.pack("<I", 4) + bytes(28), "wireguard_keepalive_packets"),
                                 (struct.pack("<I", 1) + bytes(144), "wireguard_handshake_packets")):
            self.assertEqual(classify(current, "relay4", "49.165.5.1", "42.158.0.1", payload=payload),
                             {counter: 1})

    def test_owner_fixture_allows_only_exact_local_tuple_phase_interface_and_shape(self):
        expected = dict(owner_fixture_packets=1, owner_fixture_payload_bytes=1200)
        payload = b"VPC04OWN" + bytes(1192)
        for node, iface in (("relay4", "ar0"), ("relay0", "r0a")):
            self.assertEqual(classify(layout(), node, "10.241.90.1", "10.241.90.2",
                                     sport=19004, dport=19004, payload=payload, iface=iface), expected)
        for current, node, source, destination, sport, dport, body, iface in (
            (layout("reserve-fetch"), "relay4", "10.241.90.1", "10.241.90.2", 19004, 19004, payload, "ar0"),
            (layout(), "relay4", "10.241.90.3", "10.241.90.2", 19004, 19004, payload, "ar0"),
            (layout(), "relay4", "10.241.90.1", "46.162.3.1", 19004, 19004, payload, "ar0"),
            (layout(), "relay4", "10.241.90.1", "10.241.90.2", 19005, 19004, payload, "ar0"),
            (layout(), "relay4", "10.241.90.1", "10.241.90.2", 19004, 19004, bytes(1200), "ar0"),
            (layout(), "relay4", "10.241.90.1", "10.241.90.2", 19004, 19004, payload, "ar2"),
        ):
            self.assertEqual(classify(current, node, source, destination, sport=sport, dport=dport,
                                     payload=body, iface=iface).get("forbidden_packets"), 1)

    def test_wireguard_mtu_clamped_data_is_legal_but_not_arbitrary_or_oversized_udp(self):
        current = layout()
        # Linux pads only up to MTU1420: 1420 plaintext +32 authenticated overhead =1452.
        payload = struct.pack("<I", 4) + bytes(1448)
        result = classify(current, "relay4", "49.165.5.1", "42.158.0.1", payload=payload)
        self.assertEqual(result["client_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(result["client_leg_wireguard_data_bytes"], 1452)
        for length in (31, 47, 1451, 1453, 1456, 65504):
            self.assertEqual(classify(current, "relay4", "49.165.5.1", "42.158.0.1",
                                      payload=struct.pack("<I", 4) + bytes(length - 4)),
                             {"forbidden_packets": 1})
        self.assertEqual(classify(current, "relay4", "49.165.5.1", "42.158.0.1", payload=bytes(1452)),
                         {"forbidden_packets": 1})
        self.assertEqual(classify(current, "exit", "49.165.5.1", "46.162.3.1", payload=payload)[
            "direct_client_exit_packets"], 1)

    def test_exact_fixture_control_errors_bind_reverse_quote_ports_and_physical_link(self):
        current = layout()
        for iface, segment in (("xr3", 23), ("xr5", 25)):
            src, dst = f"10.241.{segment}.1", f"10.241.{segment}.2"
            udp = struct.pack("!HHHH", 45678, 41000, 8, 0)
            quoted = ipv4_frame(dst, src, socket.IPPROTO_UDP, udp)[14:]
            error = b"\x03\x03" + bytes(6) + quoted
            self.assertEqual(classify(current, "exit", dst, src, dport=41000, iface=iface),
                             {"control_packets": 1})
            self.assertEqual(classify(current, "exit", src, dst, socket.IPPROTO_ICMP,
                                      payload=error, iface=iface),
                             {"control_packets": 1, "control_port_unreachable_packets": 1})
            wrong_port = bytearray(error)
            wrong_port[-6:-4] = struct.pack("!H", 443)
            fragmented = bytearray(error)
            fragmented[14:16] = b"\x20\x00"
            for bad in (b"\x03\x04" + error[2:], b"\x0b\x00" + error[2:], error[:-1],
                        bytes(wrong_port), bytes(fragmented)):
                self.assertEqual(classify(current, "exit", src, dst, socket.IPPROTO_ICMP,
                                          payload=bad, iface=iface), {"forbidden_packets": 1})
            for bad_src, bad_dst, bad_iface in ((dst, src, iface), (src, "10.241.99.2", iface),
                                                (src, dst, "xr2"), ("203.0.113.1", dst, iface)):
                self.assertEqual(classify(current, "exit", bad_src, bad_dst, socket.IPPROTO_ICMP,
                                          payload=error, iface=bad_iface), {"forbidden_packets": 1})
            self.assertEqual(classify(current, "exit", dst, src, dport=443, iface=iface),
                             {"forbidden_packets": 1})
            self.assertEqual(classify(current, "exit", "10.241.99.2", src, dport=41000, iface=iface),
                             {"forbidden_packets": 1})

    def test_mdns_source_must_belong_to_the_actual_captured_fixture_link(self):
        current = layout()
        for source in ("47.163.4.1", "47.163.4.2", "10.241.31.1", "10.241.31.2"):
            self.assertEqual(classify(current, "exit", source, "224.0.0.251", sport=45678,
                                      dport=5353, iface="xd"), {"mdns_packets": 1, "control_packets": 1})
            self.assertEqual(classify(current, "exit", source, "224.0.0.251", sport=45678,
                                      dport=5353, iface="xr3"), {"forbidden_packets": 1})
        self.assertEqual(classify(current, "relay4", "10.241.99.1", "224.0.0.251", sport=45678,
                                  dport=5353, iface="ar0"), {"forbidden_packets": 1})
        self.assertEqual(CAPTURE.MDNS_INTERFACE_ADDRESSES["relay4", "ar1"],
                         {"10.241.94.1", "10.241.94.2"})

    def test_repair_restart_control_is_exact_link_bound_and_never_a_data_exception(self):
        cases = (("relay4", "r4b1", 50, "49.165.5.1", "40.156.1.1"),
                 ("relay1", "r1x", 21, "44.160.1.1", "46.162.3.1"),
                 ("relay0", "r0x2", 26, "42.158.0.1", "51.167.7.1"),
                 ("relay4", "ar1", 94, "49.165.5.1", "44.160.1.1"),
                 ("client", "cb2", 41, "43.159.1.1", "41.157.2.1"))
        for node, iface, segment, local_public, remote_public in cases:
            current = layout("reserve-fetch") if node == "client" else layout()
            if node != "client":
                current["phase"] = "repair-uptake"
                current["relays"]["relay1"] = CAPTURE.PUBLIC["relay1"]
            local, remote = f"10.241.{segment}.1", f"10.241.{segment}.2"
            self.assertEqual(CAPTURE.EXACT_CONTROL_LINKS[node, iface],
                             ({local, local_public}, {remote, remote_public}))
            for source, destination in ((local, remote), (remote, local),
                                         (local_public, remote), (local, remote_public)):
                self.assertEqual(classify(current, node, source, destination,
                                          dport=41000, iface=iface), {"control_packets": 1})
                udp = struct.pack("!HHHH", 45678, 41000, 8, 0)
                quote = ipv4_frame(source, destination, socket.IPPROTO_UDP, udp)[14:]
                error = b"\x03\x03" + bytes(6) + quote
                self.assertEqual(classify(current, node, destination, source, socket.IPPROTO_ICMP,
                                          payload=error, iface=iface),
                                 {"control_packets": 1, "control_port_unreachable_packets": 1})
                self.assertEqual(classify(current, node, destination, source, socket.IPPROTO_ICMP,
                                          payload=error, iface="wrong0"), {"forbidden_packets": 1})
            for source, destination, port, interface in ((local, remote, 443, iface),
                    (local, remote, 41000, "wrong0"), (local, local_public, 41000, iface),
                    ("10.241.99.1", remote, 41000, iface), (local, "203.0.113.1", 41000, iface)):
                self.assertEqual(classify(current, node, source, destination,
                                          dport=port, iface=interface), {"forbidden_packets": 1})

    def test_forbidden_wireguard_quote_and_igmp_get_headers_not_a_pass(self):
        marker = b"never-store-this-content"
        udp = struct.pack("!HHHH", 45678, 23000, 12 + len(marker), 0) + b"\x04\0\0\0" + marker
        quote = ipv4_frame("49.165.5.1", "42.158.0.1", socket.IPPROTO_UDP, udp)[14:]
        frame = ipv4_frame("42.158.0.1", "49.165.5.1", socket.IPPROTO_ICMP, b"\x03\x03" + bytes(6) + quote)
        packet = CAPTURE.decode_frame(frame)
        self.assertEqual(CAPTURE.classify(layout(), "relay4", *packet[1:], "ar0"),
                         {"forbidden_packets": 1})
        sample = CAPTURE.fixture_header_sample(packet, "ar0", frame)
        self.assertEqual(sample["quoted_udp"], {"source": "relay4.public", "destination": "relay0.public",
                         "source_port": "other_nonzero", "destination_port": "other_nonzero",
                         "classification": "wireguard_header"})
        self.assertNotIn(marker.decode(), json.dumps(sample))
        report = bytes([0x22, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0]) + socket.inet_aton("224.0.0.251")
        frame = ipv4_frame("10.241.90.1", "224.0.0.22", socket.IPPROTO_IGMP, report)
        packet = CAPTURE.decode_frame(frame)
        self.assertEqual(CAPTURE.classify(layout(), "relay4", *packet[1:], "ar0"),
                         {"forbidden_packets": 1})
        sample = CAPTURE.fixture_header_sample(packet, "ar0", frame)
        self.assertEqual(sample["source"], "relay4.ar0")
        self.assertEqual(sample["igmp"]["records"], [{"type": 4, "auxiliary_words": 0,
                                                      "source_count": 0, "group": "mdns.multicast"}])
        self.assertEqual(sample["igmp"]["parse"], "complete")
        incomplete = CAPTURE.decode_frame(ipv4_frame("10.241.90.1", "224.0.0.22", socket.IPPROTO_IGMP,
                                                     report[:-1]))
        self.assertEqual(CAPTURE.fixture_header_sample(incomplete, "ar0", b"")["igmp"]["parse"], "incomplete")

    def test_failure_headers_are_deduplicated_capped_and_unknown_addresses_redacted(self):
        record = {"forbidden_header_samples": [], "forbidden_header_sample_overflow_packets": 0}
        for protocol in range(1, CAPTURE.MAX_HEADER_SAMPLES + 4):
            packet = (4, protocol, "203.0.113.123", 45678, "192.0.2.45", 23456, b"private-payload")
            for _ in range(2):
                CAPTURE.record_forbidden_header(record, packet, "ar0", b"")
        self.assertEqual(len(record["forbidden_header_samples"]), CAPTURE.MAX_HEADER_SAMPLES)
        self.assertEqual(record["forbidden_header_sample_overflow_packets"], 6)
        self.assertTrue(all(row["packets"] == 2 for row in record["forbidden_header_samples"]))
        for text in ("203.0.113.123", "192.0.2.45", "private-payload", "45678", "23456"):
            self.assertNotIn(text, json.dumps(record))

    def test_layout_and_frame_bounds_reject_substitution_fragments_and_truncation(self):
        current = layout()
        for path, value in (("phase", "forged"), ("client", dict(node="client", ip="43.159.1.1")),
                            ("relays", {"relay0": "42.158.0.1"})):
            invalid = copy.deepcopy(current)
            invalid[path] = value
            with self.assertRaises(ValueError):
                CAPTURE.validate_layout(invalid)
        frame = udp_frame("49.165.5.1", "42.158.0.1", struct.pack("<I", 4) + bytes(44))
        decoded = CAPTURE.decode_frame(frame)
        self.assertEqual(decoded[2], "49.165.5.1")
        for invalid in (frame[:30], frame[:-1], frame[:20] + b"\x20\x00" + frame[22:]):
            with self.assertRaises(ValueError):
                CAPTURE.decode_frame(invalid)
        arp = (bytes(12) + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
               + bytes(6) + socket.inet_aton("10.241.90.1") + bytes(6)
               + socket.inet_aton("10.241.90.2"))
        self.assertIsNone(CAPTURE.decode_frame(arp))
        with self.assertRaises(ValueError):
            CAPTURE.decode_frame(arp[:-4] + socket.inet_aton("203.0.113.1"))

    def test_signal_stops_all_intake_before_fair_full_drain_and_exact_statistics(self):
        record, order = buffered_capture()
        self.assertTrue(record["complete"])
        self.assertEqual(order[128], "physical1")
        self.assertEqual(record["observed_frames"], 301)
        self.assertEqual(record["client_leg_wireguard_data_datagrams"], 301)
        self.assertEqual(record["packet_socket_drops"], 0)
        self.assertTrue(all(row["drained"] and row["intake_stopped"]
                            for row in record["interface_statistics"].values()))
        for extra, drops in ((1, 0), (0, 1)):
            record, _ = buffered_capture(extra=extra, drops=drops)
            self.assertFalse(record["complete"])

    def test_fixed_diagnostics_do_not_change_classification_or_record_packet_details(self):
        for version, protocol, label in ((4, socket.IPPROTO_TCP, "tcp"),
                                         (4, socket.IPPROTO_UDP, "udp"),
                                         (4, socket.IPPROTO_ICMP, "icmp"),
                                         (6, socket.IPPROTO_ICMPV6, "icmpv6"),
                                         (4, 253, "other_ip")):
            source, destination = (("203.0.113.1", "203.0.113.2") if version == 4
                                   else ("fe80::1", "fe80::2"))
            packet = (version, protocol, source, 54321, destination, 54322, b"private payload")
            decision = CAPTURE.classify(layout(), "exit", *packet[1:], "physical0")
            self.assertEqual(decision, {"forbidden_packets": 1})
            diagnostics = CAPTURE.diagnostic_updates(packet, decision)
            expected = {f"classified_{label}_packets": 1, f"forbidden_{label}_packets": 1,
                        f"forbidden_ipv{version}_unmatched_packets": 1}
            if protocol == socket.IPPROTO_UDP:
                expected["forbidden_udp_outside_fixture_packets"] = 1
            elif protocol == socket.IPPROTO_ICMP:
                expected.update(forbidden_icmp_other_packets=1, forbidden_icmp_unparsed_quote_packets=1)
            self.assertEqual(diagnostics, expected)
            self.assertTrue(set(diagnostics).issubset(CAPTURE.DIAGNOSTIC_COUNTERS))
            self.assertEqual(decision, {"forbidden_packets": 1})
        self.assertEqual(CAPTURE.diagnostic_updates(None, {"neighbor_packets": 1}),
                         {"classified_arp_packets": 1})

    def test_fixed_icmp_quote_diagnostics_never_admit_unreachable_or_persist_tuple(self):
        current = layout()
        for kind, code, label in ((3, 3, "port_unreachable"), (3, 4, "fragmentation_needed"),
                                  (3, 1, "destination_unreachable"), (11, 0, "time_exceeded")):
            udp = struct.pack("!HHHH", 41000, 45678, 1234, 0)
            quoted_ip = ipv4_frame("46.162.3.1", "48.164.4.1", socket.IPPROTO_UDP, udp)[14:]
            packet = (4, socket.IPPROTO_ICMP, "48.164.4.1", 0, "46.162.3.1", 0,
                      bytes((kind, code)) + bytes(6) + quoted_ip)
            decision = CAPTURE.classify(current, "exit", *packet[1:], "xr3")
            self.assertEqual(decision, {"forbidden_packets": 1})
            diagnostics = CAPTURE.diagnostic_updates(packet, decision)
            self.assertEqual(diagnostics[f"forbidden_icmp_{label}_packets"], 1)
            self.assertEqual(diagnostics["forbidden_icmp_quoted_udp_control_port_packets"], 1)
            self.assertTrue(set(diagnostics).issubset(CAPTURE.DIAGNOSTIC_COUNTERS))
            for value in ("46.162.3.1", "48.164.4.1", "41000", "45678"):
                self.assertNotIn(value, json.dumps(diagnostics))

    def test_capture_attributes_forbidden_protocol_and_interface_without_changing_totals(self):
        marker = b"do-not-record-this-payload"
        frames = [[udp_frame("49.165.5.1", "42.158.0.1", struct.pack("<I", 4) + bytes(44)),
                   ipv4_frame("46.162.3.1", "42.158.0.1", socket.IPPROTO_ICMP, b"\x03\x03" + bytes(6)),
                   udp_frame("49.165.5.1", "203.0.113.1", marker)],
                  [b"short", udp_frame("49.165.5.1", "46.162.3.1", marker),
                   udp_frame("49.165.5.1", "50.166.6.1", marker)]]
        record, _order = buffered_capture(frames=frames)
        self.assertTrue(record["complete"])
        expected = {"observed_frames": 6, "ipv4_frames": 5, "packet_socket_drops": 0,
                    "client_leg_wireguard_data_datagrams": 1, "forbidden_packets": 5,
                    "direct_client_exit_packets": 1, "direct_provider_packets": 1,
                    "malformed_packets": 1, "classified_udp_packets": 4,
                    "classified_icmp_packets": 1, "forbidden_udp_packets": 3,
                    "forbidden_icmp_packets": 1, "forbidden_unparsed_packets": 1,
                    "forbidden_ipv4_unmatched_packets": 2}
        for counter, value in expected.items():
            self.assertEqual(record[counter], value, counter)
        self.assertEqual([row["forbidden_packets"] for row in record["interface_statistics"].values()],
                         [2, 3])
        self.assertEqual(sum(row["forbidden_packets"] for row in record["interface_statistics"].values()),
                         record["forbidden_packets"])
        self.assertEqual(record["interface_statistics"]["physical0"]["forbidden_icmp_port_unreachable_packets"], 1)
        self.assertEqual(record["interface_statistics"]["physical1"]["forbidden_icmp_port_unreachable_packets"], 0)
        for counter in CAPTURE.DIAGNOSTIC_COUNTERS:
            self.assertEqual(sum(row[counter] for row in record["interface_statistics"].values()), record[counter])
        serialized = json.dumps(record)
        for detail in (marker.decode(), "49.165.5.1", "46.162.3.1", "203.0.113.1", "22000", "23000"):
            self.assertNotIn(detail, serialized)


def buffered_capture(extra=0, drops=0, frames=None, max_seconds=CAPTURE.MAX_SECONDS):
    """Exercise the actual collector with finite mock socket queues and a real temporary report."""
    handlers, order = {}, []
    packet = udp_frame("49.165.5.1", "42.158.0.1", struct.pack("<I", 4) + bytes(44))

    class Observer:
        def __init__(self, interface, queued_frames):
            self.interface, self.total, self.remaining = interface, len(queued_frames), len(queued_frames)
            self.frames = queued_frames
            self.stopped = False

        def setsockopt(self, level, option, value):
            if option == 26:
                length, pointer = struct.unpack("@HP", value)
                assert length == 1 and ctypes.string_at(pointer, 8) == struct.pack("HBBI", 6, 0, 0, 0)
                self.stopped = True
            else:
                assert (level, option, value) == (socket.SOL_SOCKET, 33, 4 * 1024 * 1024)

        def getsockopt(self, level, option, length=None):
            if length is None:
                return 8 * 1024 * 1024
            assert self.stopped and (level, option, length) == (263, 6, 8)
            return struct.pack("II", self.total + extra + drops, drops)

        def bind(self, address):
            assert address == (self.interface, 3)

        def setblocking(self, enabled):
            assert enabled is False

        def recvmsg(self, maximum):
            assert maximum == CAPTURE.MAX_FRAME_BYTES
            if self.remaining == 0:
                raise BlockingIOError
            self.remaining -= 1
            order.append(self.interface)
            return self.frames[self.total - self.remaining - 1], [], 0, None

        def close(self):
            pass

    frame_queues = [[packet] * 300, [packet]] if frames is None else frames
    observers = [Observer(f"physical{index}", queued) for index, queued in enumerate(frame_queues)]

    def select_ready(*_args):
        handlers[signal.SIGTERM]()
        return [observer for observer in observers if observer.remaining], [], []

    # Import here solely to keep the mock signal handler explicit beside its use.
    import signal
    with tempfile.TemporaryDirectory(prefix="volparossa-replication-capture-") as temporary:
        output, ready = Path(temporary) / "capture.json", Path(temporary) / "ready"
        with patch.object(CAPTURE.socket, "socket", side_effect=observers), \
                patch.object(CAPTURE.signal, "signal", side_effect=handlers.__setitem__), \
                patch.object(CAPTURE.select, "select", side_effect=select_ready):
            try:
                CAPTURE.capture(layout(), output, ready, "relay4", [observer.interface for observer in observers], max_seconds)
            except ValueError:
                if not (extra or drops):
                    raise
        return json.loads(output.read_text()), order


if __name__ == "__main__":
    unittest.main()
