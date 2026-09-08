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


class ReplicationCaptureTests(unittest.TestCase):
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


def buffered_capture(extra=0, drops=0, frames=None):
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
                CAPTURE.capture(layout(), output, ready, "relay4", [observer.interface for observer in observers])
            except ValueError:
                if not (extra or drops):
                    raise
        return json.loads(output.read_text()), order


if __name__ == "__main__":
    unittest.main()
