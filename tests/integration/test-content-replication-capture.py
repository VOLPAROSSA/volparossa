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
             sport=22000, dport=23000, payload=struct.pack("<I", 4) + bytes(44)):
    return CAPTURE.classify(current, role, protocol, source, sport, destination,
                            dport, payload, "physical0")


def udp_frame(source, destination, payload):
    transport = struct.pack("!HHHH", 22000, 23000, len(payload) + 8, 0) + payload
    header = bytearray(20)
    header[0], header[9] = 0x45, socket.IPPROTO_UDP
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
            for port in (41000, 22000):
                self.assertEqual(classify(current, "exit", client, exit_ip, dport=port)[
                    "direct_client_exit_packets"], 1)
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
        self.assertEqual(classify(current, "relay4", "10.241.90.1", "224.0.0.251", sport=5353, dport=5353),
                         {"mdns_packets": 1, "control_packets": 1})
        self.assertEqual(classify(current, "relay4", "fe80::1", "ff02::fb", sport=5353, dport=5353),
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


def buffered_capture(extra=0, drops=0):
    """Exercise the actual collector with finite mock socket queues and a real temporary report."""
    handlers, order = {}, []
    packet = udp_frame("49.165.5.1", "42.158.0.1", struct.pack("<I", 4) + bytes(44))

    class Observer:
        def __init__(self, interface, total):
            self.interface, self.total, self.remaining = interface, total, total
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
            return packet, [], 0, None

        def close(self):
            pass

    observers = [Observer("physical0", 300), Observer("physical1", 1)]

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
