#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert fixed-interface ARP/mDNS and redacted capture-diagnostic regressions."""

import importlib.util
import json
from pathlib import Path
import socket
import struct
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("private_dns_capture_test", HERE / "reciprocity-private-dns-capture.py")
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def arp(source="10.242.93.100", destination="10.242.93.2", operation=1):
    sender = bytes.fromhex("020000000001")
    target = bytes.fromhex("020000000002") if operation == 2 else bytes(6)
    ethernet = (target if operation == 2 else b"\xff" * 6) + sender + b"\x08\x06"
    return ethernet + struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation) + sender \
        + socket.inet_aton(source) + target + socket.inet_aton(destination)


def slirp_reply():
    # Exact arp_input output shape in the pinned Debian libslirp source, not
    # reconstructed bytes from the historical capture (which did not retain them).
    frame = bytearray(arp(CAPTURE.TAP_GATEWAY, CAPTURE.TAP_ADDRESS, 2))
    frame[6:12] = frame[22:28] = b"\x52\x55" + socket.inet_aton(CAPTURE.TAP_GATEWAY)
    return bytes(frame) + bytes(22)


class PrivateDnsCaptureTests(unittest.TestCase):
    def test_exact_libslirp_64_byte_reply_is_accepted_only_on_owned_tap(self):
        frame = slirp_reply()
        self.assertEqual(len(frame), 64)
        self.assertIsNone(CAPTURE.decode_frame_on_interface(frame, "dnsup0"))
        for interface in ("xd", "underlay", "dnsup1", None):
            with self.subTest(interface=interface), self.assertRaises(ValueError):
                CAPTURE.decode_frame_on_interface(frame, interface)
        wrong_target = bytearray(frame)
        wrong_target[0] ^= 2
        broadcast_target = bytearray(frame)
        broadcast_target[:6] = broadcast_target[32:38] = b"\xff" * 6
        wrong_operation = bytearray(frame)
        wrong_operation[21] = 1
        for invalid in (frame[:-1], frame + b"\x00", frame[:-1] + b"\x01",
                        bytes(wrong_target), bytes(broadcast_target), bytes(wrong_operation),
                        arp(CAPTURE.TAP_GATEWAY, CAPTURE.TAP_ADDRESS, 2) + bytes(22),
                        arp(CAPTURE.TAP_ADDRESS, CAPTURE.TAP_GATEWAY, 2) + bytes(22)):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                CAPTURE.decode_frame_on_interface(invalid, "dnsup0")

    def test_arp_shape_diagnostics_separate_lengths_padding_and_fixed_fields(self):
        frame = slirp_reply()
        for invalid, length_class, failure in (
            (frame[:41], "shorter_than_42", "short_header"),
            (frame[:63], "between_61_and_63", "unexpected_length"),
            (frame + b"\x00", "longer_than_64", "unexpected_length"),
            (frame[:-1] + b"\x01", "slirp_64", "nonzero_padding"),
            (frame[:18] + b"\x08" + frame[19:], "slirp_64", "hardware_protocol_lengths"),
            (frame[:21] + b"\x03" + frame[22:], "slirp_64", "operation"),
        ):
            with self.subTest(failure=failure):
                sample = CAPTURE.fixture_header_sample(None, "dnsup0", invalid)
                self.assertEqual(sample["reason"], "tap_arp_shape")
                self.assertEqual(sample["arp_frame_length_class"], length_class)
                self.assertEqual(sample["arp_shape_failure"], failure)
                self.assertNotIn(CAPTURE.TAP_GATEWAY, json.dumps(sample))
                self.assertNotIn(CAPTURE.TAP_ADDRESS, json.dumps(sample))
                with self.assertRaises(ValueError):
                    CAPTURE.decode_frame_on_interface(invalid, "dnsup0")

    def test_exact_tap_arp_requires_its_physical_interface_and_keeps_ip_parser_strict(self):
        for source, destination in ((CAPTURE.TAP_ADDRESS, CAPTURE.TAP_GATEWAY),
                                    (CAPTURE.TAP_GATEWAY, CAPTURE.TAP_ADDRESS)):
            for operation in (1, 2):
                frame = arp(source, destination, operation)
                for padding in (b"", bytes(18)):
                    with self.subTest(source=source, operation=operation, padding=len(padding)):
                        self.assertIsNone(CAPTURE.ENGINE.decode_frame_on_interface(frame + padding, "dnsup0"))
                # Demonstrates the original decoder's concrete omission, not the identity of
                # historical frames whose failure artifacts retained no EtherType.
                with self.assertRaisesRegex(ValueError, "ARP endpoint outside"):
                    CAPTURE.ENGINE.decode_frame(frame)
                for interface in ("xd", "underlay", "xr2", "dnsup1", None):
                    with self.assertRaises(ValueError):
                        CAPTURE.decode_frame_on_interface(frame, interface)
        original = arp("10.241.31.1", "10.241.31.2")
        self.assertIsNone(CAPTURE.ENGINE.decode_frame_on_interface(original, "xd"))
        with self.assertRaises(ValueError):
            CAPTURE.ENGINE.decode_frame_on_interface(original, "dnsup0")

    def test_malformed_tap_arp_and_any_other_addresses_stay_forbidden(self):
        valid = arp()
        bad_mac = bytearray(valid)
        bad_mac[22] ^= 2
        multicast_mac = bytearray(valid)
        multicast_mac[6] |= 1
        multicast_mac[22] |= 1
        bad_shape = bytearray(valid)
        bad_shape[18] = 8
        for frame in (valid[:41], valid + bytes(19), valid + b"\x01", bytes(bad_mac),
                      bytes(multicast_mac), bytes(bad_shape), arp(operation=3),
                      arp(destination="10.242.93.3"), arp(source="10.241.93.100"),
                      arp(source="0.0.0.0"), arp(source=CAPTURE.TAP_GATEWAY,
                                               destination=CAPTURE.TAP_GATEWAY)):
            with self.subTest(length=len(frame)), self.assertRaises(ValueError):
                CAPTURE.decode_frame_on_interface(frame, "dnsup0")

    def test_existing_exit_aliases_are_retained_without_allowing_tap_on_other_interfaces(self):
        layout = dict(phase="local", exit_node="exit", relays={"relay2": "45.161.2.1"}, run_id="a" * 32)
        def classify(source, interface):
            return CAPTURE.classify(layout, "exit", socket.IPPROTO_UDP, source, 45000,
                                    "224.0.0.251", 5353, b"synthetic", interface)
        for address in ("10.241.31.1", "10.241.31.2", "47.163.4.1", "47.163.4.2"):
            self.assertEqual(classify(address, "xd"), {"mdns_packets": 1})
            self.assertEqual(classify(address, "dnsup0"), {"forbidden_packets": 1})
        self.assertEqual(classify(CAPTURE.TAP_ADDRESS, "xd"), {"forbidden_packets": 1})
        self.assertEqual(classify("203.0.113.123", "xd"), {"forbidden_packets": 1})
        self.assertEqual(classify("47.163.4.1", "xr2"), {"forbidden_packets": 1})

    def test_failure_headers_expose_fixed_classes_not_raw_addresses_or_body(self):
        foreign = arp(source="203.0.113.123")
        sample = CAPTURE.fixture_header_sample(None, "dnsup0", foreign)
        self.assertEqual(sample, dict(interface="dnsup0", parse="unavailable", ethernet_kind="arp",
            reason="tap_arp_endpoints", arp_operation="request", source="outside_fixed_fixture",
            destination="private_dns.gateway", arp_frame_length_class="arp_42", arp_shape_failure="none"))
        self.assertNotIn("203.0.113.123", json.dumps(sample))
        sample = CAPTURE.fixture_header_sample(None, "xd", arp())
        self.assertEqual(sample["reason"], "arp_endpoints")
        self.assertEqual(sample["source"], "private_dns.tap")
        short = CAPTURE.fixture_header_sample(None, "dnsup0", b"private")
        self.assertEqual(short, dict(interface="dnsup0", parse="unavailable", ethernet_kind="short",
                                    reason="ethernet_short"))
        packet = (4, socket.IPPROTO_UDP, "47.163.4.1", 45000, "224.0.0.251", 5353, b"PRIVATE_BODY")
        known = CAPTURE.fixture_header_sample(packet, "xd", b"unused")
        self.assertEqual(known["source"], "exit.xd.alias")
        self.assertNotIn("PRIVATE_BODY", json.dumps(known))
        # Diagnostic aggregation never changes the original fail-closed verdict.
        self.assertEqual(CAPTURE.ENGINE.diagnostic_updates(None, {"forbidden_packets": 1}),
                         {"forbidden_unparsed_packets": 1})


if __name__ == "__main__":
    unittest.main()
