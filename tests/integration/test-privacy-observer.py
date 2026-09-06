#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure collector checks plus an opt-in AF_PACKET stop proof in a disposable namespace."""

import ast
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name("kvm-alpha-topology.sh").read_text(encoding="utf-8")
OBSERVER = SOURCE.split('cat >"$WORK/bin/privacy-observer.py" <<\'PYTHON\'\n', 1)[1].split(
    "\nPYTHON\n", 1
)[0]
TREE = ast.parse(OBSERVER)
FUNCTIONS = ast.Module(
    body=[
        node for node in TREE.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"receive_frame", "record_unexpected_outer_tuple"}
    ],
    type_ignores=[],
)
assert len(FUNCTIONS.body) == 2


def environment(role="relay1", marker=True):
    pauses = []
    namespace = {
        "errno": errno, "role": role, "expected_down_marker": "fixture-marker",
        "output_path": "capture.json",
        "os": SimpleNamespace(path=SimpleNamespace(exists=lambda _: marker,
            basename=os.path.basename, dirname=os.path.dirname, join=os.path.join)),
        "time": SimpleNamespace(sleep=pauses.append),
        "counters": {"expected_link_down_notifications": 0,
                     "unexpected_outer_tuple_overflow_packets": 0},
        "link_down_interfaces": {}, "unexpected_outer_tuples": {},
    }
    exec(compile(FUNCTIONS, "privacy-observer.py", "exec"), namespace)
    return namespace, pauses


class Capture:
    def __init__(self, *results):
        self.results = iter(results)

    def recv(self, maximum):
        assert maximum == 65535
        result = next(self.results)
        if isinstance(result, Exception):
            raise result
        return result


def buffered_observer(extra_unread_packet=False, clock=None, idle=False,
                      role="relay1", frames=None):
    """Execute the complete generated collector with actual queue semantics, not packet parsing."""
    order = []

    class BufferedCapture:
        def __init__(self, interface, packets):
            self.interface, self.packets, self.remaining = interface, packets, packets

        def bind(self, address):
            assert address == (self.interface, 3)

        def setblocking(self, enabled):
            assert enabled is False

        def setsockopt(self, level, option, size):
            if option == 26:
                self_assertion = struct.unpack("@HP", size)
                assert level == socket.SOL_SOCKET and self_assertion[0] == 1
                assert ctypes.string_at(self_assertion[1], 8) == struct.pack("HBBI", 6, 0, 0, 0)
                assert namespace["running"] is False
                return
            assert (level, option, size) == (socket.SOL_SOCKET, 33, 4 * 1024 * 1024)

        def getsockopt(self, level, option, size=None):
            if size is None:
                assert (level, option) == (socket.SOL_SOCKET, socket.SO_RCVBUF)
                return 8 * 1024 * 1024
            assert (level, option, size) == (263, 6, 8)
            return struct.pack("II", self.packets + int(extra_unread_packet), 0)

        def recv(self, maximum):
            assert maximum == 65535
            if not self.remaining:
                raise BlockingIOError
            self.remaining -= 1
            order.append(self.interface)
            if frames is not None:
                return frames[self.interface][self.remaining]
            return b"counted non-IPv4 frame"

        def close(self):
            pass

    captures = ([BufferedCapture(interface, len(packets)) for interface, packets in frames.items()]
                if frames is not None else [BufferedCapture("r1c", 0 if idle else 300),
                                           BufferedCapture("r1x", 0 if idle else 1)])
    namespace = {}

    def ready(_read, _write, _exception, _timeout):
        # SIGTERM arrives with more than a fair batch already queued on the first interface.
        namespace["running"] = False
        return [capture for capture in captures if capture.remaining], [], []

    with tempfile.TemporaryDirectory(prefix="volparossa-privacy-drain-") as directory:
        output = Path(directory) / "capture.json"
        args = ["privacy-observer.py", role, str(output), str(Path(directory) / "ready"),
                *(capture.interface for capture in captures)]
        with (
            patch("sys.argv", args), patch("socket.socket", side_effect=captures),
            patch("signal.signal"), patch("select.select", side_effect=ready),
            patch("time.monotonic", side_effect=clock, return_value=1),
        ):
            exec(compile(OBSERVER, "privacy-observer.py", "exec"), namespace)
        return json.loads(output.read_text()), order


class PrivacyObserverTests(unittest.TestCase):
    def test_actual_relay0_collector_observes_both_wg_legs_and_forbidden_destination(self):
        def frame(source, destination):
            ipv4 = bytearray(20)
            ipv4[0] = 0x45
            ipv4[9] = socket.IPPROTO_UDP
            ipv4[12:16] = socket.inet_aton(source)
            ipv4[16:20] = socket.inet_aton(destination)
            return (b"\0" * 12 + b"\x08\x00" + ipv4
                    + struct.pack("!HHHH", 20000, 30000, 44, 0)
                    + struct.pack("<I", 4) + b"\0" * 32)

        frames = {"r0c": [frame("43.159.1.1", "42.158.0.1")],
                  "r0x": [frame("42.158.0.1", "46.162.3.1")]}
        record, _ = buffered_observer(role="relay0", frames=frames)
        self.assertEqual(record["client_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(record["exit_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(record["unexpected_outer_packets"], 0)
        self.assertEqual(record["packet_socket_drops"], 0)
        self.assertFalse(record["truncated"])
        frames["r0x"].append(frame("42.158.0.1", "47.163.4.2"))
        record, _ = buffered_observer(role="relay0", frames=frames)
        self.assertEqual(record["internet_destination_outer_packets"], 1)
        self.assertEqual(record["unexpected_outer_packets"], 1)

    def test_idle_signal_during_select_still_stops_intake_before_final_stats(self):
        record, order = buffered_observer(idle=True)
        self.assertFalse(order)
        self.assertFalse(record["truncated"])
        self.assertTrue(all(row["intake_stopped"]
                            for row in record["interface_statistics"].values()))

    def test_fair_drain_keeps_other_link_responsive_and_drains_after_stop(self):
        record, order = buffered_observer()
        self.assertEqual(order[128], "r1x")
        self.assertEqual(record["observed_frames"], 301)
        self.assertFalse(record["truncated"])
        self.assertEqual(record["packet_socket_drops"], 0)
        for interface in ("r1c", "r1x"):
            statistics = record["interface_statistics"][interface]
            self.assertEqual(statistics["receive_buffer_bytes"], 8 * 1024 * 1024)
            self.assertEqual(statistics["packet_socket_packets"], statistics["observed_frames"])
            self.assertTrue(statistics["intake_stopped"])

    def test_unread_tail_or_expired_drain_cannot_report_complete_capture(self):
        for arguments in ({"extra_unread_packet": True}, {"clock": [0, 1, 1.1, 3.2]}):
            with self.subTest(arguments=arguments):
                record, _ = buffered_observer(**arguments)
                self.assertTrue(record["truncated"])

    def test_actual_a11_a12_a13_predicates_require_complete_drop_evidence(self):
        for acceptance, captures in (("A11", ("relay0", "relay1", "relay2")),
                                     ("A12", ("exit_capture",)),
                                     ("A13", ("client_capture",))):
            section = SOURCE.rsplit(f"\n{acceptance}_STATUS=1\n", 1)[1]
            expression = section.split("    '", 1)[1].split("' >\"$WORK/", 1)[0]
            values = {"mptcp": [{"success": True}], "selected": [{"benchmark_slots": [
                {"relay_node": "relay0", "relay_index": 0},
                {"relay_node": "relay2", "relay_index": 2}]}]}
            for name in captures:
                values[name] = [{
                    "capture_role": name.removesuffix("_capture"),
                    "truncated": False, "packet_socket_drops": 0,
                    "client_leg_wireguard_data_datagrams": 1,
                    "exit_leg_wireguard_data_datagrams": 1,
                    "relay0_wireguard_data_datagrams": 1,
                    "relay1_wireguard_data_datagrams": 1,
                    "relay2_wireguard_data_datagrams": 1,
                    "internet_destination_outer_packets": 0,
                    "unexpected_outer_packets": 0, "client_public_packets": 0,
                    "outbound_client_discovery_attempt_packets": 0,
                    "direct_client_exit_packets": 0,
                }]

            def evaluate():
                command = ["jq", "-c", "-n"]
                for name, value in values.items():
                    command.extend(("--argjson", name, json.dumps(value)))
                if acceptance == "A13":
                    for name in ("routes_before", "routes_after"):
                        command.extend(("--argjson", name, "[[]]"))
                    for name in ("exit_route_before", "exit_route_after",
                                 "destination_route_before", "destination_route_after"):
                        command.extend(("--arg", name, "47.163.4.2 dev underlay"))
                command.append(expression)
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                return json.loads(result.stdout)["success"]

            self.assertTrue(evaluate(), acceptance)
            for invalid in ({}, {"success": False}, {"success": None}):
                values["mptcp"] = [invalid]
                self.assertFalse(evaluate(), (acceptance, invalid))
            values["mptcp"] = [{"success": True}]
            for name in captures:
                for missing, value in ((False, 1), (False, None), (True, None)):
                    record = values[name][0]
                    if missing:
                        record.pop("packet_socket_drops")
                    else:
                        record["packet_socket_drops"] = value
                    with self.subTest(acceptance=acceptance, capture=name,
                                      missing=missing, drops=value):
                        self.assertFalse(evaluate())
                    record["packet_socket_drops"] = 0

    def test_expected_down_is_reported_and_same_capture_resumes(self):
        observer, pauses = environment()
        capture = Capture(OSError(errno.ENETDOWN, "link down"), b"restored frame")
        self.assertIsNone(observer["receive_frame"](capture, "r1c"))
        self.assertEqual(observer["receive_frame"](capture, "r1c"), b"restored frame")
        self.assertEqual(pauses, [0.05])
        self.assertEqual(observer["counters"]["expected_link_down_notifications"], 1)
        self.assertEqual(observer["link_down_interfaces"], {"r1c": 1})

    def test_unexpected_socket_errors_are_not_treated_as_packet_absence(self):
        for role, interface, marker, code in [
            ("relay2", "r2c", True, errno.ENETDOWN),
            ("relay1", "underlay", True, errno.ENETDOWN),
            ("relay1", "r1x", False, errno.ENETDOWN),
            ("relay1", "r1x", True, errno.EIO),
        ]:
            observer, pauses = environment(role, marker)
            with self.assertRaises(OSError):
                observer["receive_frame"](Capture(OSError(code, "failed")), interface)
            self.assertFalse(pauses)
            self.assertEqual(observer["counters"]["expected_link_down_notifications"], 0)

    def test_benchmark_downtime_is_exact_role_interface_and_window(self):
        for prefix in ("mptcp-privacy", "privacy"):
            for index in range(3):
                observer, _ = environment(f"relay{index}")
                observer["output_path"] = f"{prefix}-relay{index}.json"
                for suffix in ("c", "x"):
                    self.assertIsNone(observer["receive_frame"](
                        Capture(OSError(errno.ENETDOWN, "planned")), f"r{index}{suffix}"))
                for unexpected in ("underlay", f"r{(index + 1) % 3}c"):
                    with self.assertRaises(OSError):
                        observer["receive_frame"](
                            Capture(OSError(errno.ENETDOWN, "unplanned")), unexpected)

    def test_nonblocking_empty_socket_is_not_a_link_down(self):
        observer, pauses = environment()
        self.assertIsNone(observer["receive_frame"](Capture(BlockingIOError()), "r1c"))
        self.assertFalse(pauses)
        self.assertFalse(observer["link_down_interfaces"])

    def test_unexpected_tuples_are_bounded_and_overflow_remains_counted(self):
        observer, _ = environment()
        record = observer["record_unexpected_outer_tuple"]
        for port in range(33):
            record("underlay", 17, "192.0.2.1", port, "198.51.100.1", 41000)
        record("underlay", 17, "192.0.2.1", 0, "198.51.100.1", 41000)
        tuples = observer["unexpected_outer_tuples"]
        self.assertEqual(len(tuples), 32)
        self.assertEqual(sum(tuples.values()), 33)
        self.assertEqual(observer["counters"]["unexpected_outer_tuple_overflow_packets"], 1)


def live_stop_intake():
    """Use the exact generated stop function, not a duplicate implementation."""
    parent = os.environ.get("VOLPAROSSA_PRIVACY_PARENT_NETNS")
    if not parent or os.readlink("/proc/self/ns/net") == parent or os.geteuid() != 0:
        raise RuntimeError("requires disposable unshare --user --map-root-user --net, never host")
    print("Disposable namespace only: create privacy0<->privacy1 veth; preserve queued frames, "
          "stop capture intake, send 400 later frames; delete the exact owned pair.", flush=True)
    stop_node = next(node for node in TREE.body
                     if isinstance(node, ast.FunctionDef) and node.name == "stop_capture_intake")
    namespace = {"ctypes": ctypes, "socket": socket}
    exec(compile(ast.Module(body=[stop_node], type_ignores=[]), "privacy-stop", "exec"), namespace)

    def ip(*args):
        subprocess.run(["ip", *args], check=True, capture_output=True)

    ip("link", "add", "privacy0", "type", "veth", "peer", "name", "privacy1")
    try:
        for interface in ("privacy0", "privacy1"):
            ip("link", "set", interface, "up")
        with (socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as capture,
              socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sender):
            capture.bind(("privacy0", 3))
            capture.setblocking(False)
            sender.bind(("privacy1", 3))
            header = bytes.fromhex("ffffffffffff02000000000188b5")
            expected = {b"zero-bind-still-open", b"before:0", b"before:1", b"before:2"}
            capture.bind(("privacy0", 0))
            assert capture.getsockname()[1] == 3, "zero bind is not a capture stop on Linux"
            sender.send(header + b"zero-bind-still-open")
            for index in range(3):
                sender.send(header + f"before:{index}".encode())
            descriptor = capture.fileno()
            namespace["stop_capture_intake"](capture)
            for _ in range(200):
                sender.send(header + b"after-stop")
            observed, frame_count = set(), 0
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    frame = capture.recv(65535)
                except BlockingIOError:
                    break
                frame_count += 1
                if frame[12:14] == b"\x88\xb5":
                    observed.add(frame[14:])
            else:
                raise AssertionError("fixed stop filter failed to quiesce capture")
            packets, drops = struct.unpack("II", capture.getsockopt(263, 6, 8))
            assert capture.fileno() == descriptor and observed == expected
            assert packets == frame_count and drops == 0
            for _ in range(200):
                sender.send(header + b"after-stats")
            assert struct.unpack("II", capture.getsockopt(263, 6, 8)) == (0, 0)
            print(json.dumps({"success": True, "same_capture_fd": True, "queued_markers": 4,
                              "post_stop_markers": 0, "packet_socket_packets": packets,
                              "observed_frames": frame_count, "packet_socket_drops": drops,
                              "later_statistics_stable": True}))
    finally:
        ip("link", "delete", "privacy0")


if __name__ == "__main__":
    if sys.argv[1:] == ["--live-stop"]:
        live_stop_intake()
    else:
        unittest.main()
