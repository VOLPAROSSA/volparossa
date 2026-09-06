#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure checks of the generated privacy observer; no network sockets or mutations."""

import ast
import errno
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
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
        "os": SimpleNamespace(path=SimpleNamespace(exists=lambda _: marker)),
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


def buffered_observer(extra_unread_packet=False, clock=None):
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
            return b"counted non-IPv4 frame"

        def close(self):
            pass

    captures = [BufferedCapture("r1c", 300), BufferedCapture("r1x", 1)]
    namespace = {}

    def ready(_read, _write, _exception, _timeout):
        # SIGTERM arrives with more than a fair batch already queued on the first interface.
        namespace["running"] = False
        return [capture for capture in captures if capture.remaining], [], []

    with tempfile.TemporaryDirectory(prefix="volparossa-privacy-drain-") as directory:
        output = Path(directory) / "capture.json"
        args = ["privacy-observer.py", "relay1", str(output), str(Path(directory) / "ready"),
                "r1c", "r1x"]
        with (
            patch("sys.argv", args), patch("socket.socket", side_effect=captures),
            patch("signal.signal"), patch("select.select", side_effect=ready),
            patch("time.monotonic", side_effect=clock, return_value=1),
        ):
            exec(compile(OBSERVER, "privacy-observer.py", "exec"), namespace)
        return json.loads(output.read_text()), order


class PrivacyObserverTests(unittest.TestCase):
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

    def test_unread_tail_or_expired_drain_cannot_report_complete_capture(self):
        for arguments in ({"extra_unread_packet": True}, {"clock": [0, 1, 1.1, 3.2]}):
            with self.subTest(arguments=arguments):
                record, _ = buffered_observer(**arguments)
                self.assertTrue(record["truncated"])

    def test_actual_a11_a12_a13_predicates_require_complete_drop_evidence(self):
        for acceptance, captures in (("A11", ("relay1", "relay2")),
                                     ("A12", ("exit_capture",)),
                                     ("A13", ("client_capture",))):
            section = SOURCE.rsplit(f"\n{acceptance}_STATUS=1\n", 1)[1]
            expression = section.split("    '", 1)[1].split("' >\"$WORK/", 1)[0]
            values = {}
            for name in captures:
                values[name] = [{
                    "capture_role": name.removesuffix("_capture"),
                    "truncated": False, "packet_socket_drops": 0,
                    "client_leg_wireguard_data_datagrams": 1,
                    "exit_leg_wireguard_data_datagrams": 1,
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


if __name__ == "__main__":
    unittest.main()
