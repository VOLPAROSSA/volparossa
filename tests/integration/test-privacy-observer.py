#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure checks of the generated privacy observer; no network sockets or mutations."""

import ast
import errno
from pathlib import Path
from types import SimpleNamespace
import unittest


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


class PrivacyObserverTests(unittest.TestCase):
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
