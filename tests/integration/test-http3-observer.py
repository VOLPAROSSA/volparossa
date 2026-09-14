#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure checks of the generated HTTP/3 observer's actual finite frame guard."""

import ast
from pathlib import Path
import unittest


HERE = Path(__file__).parent
SOURCE = (HERE / "kvm-alpha-topology.sh").read_text(encoding="utf-8")
OBSERVER = SOURCE.split('cat >"$WORK/bin/a06-observer.py" <<\'PYTHON\'\n', 1)[1].split(
    "\nPYTHON\n", 1
)[0]
TREE = ast.parse(OBSERVER)
CONSTANTS = ast.Module(
    body=[node for node in TREE.body if isinstance(node, ast.Assign)
          and isinstance(node.targets[0], ast.Name)
          and node.targets[0].id.startswith("MAX_HTTP3_")],
    type_ignores=[],
)
assert len(CONSTANTS.body) == 2
GUARDS = [node for node in ast.walk(TREE) if isinstance(node, ast.If)
          and isinstance(node.test, ast.Compare)
          and isinstance(node.test.left, ast.Name)
          and node.test.left.id == "observed_frames"]
assert len(GUARDS) == 1
# Execute the production increment/guard inside one iteration, preserving its
# real break semantics without opening sockets or iterating half a million times.
INCREMENTS = [node for node in ast.walk(TREE) if isinstance(node, ast.AugAssign)
              and isinstance(node.target, ast.Name)
              and node.target.id == "observed_frames"]
assert len(INCREMENTS) == 1
ITERATION = ast.parse("for _ in range(1): pass")
ITERATION.body[0].body = [INCREMENTS[0], GUARDS[0]]


def record_frame(previous):
    namespace = {"observed_frames": previous, "running": True, "truncated": False}
    exec(compile(CONSTANTS, "a06-observer.py", "exec"), namespace)
    exec(compile(ITERATION, "a06-observer.py", "exec"), namespace)
    return namespace


class Http3ObserverBoundTests(unittest.TestCase):
    def test_largest_declared_response_scales_the_original_frame_allowance(self):
        result = record_frame(131072)
        fixture = (HERE.parents[1] / "crates/volparossa-test-support/examples/"
                   "http3-acceptance-fixture.rs").read_text(encoding="utf-8")
        self.assertIn("const A07_RESPONSE_BYTES: usize = 32 * 1024 * 1024;", fixture)
        self.assertEqual(result["MAX_HTTP3_RESPONSE_BYTES"], 33554432)
        self.assertEqual(result["MAX_HTTP3_CAPTURE_FRAMES"], 524288)
        self.assertEqual(result["observed_frames"], 131073)
        self.assertTrue(result["running"])
        self.assertFalse(result["truncated"])

    def test_exact_frame_limit_remains_complete(self):
        result = record_frame(524287)
        self.assertEqual(result["observed_frames"], 524288)
        self.assertTrue(result["running"])
        self.assertFalse(result["truncated"])

    def test_first_excess_frame_stops_and_reports_incomplete_capture(self):
        result = record_frame(524288)
        self.assertEqual(result["observed_frames"], 524289)
        self.assertFalse(result["running"])
        self.assertTrue(result["truncated"])


if __name__ == "__main__":
    unittest.main()
