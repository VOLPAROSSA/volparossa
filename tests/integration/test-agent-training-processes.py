#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual Linux thread-owned child discovery; no model, namespace or network changes."""

import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys
import unittest

TRAIN = runpy.run_path(str(Path(__file__).with_name("agent-training-smoke.py")))
PARENT = r'''
import json, os, subprocess, sys, threading
stop = threading.Event()
def spawn():
    child = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read(1)"],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        print(json.dumps({"parent": os.getpid(), "thread": threading.get_native_id(), "child": child.pid}), flush=True)
        stop.wait(10)
    finally:
        try:
            child.communicate(b"x", timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
thread = threading.Thread(target=spawn)
thread.start()
try:
    sys.stdin.buffer.read(1)
finally:
    stop.set()
    thread.join(timeout=5)
    if thread.is_alive():
        raise RuntimeError("owned spawning thread did not stop")
'''


class ThreadOwnedChildTests(unittest.TestCase):
    def test_nonleader_child_is_found_once_with_exact_owned_subtree(self):
        parent = subprocess.Popen([sys.executable, "-I", "-c", PARENT], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        observed = None
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0], "spawning thread did not report")
            message = json.loads(parent.stdout.readline())
            self.assertEqual(message["parent"], parent.pid)
            self.assertNotEqual(message["thread"], parent.pid)
            leader = Path(f"/proc/{parent.pid}/task/{parent.pid}/children").read_text().split()
            spawning = Path(f"/proc/{parent.pid}/task/{message['thread']}/children").read_text().split()
            self.assertNotIn(str(message["child"]), leader)
            self.assertIn(str(message["child"]), spawning)
            observed = TRAIN["descendants"](parent.pid)
            self.assertEqual({item["pid"] for item in observed}, {parent.pid, message["child"]})
            self.assertEqual(len(observed), 2)
            self.assertEqual(len({(item["pid"], item["start_ticks"]) for item in observed}), 2)
            self.assertNotIn(os.getpid(), {item["pid"] for item in observed})
            self.assertTrue(all(TRAIN["identity"](item["pid"]) == item for item in observed))
        finally:
            try:
                _, errors = parent.communicate(b"x", timeout=8)
            except subprocess.TimeoutExpired:
                parent.kill()
                _, errors = parent.communicate(timeout=3)
            self.assertEqual(parent.returncode, 0, errors.decode(errors="replace"))
        self.assertIsNotNone(observed)
        self.assertTrue(all(not TRAIN["alive"](item) for item in observed), "owned fixture child was not reaped")


if __name__ == "__main__":
    unittest.main()
