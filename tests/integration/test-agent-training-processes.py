#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual Linux task/process ownership; no model, namespace or network changes."""

import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys
import unittest

TRAIN = runpy.run_path(str(Path(__file__).with_name("agent-training-smoke.py")))
BROWSER = runpy.run_path(str(Path(__file__).with_name("agent-cooperative-browser.py")))
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


PERSISTENT_PARENT = r'''
import json, os, subprocess, sys, threading
wrapper_source = r"""
import json, subprocess, sys
child = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read(1)"],
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    print(json.dumps({"worker": child.pid}), flush=True)
    sys.stdin.buffer.read(1)
    child.communicate(b"x", timeout=3)
    print(json.dumps({"worker_reaped": True}), flush=True)
    sys.stdin.buffer.read(1)
finally:
    if child.poll() is None:
        child.kill()
        child.wait(timeout=3)
"""
def spawn():
    wrapper = subprocess.Popen([sys.executable, "-I", "-c", wrapper_source], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        message = json.loads(wrapper.stdout.readline())
        print(json.dumps(dict(parent=os.getpid(), thread=threading.get_native_id(),
                              wrapper=wrapper.pid, **message)), flush=True)
        sys.stdin.buffer.read(1)
        wrapper.stdin.write(b"x")
        wrapper.stdin.flush()
        print(wrapper.stdout.readline().decode().strip(), flush=True)
        sys.stdin.buffer.read(1)
        _out, errors = wrapper.communicate(b"x", timeout=3)
        if wrapper.returncode != 0:
            raise RuntimeError("fixture wrapper failed: " + errors.decode())
        print(json.dumps({"wrapper_reaped": True}), flush=True)
        sys.stdin.buffer.read(1)
    finally:
        if wrapper.poll() is None:
            wrapper.kill()
            wrapper.wait(timeout=3)
thread = threading.Thread(target=spawn)
thread.start()
thread.join()
'''


class ThreadOwnedChildTests(unittest.TestCase):
    def test_task_cleanup_keeps_sandbox_parent_but_not_persistent_broker(self):
        parent = subprocess.Popen([sys.executable, "-I", "-c", PERSISTENT_PARENT], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        observed = None
        def receive():
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0], "fixture did not report")
            return json.loads(parent.stdout.readline())
        def advance():
            parent.stdin.write(b"x")
            parent.stdin.flush()
            return receive()
        try:
            message = receive()
            self.assertNotEqual(message["thread"], parent.pid)
            leader_children = Path(f"/proc/{parent.pid}/task/{parent.pid}/children").read_text().split()
            thread_children = Path(f"/proc/{parent.pid}/task/{message['thread']}/children").read_text().split()
            self.assertNotIn(str(message["wrapper"]), leader_children)
            self.assertIn(str(message["wrapper"]), thread_children)
            observed = TRAIN["descendants"](parent.pid)
            broker, worker = TRAIN["identity"](parent.pid), TRAIN["identity"](message["worker"])
            entry = dict(broker=broker, worker=worker, owned_processes=observed)
            self.assertEqual({item["pid"] for item in observed},
                             {parent.pid, message["wrapper"], message["worker"]})
            self.assertEqual({item["pid"] for item in BROWSER["task_processes"](entry)},
                             {message["wrapper"], message["worker"]})
            with self.assertRaisesRegex(ValueError, "observed task workers still alive"):
                BROWSER["check_task_workers_ended"]([entry])
            self.assertEqual(advance(), {"worker_reaped": True})
            self.assertFalse(TRAIN["alive"](worker))
            with self.assertRaisesRegex(ValueError, "observed task workers still alive"):
                BROWSER["check_task_workers_ended"]([entry])  # Sandbox wrapper still lives.
            self.assertEqual(advance(), {"wrapper_reaped": True})
            self.assertTrue(TRAIN["alive"](broker))
            BROWSER["check_task_workers_ended"]([entry])
            self.assertIn(broker, entry["owned_processes"])  # Full after-stop ownership is unchanged.
        finally:
            try:
                _, errors = parent.communicate(b"xxx", timeout=8)
            except subprocess.TimeoutExpired:
                parent.kill()
                _, errors = parent.communicate(timeout=3)
            self.assertEqual(parent.returncode, 0, errors.decode(errors="replace"))
        self.assertIsNotNone(observed)
        self.assertTrue(all(not TRAIN["alive"](item) for item in observed), "owned fixture child was not reaped")

    def test_task_scope_requires_exact_broker_and_preserves_all_other_processes(self):
        broker, worker, tokenizer = (dict(pid=n, start_ticks=100 + n) for n in (1, 2, 3))
        entry = dict(broker=broker, worker=worker, owned_processes=[broker, worker, tokenizer])
        self.assertEqual(BROWSER["task_processes"](entry), [worker, tokenizer])
        for mutate in (
            lambda e: e["broker"].update(start_ticks=999),
            lambda e: e["worker"].update(start_ticks=999),
            lambda e: e.update(worker=e["broker"]),
            lambda e: e.update(owned_processes=e["owned_processes"][1:]),
            lambda e: e["owned_processes"].append(dict(pid=1, start_ticks=999)),
            lambda e: e["owned_processes"].append(e["broker"]),
        ):
            # Independent objects make changed PID generations genuinely differ.
            changed = json.loads(json.dumps(entry))
            mutate(changed)
            with self.assertRaisesRegex(ValueError, "observed worker ownership differs"):
                BROWSER["task_processes"](changed)
        current = TRAIN["identity"](os.getpid())
        self.assertTrue(TRAIN["alive"](current))
        self.assertFalse(TRAIN["alive"](dict(current, start_ticks=current["start_ticks"] + 1)))

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
