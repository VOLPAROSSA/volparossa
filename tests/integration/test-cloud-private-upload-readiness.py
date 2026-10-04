#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed readiness/parser regressions; no route or model execution claim."""
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "cloud-private-upload-smoke.py"))


def peers():
    names = ("client", "bootstrap1", "bootstrap2", *CHECK["INVENTORY_ROLES"])
    return {name: "1" * 31 + "ABCDEFGHJKLMNPQRSTUVWXYZ"[i] for i, name in enumerate(names)}


def inventory(value):
    return "".join(f"{peer}\troles={role}\treachability=1\n" for peer, role in value.items()).encode()


class Readiness(unittest.TestCase):
    def test_exact_identities_and_roles_not_just_count(self):
        expected = CHECK["expected_inventory"](peers())
        self.assertEqual(CHECK["parse_inventory"](inventory(expected)), expected)
        changed = dict(expected)
        changed[next(iter(changed))] = "0b100"
        self.assertNotEqual(CHECK["parse_inventory"](inventory(changed)), expected)
        changed = dict(expected); changed["2" * 32] = changed.pop(next(iter(changed)))
        self.assertEqual(len(changed), 8)
        self.assertNotEqual(CHECK["parse_inventory"](inventory(changed)), expected)
        wrong = peers(); wrong["exit2"] = wrong["exit"]
        with self.assertRaises(ValueError): CHECK["expected_inventory"](wrong)

    def test_malformed_duplicate_and_oversized_inventory_rejected(self):
        raw = inventory(CHECK["expected_inventory"](peers()))
        for invalid in (b"PRIVATE_SENTINEL", b"\xff", raw + raw, b"x" * 1048577,
                        raw.replace(b"reachability=1", b"reachability=9")):
            self.assertIsNone(CHECK["parse_inventory"](invalid))

    def run_wait(self, replies, deadline=False):
        fn = CHECK["await_inventory"]
        clock = SimpleNamespace(now=0.0)
        def tick():
            clock.now += 15 if deadline else 0.001
            return clock.now
        def run(command, **kwargs):
            self.assertEqual(command[-1], "peers")
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertLessEqual(kwargs["timeout"], 2)
            reply = replies.pop(0)
            if isinstance(reply, Exception): raise reply
            return reply
        fake_process = SimpleNamespace(run=run, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
            TimeoutExpired=subprocess.TimeoutExpired)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "a01-expected-peers.json").write_text(json.dumps(peers()))
            with patch.dict(fn.__globals__, time=SimpleNamespace(monotonic=tick, sleep=lambda _: None),
                            subprocess=fake_process):
                return fn(work, "/exact/pinned/volparossa")

    def test_timeout_and_nonzero_are_closed_before_exact_ready(self):
        complete = inventory(CHECK["expected_inventory"](peers()))
        value = self.run_wait([
            subprocess.TimeoutExpired("PRIVATE_SENTINEL", 2),
            SimpleNamespace(returncode=1, stdout=b"PRIVATE_SENTINEL"),
            SimpleNamespace(returncode=0, stdout=b"PRIVATE_SENTINEL"),
            SimpleNamespace(returncode=0, stdout=complete)])
        self.assertTrue(value["ready"])
        self.assertEqual((value["attempts"], value["query_timeouts"], value["query_nonzero"], value["invalid_replies"]), (4, 1, 1, 1))
        self.assertEqual(set(value["last_valid_presence"]), set(CHECK["INVENTORY_ROLES"]))
        encoded = json.dumps(value)
        self.assertNotIn("PRIVATE_SENTINEL", encoded)
        for peer in peers().values(): self.assertNotIn(peer, encoded)

    def test_partial_inventory_at_original_deadline_remains_failure(self):
        partial = CHECK["expected_inventory"](peers()); partial.pop(peers()["exit"])
        value = self.run_wait([SimpleNamespace(returncode=0, stdout=inventory(partial))], deadline=True)
        self.assertFalse(value["ready"])
        self.assertEqual(value["deadline_seconds"], 60)
        self.assertFalse(value["last_valid_presence"]["exit"])

    def test_retained_sampler_counts_never_export_raw_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs"
            self.assertEqual(CHECK["preselection_events"](path)["state"], "absent")
            path.write_text("1\tlevel=0\tevent=PRESELECTION_SAMPLE_NO_EXIT\tsession=abcd\tpath=-\n"
                            "2\tlevel=0\tevent=PRESELECTION_SAMPLE_PRIVATE_SENTINEL\tsession=abcd\tpath=-\n")
            path.chmod(0o600)
            value = CHECK["preselection_events"](path)
            self.assertEqual(value["counts"]["PRESELECTION_SAMPLE_NO_EXIT"], 1)
            self.assertEqual(value["unrecognized_reason_records"], 1)
            self.assertEqual(value["scope"], "retained_client_log_ring_not_last_attempt_proof")
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(value))
            self.assertNotIn("abcd", json.dumps(value))
            path.write_text("PRIVATE_SENTINEL")
            self.assertEqual(CHECK["preselection_events"](path)["state"], "invalid")

    def test_barrier_precedes_unchanged_connect_and_closed_exports(self):
        shell = (HERE / "cloud-private-upload-smoke.sh").read_text()
        self.assertLess(shell.index("await-inventory"), shell.index("    private_storage_fragments_run"))
        self.assertIn("preselection-events", shell)
        self.assertIn("cloud-private-upload-readiness.json", CHECK["EXPORT_NAMES"])
        for private in ("logs-client.txt", "cloud-preselection.part", "private-storage-fragments-connect.err"):
            self.assertNotIn(private, CHECK["EXPORT_NAMES"])
        source = (HERE / "benchmark-selection.sh").read_text()
        retry = source.split("a01_transient_connect_unavailable()", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("NO_ELIGIBLE_PATHS", retry)


if __name__ == "__main__": unittest.main()
