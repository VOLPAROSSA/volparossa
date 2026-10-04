#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure ring contracts and owned local-process cleanup; no network evidence."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "private-storage-fragments-smoke.py"))


def row(timestamp, event="MPTCP_EXIT_FLOW_COMPLETED", level=1):
    return f"{timestamp}\tlevel={level}\tevent={event}\tsession=\tpath=-\n"


def raw(rows):
    return "".join(rows).encode("ascii")


class FlowObserver(unittest.TestCase):
    def test_multiple_wraps_preserve_identical_events_and_count_every_new_record_once(self):
        prefix = [row(900 + i // 10, "PREVIOUS") for i in range(1000)]
        added = [row(1001 + i // 8, "MPTCP_EXIT_FLOW_FAILED" if i % 31 == 0
                     else "MPTCP_EXIT_FLOW_COMPLETED") for i in range(2700)]
        stream = prefix + added
        collector = CHECK["FlowObservation"](1000)
        collector.observe(raw(prefix))
        for end in range(1100, len(stream) + 1, 100):
            collector.observe(raw(stream[end - 1000:end]))
            collector.observe(raw(stream[end - 1000:end]))  # unchanged poll
        gates = collector.report(None, 0, True)
        self.assertEqual(gates["observation"]["observed_records"], len(stream))
        self.assertEqual(gates["exit_mptcp_tls_failed"], 88)
        self.assertEqual(gates["exit_mptcp_tls_completed"], 2612)
        self.assertFalse(gates["exit_log_window_covers_baseline"])
        CHECK["validate_flow_gates"](gates, 2612)
        with tempfile.TemporaryDirectory() as temporary:
            window = Path(temporary) / "private-window"
            window.write_bytes(raw(stream[-1000:]))
            cropped = CHECK["flow_gates"](window, 1000)
            with self.assertRaises(ValueError): CHECK["validate_flow_gates"](cropped, 56)
        self.assertNotIn("MPTCP_EXIT_FLOW_COMPLETED", json.dumps(gates))
        self.assertEqual(len(collector.previous), 1000)  # not a growing log

    def test_partial_last_timestamp_group_and_short_to_full_transition(self):
        stream = [row(1000, "BASELINE")] + [row(1001)] * 3 + [row(1002)] * 4
        collector = CHECK["FlowObservation"](1000)
        collector.observe(raw(stream[:2]))
        collector.observe(raw(stream[:3]))
        collector.observe(raw(stream))
        stream += [row(1003 + i // 5) for i in range(1100)]
        collector.observe(raw(stream[:1000]))
        collector.observe(raw(stream[-1000:]))
        self.assertEqual(collector.completed, len(stream) - 1)
        self.assertEqual(collector.total, len(stream))
        CHECK["validate_flow_gates"](collector.report(None, 0, True), 1107)

    def test_missing_changed_reordered_regressed_or_ambiguous_overlap_refuses(self):
        original = [row(1000 + i // 5) for i in range(1000)]
        advanced = original[100:] + [row(1200 + i // 5) for i in range(100)]
        changed = advanced.copy(); changed[300] = changed[300].replace("level=1", "level=2")
        reversed_group = advanced.copy()
        reversed_group[300] = reversed_group[300].replace("event=MPTCP_EXIT_FLOW_COMPLETED", "event=OTHER")
        invalid = (changed, reversed_group,
            [row(1400 + i) for i in range(1000)],  # entire old tail lost
            [row(900 + i // 5) for i in range(1000)],  # clock regression
            original[:999])  # ring shrank / service restarted
        for following in invalid:
            with self.subTest(following=following[0]):
                collector = CHECK["FlowObservation"](1000)
                collector.observe(raw(original))
                with self.assertRaises(ValueError): collector.observe(raw(following))
                self.assertEqual(collector.snapshots, 1)
                self.assertEqual(collector.total, 1000)
        collector = CHECK["FlowObservation"](1000)
        collector.observe(raw([row(1000)] * 1000))
        with self.assertRaises(ValueError): collector.observe(raw([row(1000)] * 1000))

    def test_invalid_windows_and_snapshot_budget_refuse_without_exporting_raw_text(self):
        invalid = (b"", b"PRIVATE_SENTINEL\n", b"\xff", b"X" * 262145,
            raw([row(1000)] * 1001), raw([row(1001), row(1000)]))
        for value in invalid:
            with self.assertRaises(ValueError): CHECK["parse_flow_window"](value)
        collector = CHECK["FlowObservation"](1000)
        with self.assertRaises(ValueError): collector.observe(raw([row(1001)]))
        collector.observe(raw([row(999), row(1001)]))
        collector.snapshots = 10000
        with self.assertRaises(ValueError): collector.observe(raw([row(999), row(1001)]))

    def test_closed_receipt_does_not_approve_a_truncated_or_failed_observation(self):
        collector = CHECK["FlowObservation"](1000)
        collector.observe(raw([row(1000), row(1001)]))
        collector.observe(raw([row(1000), row(1001), row(1002)]))
        valid = collector.report(None, 0, True)
        CHECK["validate_flow_gates"](valid, 2)
        mutations = (
            lambda v: v["observation"].update(continuity_verified=False),
            lambda v: v["observation"].update(failure="overlap_missing"),
            lambda v: v["observation"].update(command_exit_status=1),
            lambda v: v["observation"].update(command_exit_status=False),
            lambda v: v["observation"].update(command_joined=False),
            lambda v: v["observation"].update(first_oldest_unix_ms=1001),
            lambda v: v["observation"].update(snapshots=10001),
            lambda v: v["observation"].update(observed_records=1),
            lambda v: v.update(exit_log_window_covers_baseline=False),
            lambda v: v.update(exit_mptcp_tls_completed=1),
        )
        for mutate in mutations:
            value = copy.deepcopy(valid); mutate(value)
            with self.assertRaises(ValueError): CHECK["validate_flow_gates"](value, 2)

    def run_observed(self, snapshots, code="pass", minimum=1):
        children = []
        real_popen = subprocess.Popen
        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            children.append(process)
            return process
        def query(_args, **kwargs):
            value = next(snapshots)
            if isinstance(value, Exception): raise value
            kwargs["stdout"].write(value)
            return subprocess.CompletedProcess(_args, 0)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "gates.json"
            with mock.patch.object(subprocess, "run", side_effect=query), \
                 mock.patch.object(subprocess, "Popen", side_effect=spawn):
                status = CHECK["observe_flows"]("never-executed-cli", "never-used-socket", 1000,
                    output, minimum, [sys.executable, "-c", code])
            return status, json.loads(output.read_text()), children

    def test_initial_truncation_prevents_command_start(self):
        status, report, children = self.run_observed(iter([raw([row(1001)])]))
        self.assertEqual((status, children), (1, []))
        self.assertEqual(report["observation"]["failure"], "initial_window_truncated")
        self.assertFalse(report["observation"]["command_joined"])

    def test_poll_timeout_terminates_and_joins_owned_real_command(self):
        status, report, children = self.run_observed(iter([raw([row(1000)]),
            subprocess.TimeoutExpired("PRIVATE_SENTINEL", 2)]), "import time; time.sleep(30)")
        self.assertEqual(status, 1)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertEqual(report["observation"]["failure"], "query_timeout")
        self.assertTrue(report["observation"]["command_joined"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))

    def test_real_command_success_and_failure_are_not_changed_by_valid_logs(self):
        for code, expected in (("pass", 0), ("raise SystemExit(7)", 1)):
            snapshots = iter([raw([row(1000), row(1001)])] * 20)
            status, report, children = self.run_observed(snapshots, code)
            self.assertEqual(status, expected)
            self.assertEqual(report["observation"]["command_exit_status"], 0 if expected == 0 else 7)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(report["observation"]["command_joined"])
            if expected == 0: CHECK["validate_flow_gates"](report, 1)
            else:
                with self.assertRaises(ValueError): CHECK["validate_flow_gates"](report, 1)

    def test_only_cloud_upload_opts_in_and_closed_existing_exports_stay_unchanged(self):
        shell = (HERE / "private-storage-fragments-smoke.sh").read_text()
        self.assertIn('"${storage_incremental_flows:-no}" = yes', shell)
        self.assertIn('"${storage_phase_timeout_seconds:-1500}s" setpriv', shell)
        self.assertIn('"$storage_observe_minimum" -- "$@"', shell)
        self.assertIn("storage_incremental_flows=yes", (HERE / "cloud-private-upload-smoke.sh").read_text())
        for name in ("cloud-private-file-smoke.sh", "image-snapshot-smoke.sh"):
            self.assertNotIn("storage_incremental_flows=yes", (HERE / name).read_text())
        self.assertFalse(any("window" in name for name in CHECK["EXPORT_NAMES"]))
        subprocess.run(["sh", "-n", str(HERE / "private-storage-fragments-smoke.sh")], check=True)


if __name__ == "__main__": unittest.main()
