#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic inventory/clock contracts; no agent, route, namespace or VM runs."""
import io
import json
from pathlib import Path
import re
import runpy
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "content-provider-readiness.py"))
WORK = Path("/opt/va." + "a" * 32 + ".ABC123")


def peers():
    return {name: "1" * 31 + "ABCDEFGHJKLMNPQRSTUVWXYZ"[index]
            for index, name in enumerate(CHECK["FIXTURE_ROLES"])}


def inventory(names):
    expected = peers()
    return "".join(f"{expected[name]}\troles={'0b010' if name.startswith('relay') else '0b100'}\treachability=1\n"
                   for name in names).encode()


class ContentProviderReadiness(unittest.TestCase):
    def run_wait(self, replies):
        elapsed = [0.0]
        calls = []
        sequence = iter(replies)

        def run(command, **options):
            calls.append((command, options))
            reply, duration = next(sequence)
            elapsed[0] += duration
            if isinstance(reply, Exception):
                raise reply
            status, raw = reply
            return SimpleNamespace(returncode=status, stdout=raw)

        def sleep(seconds):
            elapsed[0] += seconds

        runtime = SimpleNamespace(run=run, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
                                  TimeoutExpired=subprocess.TimeoutExpired)
        clock = SimpleNamespace(monotonic=lambda: elapsed[0], sleep=sleep)
        function = CHECK["await_inventory"]
        with patch.dict(function.__globals__, subprocess=runtime, time=clock):
            value = function(WORK, peers())
        self.assertIs(CHECK["closed_record"](value), value)
        for command, options in calls:
            self.assertEqual(command, [str(WORK / "bin/volparossa"), "--control-socket",
                                      str(WORK / "runtime-client/control/agent.sock"), "peers"])
            self.assertEqual(set(options), {"stdout", "stderr", "check", "timeout"})
            self.assertEqual(options["stdout"], subprocess.PIPE)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)
            self.assertFalse(options["check"])
            self.assertGreater(options["timeout"], 0)
            self.assertLessEqual(options["timeout"], 2)
        return value, elapsed[0], calls

    def test_exact_vm3_partial_inventory_does_not_proceed(self):
        # VM3 had R0/R1/R2 plus only the deliberately under-capacity Exit2.
        raw = inventory(("relay0", "relay1", "relay2", "exit2"))
        value, elapsed, calls = self.run_wait([((0, raw), 60)])
        self.assertEqual(elapsed, 60)
        self.assertEqual(len(calls), 1)
        self.assertFalse(value["ready"])
        self.assertEqual(value["outcome"], "deadline")
        self.assertEqual(value["last_valid_presence"], dict(relay0=True, relay1=True, relay2=True, exit=False))

    def test_primary_exit_arrives_then_inventory_barrier_proceeds(self):
        value, elapsed, calls = self.run_wait([
            ((0, inventory(("relay0", "relay1", "relay2", "exit2"))), 0),
            ((0, inventory(("relay0", "relay1", "relay2", "exit", "exit2"))), 0),
        ])
        self.assertTrue(value["ready"])
        self.assertEqual(value["outcome"], "ready")
        self.assertEqual((len(calls), elapsed), (2, 0.1))
        self.assertEqual(value["scope"], "client_advertisement_inventory_not_route_readiness")

    def test_only_three_route_relays_and_primary_exit_are_required(self):
        self.assertEqual(CHECK["INVENTORY_ROLES"], ("relay0", "relay1", "relay2", "exit"))
        value, _, _ = self.run_wait([((0, inventory(CHECK["INVENTORY_ROLES"])), 0)])
        self.assertTrue(value["ready"])

    def test_other_relays_or_exit2_cannot_substitute_for_required_identity(self):
        for missing in CHECK["INVENTORY_ROLES"]:
            with self.subTest(missing=missing):
                names = [name for name in (*CHECK["INVENTORY_ROLES"], "relay3", "relay4", "relay5", "exit2")
                         if name != missing]
                value, _, _ = self.run_wait([((0, inventory(names)), 60)])
                self.assertFalse(value["ready"])
                self.assertFalse(value["last_valid_presence"][missing])

    def test_roles_must_match_even_with_correct_identity_count(self):
        raw = inventory(CHECK["INVENTORY_ROLES"]).replace(b"roles=0b010", b"roles=0b100", 1)
        value, _, _ = self.run_wait([((0, raw), 60)])
        self.assertFalse(value["ready"])
        self.assertFalse(value["last_valid_presence"]["relay0"])

    def test_expected_ids_are_complete_unique_and_immutable(self):
        expected = peers()
        before = dict(expected)
        CHECK["expected_inventory"](expected)
        self.assertEqual(expected, before)
        for modified in (dict(expected, exit=expected["exit2"]), dict(expected, relay4=expected["relay0"]),
                         dict(expected, exit="private-invalid"), dict(expected, extra="2" * 32)):
            with self.assertRaises(ValueError): CHECK["expected_inventory"](modified)
        modified = dict(expected); del modified["bootstrap1"]
        with self.assertRaises(ValueError): CHECK["expected_inventory"](modified)

    def test_malformed_duplicate_oversized_and_truncated_inventory_fail_closed(self):
        valid = inventory(CHECK["INVENTORY_ROLES"])
        for raw in (b"PRIVATE_SENTINEL", b"\xff\n", valid + valid, valid[:-1],
                    b"x" * 1048577, valid.replace(b"reachability=1", b"reachability=9")):
            with self.subTest(raw=raw[:60]):
                self.assertIsNone(CHECK["parse_inventory"](raw))
                value, _, _ = self.run_wait([((0, raw), 60)])
                self.assertFalse(value["ready"])
                self.assertEqual(value["invalid_replies"], 1)
                self.assertIsNone(value["last_valid_presence"])

    def test_transient_query_failures_are_counted_without_exporting_raw_data(self):
        complete = inventory(CHECK["INVENTORY_ROLES"])
        value, _, calls = self.run_wait([
            (subprocess.TimeoutExpired("PRIVATE_SENTINEL", 2), 2),
            ((1, b"PRIVATE_SENTINEL"), 0), ((0, b"PRIVATE_SENTINEL"), 0), ((0, complete), 0),
        ])
        self.assertTrue(value["ready"])
        self.assertEqual((value["query_timeouts"], value["query_nonzero"], value["invalid_replies"]), (1, 1, 1))
        self.assertEqual(len(calls), 4)
        serialized = json.dumps(value)
        self.assertNotIn("PRIVATE_SENTINEL", serialized)
        self.assertTrue(all(peer not in serialized for peer in peers().values()))
        self.assertNotIn(str(WORK), serialized)

    def test_complete_reply_at_deadline_is_not_success(self):
        value, elapsed, _ = self.run_wait([((0, inventory(CHECK["INVENTORY_ROLES"])), 60)])
        self.assertEqual(elapsed, 60)
        self.assertFalse(value["ready"])
        self.assertEqual(value["outcome"], "deadline")

    def test_query_deadlines_shrink_and_do_not_restart_budget(self):
        replies = [(subprocess.TimeoutExpired("closed", 2), 2)] * 28
        replies.append((subprocess.TimeoutExpired("closed", 1.2), 1.2))
        value, elapsed, calls = self.run_wait(replies)
        self.assertAlmostEqual(elapsed, 60)
        self.assertFalse(value["ready"])
        self.assertEqual(value["outcome"], "deadline")
        self.assertAlmostEqual(calls[-1][1]["timeout"], 1.2)

    def test_os_error_has_closed_terminal_receipt(self):
        value, _, _ = self.run_wait([(OSError("PRIVATE_SENTINEL"), 0)])
        self.assertEqual(value["outcome"], "os_error")
        self.assertFalse(value["ready"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(value))

    def test_invalid_fixture_cli_still_emits_closed_error(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            status = CHECK["main"]([])
        value = json.loads(output.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(value["outcome"], "invalid_fixture")
        self.assertIs(CHECK["closed_record"](value), value)

    def test_receipt_rejects_private_fields_false_readiness_and_unbounded_counts(self):
        record = CHECK["new_record"]()
        for change in ({"raw_ids": list(peers().values())}, {"ready": True}, {"attempts": 601},
                       {"last_valid_presence": {"unexpected": True}}, {"scope": "path_readiness_proven"}):
            with self.assertRaises(ValueError): CHECK["closed_record"](dict(record, **change))

    def test_hook_staging_and_exports_are_specific_without_selector_changes(self):
        shell = (HERE / "content-provider-smoke.sh").read_text()
        start = shell.index("content_provider_run() {\n")
        barrier = shell[start:shell.index("    benchmark_bind_slots", start)]
        self.assertLess(barrier.index("content-provider-readiness.py"), barrier.index("benchmark_select_route"))
        self.assertIn('|| fail CONTENT_PROVIDER_INVENTORY_UNAVAILABLE', barrier)
        self.assertIn('benchmark_select_route content-provider mptcp || fail CONTENT_PROVIDER_MPTCP_SELECTION_UNAVAILABLE', barrier)
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertIn('if [ "$scenario" = content-provider ]; then\n'
                      '    install -o root -g root -m 0555 "$source_directory/tests/integration/content-provider-readiness.py"', topology)
        self.assertIn("content-provider-readiness.json", topology.split("copy_artifacts() {", 1)[1].split("\n}", 1)[0])
        self.assertIn('"$WORK"/content-provider-*.json', shell)
        selection = (HERE / "benchmark-selection.sh").read_text()
        retry = selection.split("a01_transient_connect_unavailable() {", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("NO_ELIGIBLE_PATHS", retry)
        self.assertEqual(re.findall(r"\b[A-Z_]+_UNAVAILABLE\b", retry), ["PRESELECTION_UNAVAILABLE",
            "NATIVE_PERMIT_UNAVAILABLE", "NATIVE_RELAY_READY_UNAVAILABLE", "NATIVE_HELPER_COMMIT_UNAVAILABLE",
            "NATIVE_PROBE_START_UNAVAILABLE", "NATIVE_PROBE_PROOF_UNAVAILABLE", "ROUTE_ADMISSION_UNAVAILABLE"])


if __name__ == "__main__":
    unittest.main()
