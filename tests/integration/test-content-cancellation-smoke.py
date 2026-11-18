#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert prerequisite clock/receipt checks; not live cancellation evidence."""

import copy
from pathlib import Path
import re
import runpy
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-cancellation-smoke.py"))


class Clock:
    def __init__(self, wall_rate=1):
        self.monotonic = 0
        self.wall = 1000000000000
        self.wall_rate = wall_rate

    def sleep(self, seconds):
        increment = round(seconds * 1000000000)
        self.monotonic += increment
        self.wall += round(increment * self.wall_rate)

    def wait(self, record, confirm):
        CHECK["await_fixture_cooldown"](
            record, confirm, monotonic_ns=lambda: self.monotonic,
            wall_ns=lambda: self.wall, sleep=self.sleep)


class CooldownTests(unittest.TestCase):
    def test_idle_does_not_mean_preselection_ready_and_pause_follows_both_clocks(self):
        clock, record, events = Clock(), CHECK["cooldown_record"](), []

        def confirm(remaining):
            self.assertGreater(remaining(), 0)
            # Both snapshots may say idle while production preselection is cooling.
            events.append(("same-running-services-and-idle", clock.monotonic))

        self.assertLess(8000, CHECK["COOLDOWN_MS"])
        clock.wait(record, confirm)
        events.append(("pause-helper-and-start-fetch", clock.monotonic))
        self.assertEqual(events, [("same-running-services-and-idle", 0),
                                  ("same-running-services-and-idle", 30000000000),
                                  ("pause-helper-and-start-fetch", 30000000000)])
        self.assertEqual(CHECK["validate_cooldown"](record)["outcome"], "elapsed")

    def test_forward_wall_jump_cannot_replace_monotonic_cooldown(self):
        clock, record = Clock(wall_rate=100), CHECK["cooldown_record"]()
        clock.wait(record, lambda remaining: remaining())
        self.assertEqual(record["elapsed_monotonic_ms"], 30000)
        self.assertEqual(record["elapsed_wall_ms"], 3000000)

    def test_slow_wall_clock_must_also_elapse_before_admission(self):
        clock, record = Clock(wall_rate=0.9), CHECK["cooldown_record"]()
        clock.wait(record, lambda remaining: remaining())
        self.assertGreaterEqual(record["elapsed_monotonic_ms"], 33333)
        self.assertGreaterEqual(record["elapsed_wall_ms"], 30000)
        self.assertLess(record["elapsed_monotonic_ms"], 35000)

    def test_wall_clock_stalled_exhausts_absolute_deadline_without_pause(self):
        clock, record, confirms = Clock(wall_rate=0), CHECK["cooldown_record"](), []
        with self.assertRaisesRegex(ValueError, "exceeded deadline"):
            clock.wait(record, lambda remaining: confirms.append(remaining()))
        self.assertEqual(len(confirms), 1)
        self.assertEqual(record["outcome"], "deadline")
        self.assertFalse(record["after_confirmed"])
        self.assertEqual(record["elapsed_monotonic_ms"], 35000)
        CHECK["validate_cooldown"](record)

    def test_wall_clock_rollback_fails_without_final_confirmation(self):
        clock, record = Clock(wall_rate=-1), CHECK["cooldown_record"]()
        with self.assertRaisesRegex(ValueError, "moved backwards"):
            clock.wait(record, lambda remaining: remaining())
        self.assertEqual(record["outcome"], "clock-invalid")
        self.assertFalse(record["after_confirmed"])
        CHECK["validate_cooldown"](record)

    def test_final_identity_and_idle_checks_share_original_deadline(self):
        clock, record, limits = Clock(), CHECK["cooldown_record"](), []

        def confirm(remaining):
            limits.append(remaining())
            if len(limits) == 2:
                clock.sleep(5)

        with self.assertRaisesRegex(ValueError, "exceeded deadline"):
            clock.wait(record, confirm)
        self.assertEqual(limits, [35, 5])
        self.assertEqual(record["outcome"], "deadline")
        self.assertFalse(record["after_confirmed"])

    def test_initial_confirmation_time_does_not_shorten_cooldown(self):
        clock, record, confirms = Clock(), CHECK["cooldown_record"](), []

        def confirm(remaining):
            confirms.append((clock.monotonic, remaining()))
            if len(confirms) == 1:
                clock.sleep(2)

        clock.wait(record, confirm)
        self.assertEqual(confirms, [(0, 35), (32000000000, 3)])
        self.assertEqual(record["elapsed_monotonic_ms"], 30000)
        self.assertEqual(record["elapsed_wall_ms"], 30000)
        self.assertEqual(record["total_monotonic_ms"], 32000)

    def test_initial_confirmation_cannot_extend_absolute_budget(self):
        clock, record, confirms = Clock(), CHECK["cooldown_record"](), []

        def confirm(remaining):
            confirms.append(remaining())
            clock.sleep(5)

        with self.assertRaisesRegex(ValueError, "exceeded deadline"):
            clock.wait(record, confirm)
        self.assertEqual(confirms, [35])
        self.assertEqual(record["total_monotonic_ms"], 35000)
        self.assertFalse(record["after_confirmed"])

    def test_changed_service_or_idle_condition_never_confirms_prerequisite(self):
        for failed_check in (1, 2):
            with self.subTest(failed_check=failed_check):
                clock, record, confirms = Clock(), CHECK["cooldown_record"](), []

                def confirm(remaining):
                    confirms.append(remaining())
                    if len(confirms) == failed_check:
                        raise ValueError("service identity or idle changed")

                with self.assertRaisesRegex(ValueError, "identity or idle"):
                    clock.wait(record, confirm)
                self.assertFalse(record["after_confirmed"])
                self.assertEqual(record["outcome"], "not-confirmed")
                CHECK["validate_cooldown"](record)

    def test_closed_receipt_rejects_shortened_clocks_scope_and_unknown_fields(self):
        value, publication, named = CHECK["sample"]()
        mutations = [dict(required_ms=8000), dict(deadline_ms=40000),
                     dict(elapsed_monotonic_ms=29999), dict(elapsed_wall_ms=29999),
                     dict(elapsed_monotonic_ms=35000), dict(before_confirmed=False),
                     dict(after_confirmed=False), dict(scope="route-ready"),
                     dict(schema_version=True), dict(elapsed_wall_ms=30000.0),
                     dict(raw_log="private"), dict(outcome="deadline"), dict(outcome=[]),
                     dict(total_monotonic_ms=35000), dict(total_monotonic_ms=29999)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                broken = copy.deepcopy(value)
                broken["cooldown_prerequisite"].update(mutation)
                with self.assertRaises(ValueError):
                    CHECK["validate"](broken, publication, named)

    def test_required_cooldown_matches_production_both_clocks(self):
        source = (HERE.parents[1] / "crates/volparossa-agent/src/discovery/preselection_observation.rs").read_text()
        wall = re.search(r"const COOLDOWN_MS: u64 = ([0-9_]+);", source)
        monotonic = re.search(r"const COOLDOWN: Duration = Duration::from_secs\(([0-9]+)\);", source)
        self.assertIsNotNone(wall)
        self.assertIsNotNone(monotonic)
        self.assertEqual(CHECK["COOLDOWN_MS"], int(wall[1].replace("_", "")))
        self.assertEqual(CHECK["COOLDOWN_MS"], 1000 * int(monotonic[1]))

    def test_old_receipt_requires_explicit_historical_validation(self):
        value, publication, named = CHECK["sample"]()
        CHECK["validate"](value, publication, named)
        with self.assertRaises(ValueError):
            CHECK["validate"](value, publication, named, historical=True)
        value["schema_version"] = 1
        with self.assertRaises(ValueError):
            CHECK["validate"](value, publication, named, historical=True)
        value.pop("cooldown_prerequisite")
        CHECK["validate"](value, publication, named, historical=True)
        with self.assertRaises(ValueError):
            CHECK["validate"](value, publication, named)
        value["schema_version"] = 2
        with self.assertRaises(ValueError):
            CHECK["validate"](value, publication, named)

    def test_fixture_orders_prerequisite_before_pause_and_retains_existing_deadlines(self):
        source = (HERE / "content-cancellation-smoke.py").read_text()
        run = source.split("def run(", 1)[1].split("def sample(", 1)[0]
        self.assertLess(run.index("await_fixture_cooldown("), run.index("signal.SIGSTOP"))
        self.assertLess(run.index("await_fixture_cooldown("), run.index("fetching = subprocess.Popen"))
        self.assertIn("time.monotonic() + 8", run)
        self.assertIn("remaining = 4 - (time.monotonic() - started)", run)
        self.assertIn('shutdown["control_eof_ms"] < 2000', run)
        self.assertIn('timeout=min(5, remaining())', run)
        self.assertIn('timeout=min(3, remaining())', run)


if __name__ == "__main__":
    unittest.main()
