#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic PSI/clock/descriptor checks; never start a VM or alter host resources."""
import copy
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
HELPER = HERE / "content-provider-resource-ready.py"
CHECK = runpy.run_path(str(HELPER))


def observation(**changes):
    result = dict.fromkeys(CHECK["THRESHOLDS"], "below_threshold")
    result.update(changes)
    return result


class Clock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += round(seconds * 1_000_000_000)


def wait(samples=None, *, clock=None, sampler=None, phase="native"):
    clock = clock or Clock()
    values = iter(samples or [observation()] * 3)
    return CHECK["wait_ready"](phase, sampler=sampler or (lambda: next(values)),
                               clock=clock.clock, sleeper=clock.sleep)


class ResourceReadiness(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="provider-psi-test-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)

    def test_exact_production_threshold_and_byte_limit_parity(self):
        rust = (HERE.parents[1] / "crates/volparossa-agent/src/resource_headroom.rs").read_text()
        actual = {kind: float(value) for kind, value in re.findall(
            r'PressureState::from_average\(observe\("(cpu|memory|io)"\), ([0-9.]+)\)', rust)}
        self.assertEqual(actual, CHECK["THRESHOLDS"])
        self.assertIn("const MAX_SYSTEM_FILE_BYTES: u64 = 16 * 1024;", rust)
        self.assertEqual(CHECK["MAX_SOURCE_BYTES"], 16 * 1024)
        for kind, threshold in actual.items():
            for value, expected in ((0, "below_threshold"), (threshold - 0.001, "below_threshold"),
                                    (threshold, "pressured"), (100, "pressured")):
                result = CHECK["observe"](lambda path: f"some avg10={value if path.name == kind else 0}\n")
                self.assertEqual(result[kind], expected)

    def test_requires_three_consecutive_samples_a_second_apart(self):
        clock = Clock()
        result = wait(clock=clock)
        self.assertEqual(result["status"], "ready")
        self.assertEqual((result["samples"], result["consecutive"], result["elapsed_ms"]), (3, 3, 2000))
        self.assertEqual(clock.sleeps, [1, 1])
        self.assertEqual(result["scope"], CHECK["SCOPE"])
        self.assertFalse(result["scope"]["worker_capacity_proven"])

    def test_pressure_phase_keeps_identical_thresholds_timing_and_failure_policy(self):
        outcomes = (([observation()] * 3, "ready", 3, 2000),
                    ([observation(), observation(cpu="unavailable")], "unavailable", 2, 1000),
                    ([observation(io="pressured")] * 30, "timeout", 30, 30000))
        for values, status, samples, elapsed in outcomes:
            with self.subTest(status=status):
                legacy = wait(values)
                pressure = wait(values, phase="pressure")
                self.assertEqual(pressure, dict(legacy, phase="pressure"))
                self.assertEqual((pressure["status"], pressure["samples"], pressure["elapsed_ms"]),
                                 (status, samples, elapsed))
                self.assertFalse(pressure["scope"]["worker_capacity_proven"])
                self.assertFalse(pressure["scope"]["production_policy_overridden"])

    def test_pressure_file_is_separate_exclusive_and_phase_bound(self):
        self.assertEqual(CHECK["OUTPUTS"], {
            "native": "content-provider-adaptive-resource-ready.json",
            "https": "content-provider-adaptive-https-resource-ready.json",
            "pressure": "content-provider-pressure-resource-ready.json"})
        retained = {}
        for phase in ("native", "https", "pressure"):
            expected = wait(phase=phase)
            self.assertTrue(CHECK["run"](self.work, phase, waiter=lambda _, v=expected: v))
            output = self.work / CHECK["OUTPUTS"][phase]
            retained[output] = output.read_bytes()
            self.assertEqual(json.loads(retained[output]), expected)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertLess(len(retained[output]), 2048)
        with self.assertRaises(ValueError):
            CHECK["run"](self.work, "pressure", waiter=lambda _: self.fail("must not sample twice"))
        for output, raw in retained.items():
            self.assertEqual(output.read_bytes(), raw)

    def test_pressure_rejects_mismatched_receipt_and_unsafe_target_before_export(self):
        target = self.work / CHECK["OUTPUTS"]["pressure"]
        with self.assertRaises(ValueError):
            CHECK["run"](self.work, "pressure", waiter=lambda _: wait(phase="native"))
        self.assertFalse(target.exists())
        target.symlink_to(self.work / "absent")
        with self.assertRaises(ValueError):
            CHECK["run"](self.work, "pressure", waiter=lambda _: self.fail("unsafe pressure target"))

    def test_pressure_resets_sequence_without_resetting_deadline(self):
        result = wait([observation(), observation(), observation(io="pressured"),
                       observation(), observation(), observation()])
        self.assertEqual((result["status"], result["samples"], result["elapsed_ms"]), ("ready", 6, 5000))
        result = wait(sampler=lambda: observation(io="pressured"))
        self.assertEqual((result["status"], result["samples"], result["consecutive"], result["elapsed_ms"]),
                         ("timeout", 30, 0, 30000))

    def test_boundary_final_three_need_to_finish_before_absolute_deadline(self):
        result = wait([observation(io="pressured")] * 27 + [observation()] * 3)
        self.assertEqual((result["status"], result["elapsed_ms"]), ("ready", 29000))
        result = wait([observation(io="pressured")] * 28 + [observation()] * 2)
        self.assertEqual((result["status"], result["consecutive"], result["elapsed_ms"]), ("timeout", 2, 30000))
        clock = Clock()
        calls = 0

        def sampler():
            nonlocal calls
            calls += 1
            if calls == 3:
                clock.now = 30_000_000_000
            return observation()

        result = wait(clock=clock, sampler=sampler)
        self.assertEqual((result["status"], result["samples"], result["consecutive"]), ("timeout", 3, 2))

    def test_slow_sample_and_sleep_overrun_do_not_extend_deadline_or_fabricate_readiness(self):
        clock = Clock()

        def slow():
            clock.now += 31_000_000_000
            return observation()

        result = wait(clock=clock, sampler=slow)
        self.assertEqual((result["status"], result["samples"], result["elapsed_ms"]), ("timeout", 1, 31000))
        self.assertEqual(clock.sleeps, [])
        clock = Clock()
        clock.sleep = lambda seconds: setattr(clock, "now", 31_000_000_000)
        result = wait(clock=clock)
        self.assertEqual((result["status"], result["samples"], result["elapsed_ms"]), ("timeout", 1, 31000))

    def test_early_sleep_return_does_not_count_early_samples(self):
        clock = Clock()
        clock.sleep = lambda seconds: setattr(clock, "now", clock.now + min(250_000_000, round(seconds * 1e9)))
        result = wait(clock=clock)
        self.assertEqual((result["samples"], result["elapsed_ms"]), (3, 2000))

    def test_unavailable_fails_immediately_and_is_not_idle(self):
        clock = Clock()
        result = wait([observation(), observation(cpu="unavailable")], clock=clock)
        self.assertEqual((result["status"], result["samples"], result["consecutive"]), ("unavailable", 2, 0))
        self.assertEqual(clock.sleeps, [1])
        seen = []

        def missing(path):
            seen.append(path.name)
            raise FileNotFoundError("private path must never enter receipt")

        self.assertEqual(CHECK["observe"](missing), dict.fromkeys(CHECK["THRESHOLDS"], "unavailable"))
        self.assertEqual(seen, ["cpu", "memory", "io"])

    def test_malformed_nonfinite_and_missing_some_fields_fail_closed(self):
        texts = ("", "full avg10=0", "some avg60=0", "some avg10=NaN", "some avg10=inf",
                 "some avg10=-1", "some avg10=100.1", "some avg10=1_0", "some avg10=", "some avg10=０")
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual(CHECK["observe"](lambda _: text),
                                 dict.fromkeys(CHECK["THRESHOLDS"], "unavailable"))
        self.assertEqual(CHECK["average"]("full avg10=99\nsome avg10=0.25 avg60=90\n"), 0.25)

    def test_bounded_descriptor_read_and_no_symlink_fifo_directory_or_bad_utf8(self):
        source = self.work / "source"
        source.write_bytes(b"some avg10=0\n" + b" " * (CHECK["MAX_SOURCE_BYTES"] - 13))
        self.assertEqual(len(CHECK["read_bounded"](source)), CHECK["MAX_SOURCE_BYTES"])
        source.write_bytes(source.read_bytes() + b"x")
        with self.assertRaises(ValueError):
            CHECK["read_bounded"](source)
        link = self.work / "link"
        link.symlink_to(source)
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo, self.work):
            with self.subTest(path=path.name), self.assertRaises((OSError, ValueError)):
                CHECK["read_bounded"](path)
        source.write_bytes(b"\xff")
        with self.assertRaises(UnicodeError):
            CHECK["read_bounded"](source)

    def test_zero_size_proc_like_file_still_has_actual_byte_bound_and_always_closes(self):
        source = self.work / "source"
        source.write_bytes(b"")
        actual_open, actual_close = os.open, os.close
        descriptors = []
        closed = []

        def opening(*args, **kwargs):
            self.assertTrue(args[1] & os.O_NOFOLLOW)
            self.assertTrue(args[1] & os.O_NONBLOCK)
            descriptor = actual_open(*args, **kwargs)
            descriptors.append(descriptor)
            return descriptor

        def closing(descriptor):
            closed.append(descriptor)
            actual_close(descriptor)

        with patch.object(os, "open", side_effect=opening), patch.object(os, "close", side_effect=closing):
            with patch.object(os, "read", return_value=b"x" * (CHECK["MAX_SOURCE_BYTES"] + 1)) as read:
                with self.assertRaises(ValueError):
                    CHECK["read_bounded"](source)
                read.assert_called_once_with(descriptors[-1], CHECK["MAX_SOURCE_BYTES"] + 1)
            with patch.object(os, "read", side_effect=OSError("private error")):
                with self.assertRaises(OSError):
                    CHECK["read_bounded"](source)
        self.assertEqual(descriptors, closed)

    def test_each_outcome_is_closed_bounded_private_retained_and_never_overwritten(self):
        for phase, expected in (("native", wait()), ("https", wait(phase="https", sampler=lambda: observation(io="pressured")))):
            self.assertEqual(CHECK["run"](self.work, phase, waiter=lambda _: expected), expected["status"] == "ready")
            output = self.work / CHECK["OUTPUTS"][phase]
            self.assertEqual(json.loads(output.read_bytes()), expected)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertLess(output.stat().st_size, 2048)
            with self.assertRaises(ValueError):
                CHECK["run"](self.work, phase, waiter=lambda _: self.fail("must reject before sampling"))
        unavailable = wait(sampler=lambda: observation(io="unavailable"))
        self.assertEqual(CHECK["validate"](unavailable)["status"], "unavailable")

    def test_unsafe_output_targets_and_directory_fail_without_sampling(self):
        target = self.work / CHECK["OUTPUTS"]["native"]
        target.symlink_to(self.work / "absent")
        with self.assertRaises(ValueError):
            CHECK["run"](self.work, "native", waiter=lambda _: self.fail("unsafe target"))
        self.work.chmod(0o777)
        try:
            with self.assertRaises(ValueError):
                CHECK["run"](self.work, "https", waiter=lambda _: self.fail("unsafe directory"))
        finally:
            self.work.chmod(0o700)

    def test_schema_rejects_forged_ready_free_form_fields_bool_counts_and_expanded_authority(self):
        original = wait()
        for changes in ({"extra": "private"}, {"samples": True}, {"samples": 31}, {"schema_version": True},
                        {"elapsed_ms": 30000}, {"elapsed_ms": 1999}, {"consecutive": 2},
                        {"phase": "unknown"}, {"last_observation": observation(io="pressured")},
                        {"scope": dict(CHECK["SCOPE"], worker_capacity_proven=True)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                CHECK["validate"](dict(original, **changes))
        value = copy.deepcopy(original)
        value["scope"]["memory_capacity_checked"] = 0
        with self.assertRaises(ValueError):
            CHECK["validate"](value)

    def test_cli_invalid_input_does_not_export_raw_paths_or_exceptions(self):
        result = subprocess.run([sys.executable, "-B", str(HELPER), str(self.work / "private"), "invalid"],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"CONTENT_PROVIDER_RESOURCE_READINESS_INVALID\n")

    def test_shell_places_both_gates_after_setup_before_captures_and_retains_exports(self):
        shell = (HERE / "content-provider-adaptive-smoke.sh").read_text()
        native = shell[shell.index("content_provider_adaptive_run() {"):]
        https = shell[shell.index("content_provider_adaptive_https_run() {"):shell.index("content_provider_adaptive_run() {")]
        self.assertLess(native.index("capture_product_logs"), native.index('"$WORK" native'))
        self.assertLess(native.index('"$WORK" native'), native.index("start_privacy_observers"))
        self.assertLess(https.index('"$ah_user/origin.pem"'), https.index('"$WORK" https'))
        self.assertLess(https.index('"$WORK" https'), https.index("start_privacy_observers"))
        self.assertIn("|| fail CONTENT_PROVIDER_ADAPTIVE_RESOURCE_UNAVAILABLE", native)
        self.assertIn("|| fail CONTENT_PROVIDER_ADAPTIVE_HTTPS_RESOURCE_UNAVAILABLE", https)
        runner = (HERE / "run-alpha-topology-vm.sh").read_text()
        safe_names = runner[runner.index("SAFE_NAMES ="):runner.index("def ", runner.index("SAFE_NAMES ="))]
        for name in (CHECK["OUTPUTS"][phase] for phase in ("native", "https")):
            self.assertIn(f'"{name}"', safe_names)
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        provider_preflight = topology[topology.index("for provider_fixture in "):]
        provider_preflight = provider_preflight[:provider_preflight.index("; do")]
        self.assertIn("content-provider-resource-ready.py", provider_preflight)


if __name__ == "__main__":
    unittest.main()
