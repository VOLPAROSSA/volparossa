#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert compatibility/diagnostic controls; no compiler or native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("probe", Path(__file__).with_name("run-f04-compiler-comparison.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def message(code="clippy::assert_is_empty", level="error", path="crates/example.rs", line=10):
    return dict(reason="compiler-message", message=dict(level=level, code={"code": code} if code else None,
        message="inert diagnostic", spans=[dict(is_primary=True, file_name=path, line_start=line)]))


def log(*items):
    return "\n".join(json.dumps(item) for item in items)


class ComparisonTests(unittest.TestCase):
    def test_real_c11_compatibility_surface_is_exact(self):
        root = Path(__file__).resolve().parents[1]
        originals = {name: subprocess.check_output(["git", "-C", str(root), "show", M.SOURCE + ":" + name])
            for name in set(M.ATOMIC) | set(M.DURATIONS) | set(M.DECLARATIONS)}
        changed = M.compatibility_changes(originals)
        self.assertEqual(len(changed), 13)
        self.assertEqual(sum(raw.count(b".fetch_update(") for name, raw in changed.items() if name in M.ATOMIC), 8)
        self.assertEqual(sum(raw.count(b"Duration::from_secs(900)") for name, raw in changed.items() if name in M.DURATIONS), 4)
        for name, raw in changed.items():
            if name in M.ATOMIC:
                inverse = raw.replace(b".fetch_update(", b".try_update(")
            elif name in M.DURATIONS:
                inverse = raw.replace(b"Duration::from_secs(900)", b"Duration::from_mins(15)")
            else:
                old, new = M.DECLARATIONS[name]
                inverse = raw.replace(new, old)
            self.assertEqual(inverse, originals[name])

    def test_input_path_and_occurrence_expansion_are_rejected(self):
        originals = {name: b".try_update(\n" * count for name, count in M.ATOMIC.items()}
        originals.update({name: b"Duration::from_mins(15)" for name in M.DURATIONS})
        originals.update({name: old for name, (old, _) in M.DECLARATIONS.items()})
        M.compatibility_changes(originals)
        for name in originals:
            changed = copy.deepcopy(originals)
            changed[name] *= 2
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.compatibility_changes(changed)
        originals["extra.rs"] = b"changed"
        with self.assertRaises(ValueError):
            M.compatibility_changes(originals)

    def test_strict_lint_failure_is_valid_incomplete_quality_evidence(self):
        value = M.parse(log(message(), dict(reason="build-finished", success=False)), 101)
        self.assertTrue(value["strict_valid"])
        self.assertFalse(value["complete"])
        self.assertFalse(value["strict_green_observed"])

    def test_actual_strict_green_is_allowed(self):
        value = M.parse(log(dict(reason="build-finished", success=True)), 0)
        self.assertTrue(value["strict_valid"])
        self.assertTrue(value["strict_green_observed"])

    def test_compiler_errors_are_fatal_even_with_lint_inventory(self):
        for code in ("E0658", "E0599", None):
            for status in (0, 101):
                value = M.parse(log(message(), message(code), dict(reason="build-finished", success=False)), status)
                with self.subTest(code=code, status=status):
                    self.assertFalse(value["strict_valid"])
                    self.assertFalse(value["complete"])
                    self.assertEqual(value["first_compiler_error"]["code"], code)

    def test_capped_warning_is_complete_but_capped_error_is_not(self):
        self.assertTrue(M.parse(log(message(level="warning"), dict(reason="build-finished", success=True)), 0)["complete"])
        self.assertFalse(M.parse(log(message(), dict(reason="build-finished", success=True)), 0)["complete"])

    def test_partial_timeout_malformed_and_duplicate_finish_are_incomplete(self):
        cases = ((log(message()), 101), (log(message(), dict(reason="build-finished", success=False)), 124),
                 (log(message(), dict(reason="build-finished", success=False)) + "\nnot json", 101),
                 (log(dict(reason="build-finished", success=True), dict(reason="build-finished", success=True)), 0))
        for raw, status in cases:
            value = M.parse(raw, status)
            with self.subTest(raw=raw, status=status):
                self.assertFalse(value["complete"])
                self.assertFalse(value["strict_valid"])

    def test_external_diagnostics_and_compatibility_deprecations_remain_counted(self):
        raw = log(message(level="warning"), message(level="warning"),
            message("deprecated", "warning", "crates/volparossa-metrics/src/lib.rs", 413),
            message("deprecated", "warning", "/cargo/registry/external.rs", 2),
            dict(reason="build-finished", success=True))
        value = M.parse(raw, 0)
        self.assertEqual(value["unique_primary_count"], 3)
        self.assertEqual(len([d for d in value["unique_primary_diagnostics"] if d["code"] == "deprecated"]), 2)

    def test_host_rejected_before_any_source_or_compiler_operation(self):
        with patch.dict(M.os.environ, {}, clear=True), patch.object(M.subprocess, "check_output", side_effect=AssertionError("execution")):
            with self.assertRaises(ValueError):
                M.prepare()
            with self.assertRaises(ValueError):
                M.run("1.89.0")


if __name__ == "__main__":
    unittest.main()
