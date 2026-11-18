#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert cache behavior tests: every Rust/tool execution is replaced by a stub."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("audit_tools", Path(__file__).with_name("quality-audit-tools.py"))
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/quality.yml"


class CacheTests(unittest.TestCase):
    def setUp(self):
        policy = patch.dict(CACHE.POLICY, activate=lambda mode, **kwargs:
                            dict(os.environ, CARGO_HOME=str(kwargs['home'])), audit_tool=lambda name: None,
                            write_scope=lambda *a, **k: None)
        policy.start(); self.addCleanup(policy.stop)
        directory = tempfile.TemporaryDirectory(prefix="audit-cache-inert-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "cache"
        self.expected = {"schema": 1, "platform": "ubuntu-24.04-X64", "tools": CACHE.TOOLS}
        self.calls = []
        env = patch.dict(os.environ, {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
                                      "GITHUB_SHA": "a" * 40})
        env.start()
        self.addCleanup(env.stop)

    def runner(self, command, **kwargs):
        self.calls.append(command)
        self.assertTrue(kwargs["check"])
        if command[:2] == ["rustup", "toolchain"]:
            self.assertIn(command[3], {compiler for compiler, _ in CACHE.TOOLS.values()})
            self.assertEqual(command[4:], ["--profile", "minimal"])
        elif command[:2] == ["rustup", "which"]:
            self.assertEqual(command[2], "--toolchain")
            self.assertEqual(command[4], "rustc")
            return subprocess.CompletedProcess(command, 0, "/inert/" + command[3] + "/rustc\n")
        elif command[:2] == ["rustup", "run"]:
            name = command[-1]
            compiler, version = CACHE.TOOLS[name]
            self.assertEqual(command[2:7], [compiler, "cargo", "install", "--locked", "--root"])
            self.assertEqual(command[8:], ["--version", "=" + version, "--registry", "crates-io", name])
            self.assertEqual(kwargs["env"]["RUSTC"], "/inert/" + compiler + "/rustc")
            self.assertIn('cargo-home-'+name, kwargs['env']['CARGO_HOME'])
            destination = Path(command[7]) / "bin"
            destination.mkdir(parents=True, exist_ok=True)
            (destination / name).write_bytes(b"inert tool fixture: " + name.encode())
            (destination.parent / ".crates.toml").write_text("inert metadata")
        else:
            name = Path(command[0]).name
            self.assertEqual(command, [str(self.root / "bin" / name), "--version"])
            self.assertEqual(kwargs["timeout"], 10)
            return subprocess.CompletedProcess(command, 0, name + " " + CACHE.TOOLS[name][1] + "\n")
        return subprocess.CompletedProcess(command, 0)

    def test_source_or_bundled_archive_rejection_stops_before_any_tool_or_cargo(self):
        for boundary in ('activate', 'audit_tool'):
            with self.subTest(boundary=boundary), patch.dict(CACHE.POLICY,
                    {boundary: Mock(side_effect=ValueError('fixed source-policy rejection'))}):
                run = Mock(side_effect=AssertionError('tool must not execute'))
                with self.assertRaises(ValueError): CACHE.source_build(self.root, self.expected, run)
                run.assert_not_called()
                self.assertFalse((self.root/'receipt.json').exists())

    def seed(self):
        CACHE.source_build(self.root, self.expected, self.runner)
        self.calls.clear()

    def test_miss_builds_only_fixed_source_tools_and_closed_payload(self):
        outcome, size = CACHE.install(self.root, self.expected, False, self.runner)
        self.assertEqual(outcome, "miss-source-built")
        self.assertGreater(size, 0)
        self.assertEqual(len(self.calls), 8)
        self.assertEqual({p.name for p in self.root.iterdir()}, CACHE.FILES)
        self.assertEqual([p.name for p in self.root.parent.iterdir()], ["cache"])

    def test_hit_skips_all_source_builds_and_checks_both_versions(self):
        self.seed()
        outcome, _ = CACHE.install(self.root, self.expected, True, self.runner)
        self.assertEqual(outcome, "hit")
        self.assertEqual(len(self.calls), 2)

    def assert_rebuild(self):
        outcome, _ = CACHE.install(self.root, self.expected, True, self.runner)
        self.assertEqual(outcome, "invalid-source-built")
        # No cached executable may run before a tampered payload is discarded.
        self.assertEqual(self.calls[0][0], "rustup")
        self.assertGreater(CACHE.validate(self.root, self.expected), 0)

    def test_tampered_binary_is_rejected_before_execution(self):
        self.seed()
        (self.root / "bin/cargo-audit").write_bytes(b"changed")
        self.assert_rebuild()

    def test_extra_file_is_rejected(self):
        self.seed()
        (self.root / "credentials").write_text("inert forbidden fixture")
        self.assert_rebuild()

    def test_recipe_drift_is_rejected(self):
        self.seed()
        self.expected["schema"] = 2
        self.assert_rebuild()

    def test_untrusted_producer_is_rejected(self):
        self.seed()
        path = self.root / "receipt.json"
        receipt = json.loads(path.read_text())
        receipt["producer"]["event"] = "pull_request"
        path.write_text(json.dumps(receipt))
        self.assert_rebuild()

    def test_malformed_receipt_is_rejected(self):
        self.seed()
        (self.root / "receipt.json").write_text("{broken")
        self.assert_rebuild()

    def test_deeply_nested_receipt_is_rejected(self):
        self.seed()
        (self.root / "receipt.json").write_text("[" * 1100 + "0" + "]" * 1100)
        self.assert_rebuild()

    def test_missing_receipt_is_rejected(self):
        self.seed()
        (self.root / "receipt.json").unlink()
        self.assert_rebuild()

    def test_symlink_is_rejected_without_touching_target(self):
        self.seed()
        original = self.root / "bin/cargo-audit"
        target = self.root.parent / "outside"
        target.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(target)
        self.assert_rebuild()
        self.assertTrue(target.exists())

    def test_root_symlink_is_removed_without_touching_target(self):
        target = self.root.parent / "outside"
        target.mkdir()
        (target / "preserve").write_text("inert")
        self.root.symlink_to(target, target_is_directory=True)
        self.assert_rebuild()
        self.assertEqual((target / "preserve").read_text(), "inert")

    def test_payload_limit_is_enforced_before_execution(self):
        self.seed()
        with patch.object(CACHE, "MAX_BYTES", 1):
            with self.assertRaises(ValueError):
                CACHE.validate(self.root, self.expected)
        self.assertEqual(self.calls, [])

    def test_inexact_restore_is_never_used(self):
        self.seed()
        CACHE.install(self.root, self.expected, False, self.runner)
        self.assertEqual(self.calls[0][0], "rustup")

    def test_failed_source_build_propagates_and_has_no_receipt(self):
        self.seed()
        def fail(command, **kwargs):
            raise subprocess.CalledProcessError(101, command)
        with self.assertRaises(subprocess.CalledProcessError) as error:
            CACHE.install(self.root, self.expected, False, fail)
        self.assertEqual(error.exception.returncode, 101)
        self.assertFalse(self.root.exists())

    def test_wrong_version_rebuilds_from_source(self):
        self.seed()
        def wrong_version(command, **kwargs):
            if not self.calls:
                self.calls.append(command)
                return subprocess.CompletedProcess(command, 0, "cargo-deny 0.0.0\n")
            return self.runner(command, **kwargs)
        outcome, _ = CACHE.install(self.root, self.expected, True, wrong_version)
        self.assertEqual(outcome, "invalid-source-built")
        self.assertEqual(self.calls[1][0], "rustup")

    def test_recipe_key_changes_for_platform_toolchain_and_helper(self):
        baseline = CACHE.cache_key(self.expected)
        for field in ("platform", "tools", "helper_sha256", "rust_toolchain_sha256", "workflow_sha256"):
            candidate = copy.deepcopy(self.expected)
            candidate[field] = "changed"
            self.assertNotEqual(CACHE.cache_key(candidate), baseline)

    def test_probe_validates_warm_fixture_without_building(self):
        self.seed()
        with patch.object(CACHE, "source_build", side_effect=AssertionError("probe must not build")) as build:
            outcome, size = CACHE.probe(self.root, self.expected, True, self.runner)
        self.assertEqual(outcome, "hit")
        self.assertGreater(size, 0)
        self.assertEqual(len(self.calls), 2)
        build.assert_not_called()

    def test_probe_miss_and_tamper_fail_without_execution_or_build(self):
        self.seed()
        (self.root / "bin/cargo-deny").write_bytes(b"tampered")
        with patch.object(CACHE, "source_build", side_effect=AssertionError("probe must not build")) as build:
            for exact_hit in (False, True):
                with self.assertRaises(ValueError):
                    CACHE.probe(self.root, self.expected, exact_hit, self.runner)
        self.assertEqual(self.calls, [])
        build.assert_not_called()

    def test_cli_guards_platform_and_never_publishes_for_pr_or_manual(self):
        self.seed()
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "GITHUB_REPOSITORY": "VOLPAROSSA/volparossa",
               "RUNNER_TEMP": str(self.root.parent), "AUDIT_CACHE_KEY": CACHE.cache_key(self.expected)}
        with patch.dict(os.environ, env), patch.object(CACHE, "recipe", return_value=self.expected), \
                patch.object(sys, "argv", ["quality-audit-tools.py", "save-check"]):
            for event, ref in (("pull_request", "refs/pull/1/merge"), ("workflow_dispatch", "refs/heads/main"),
                               ("push", "refs/heads/feature/test")):
                with patch.dict(os.environ, {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref}):
                    with self.assertRaises(ValueError):
                        CACHE.main()
            with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}):
                with self.assertRaises(ValueError):
                    CACHE.main()

    def test_cli_emits_hit_bytes_timing_and_path_after_validation(self):
        self.seed()
        self.root.rename(self.root.parent / "quality-audit-tools")
        self.root = self.root.parent / "quality-audit-tools"
        records = {name: self.root.parent / name for name in ("GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY")}
        env = {name: str(path) for name, path in records.items()}
        env.update({"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                    "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "GITHUB_REPOSITORY": "VOLPAROSSA/volparossa",
                    "RUNNER_TEMP": str(self.root.parent), "AUDIT_CACHE_KEY": CACHE.cache_key(self.expected),
                    "AUDIT_CACHE_EXACT_HIT": "true"})
        # Version commands remain inert; the real inventory/digest validation runs.
        with patch.dict(os.environ, env), patch.object(CACHE, "recipe", return_value=self.expected), \
                patch.object(CACHE, "versions", side_effect=lambda root, *args: self.runner(
                    [str(root / "bin/cargo-deny"), "--version"], check=True, timeout=10)), \
                patch.object(sys, "argv", ["quality-audit-tools.py", "install"]):
            CACHE.main()
        self.assertIn("source-built=false", records["GITHUB_OUTPUT"].read_text())
        self.assertEqual(records["GITHUB_PATH"].read_text(), str(self.root / "bin") + "\n")
        summary = records["GITHUB_STEP_SUMMARY"].read_text()
        for marker in ("`hit`", "bytes", "time:", CACHE.cache_key(self.expected)):
            self.assertIn(marker, summary)
        for path in records.values():
            path.unlink()
        env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        with patch.dict(os.environ, env), patch.object(CACHE, "recipe", return_value=self.expected), \
                patch.object(CACHE, "versions"), patch.object(CACHE, "source_build") as build, \
                patch.object(sys, "argv", ["quality-audit-tools.py", "probe"]):
            CACHE.main()
        build.assert_not_called()
        self.assertFalse(records["GITHUB_OUTPUT"].exists())
        self.assertFalse(records["GITHUB_PATH"].exists())
        self.assertIn("no Quality gates run", records["GITHUB_STEP_SUMMARY"].read_text())

    def test_probe_workflow_is_main_manual_only_and_restore_only(self):
        workflow = WORKFLOW.with_name("quality-audit-cache.yml").read_text()
        self.assertIn("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", workflow)
        for marker in ("timeout-minutes: 5", "runs-on: ubuntu-24.04", "fail-on-cache-miss: true",
                       "persist-credentials: false", "scripts/quality-audit-tools.py probe"):
            self.assertIn(marker, workflow)
        for forbidden in ("actions/cache/save", "restore-keys:", " install", " push:", " pull_request:"):
            self.assertNotIn(forbidden, workflow)

    def test_workflow_uses_only_pinned_restore_save_and_main_only_publication(self):
        workflow = WORKFLOW.read_text()
        self.assertNotIn("restore-keys:", workflow)
        pin = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
        self.assertIn("uses: actions/cache/restore@" + pin, workflow)
        self.assertIn("uses: actions/cache/save@" + pin, workflow)
        save = workflow.split("      - name: Save own audit-tool build", 1)[1]
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", save)
        self.assertIn("steps.audit-cache-save.outputs.cacheable == 'true'", save)
        for gate in ("Run strict Clippy", "Run workspace tests", "Check locked dependencies and licenses",
                     "Report namespace-backed proof outcomes", "Check non-mutating integration harness"):
            self.assertLess(workflow.index("      - name: " + gate), workflow.index("      - name: Save own audit-tool build"))


if __name__ == "__main__":
    unittest.main()
