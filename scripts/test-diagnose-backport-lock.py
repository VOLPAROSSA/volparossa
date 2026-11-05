#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert diagnostic tests: every process invocation is a Python stub, never Cargo."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("lock_diagnostic", Path(__file__).with_name("diagnose-backport-lock.py"))
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)
BEFORE = b'version = 4\n\n[[package]]\nname = "fixture"\nversion = "1.0.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "original"\n'
AFTER = BEFORE + b'\n[[package]]\nname = "new-fixture"\nversion = "1.0.0"\n'
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/quality.yml"


def workflow_step(name):
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index("      - name: " + name) + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("      - name: ")), len(lines))
    return lines[start:end]


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        policy = patch.dict(DIAG.POLICY, validate_diagnostic=lambda cwd, env: dict(env))
        policy.start(); self.addCleanup(policy.stop)
        self.directory = tempfile.TemporaryDirectory(prefix="volparossa-lock-inert-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self.output = self.root / "output"
        for relative in DIAG.HARNESS_FILES:
            path = self.repository / DIAG.HARNESS / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(BEFORE if relative == "Cargo.lock" else b"# inert\n")
        for relative in ("Cargo.lock", "fuzz/Cargo.lock"):
            path = self.repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(BEFORE)
        for name in DIAG.VENDORS:
            path = self.repository / "third_party/rust/vendor" / name
            path.mkdir(parents=True)
            (path / "Cargo.toml").write_text("# inert\n", encoding="ascii")
        self.calls = []

    def runner(self, command, **kwargs):
        self.calls.append(command)
        self.assertEqual(kwargs["timeout"], 120)
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        if command[0] == "sh":
            self.assertEqual(command, ["sh", "scripts/check-rust-dependencies.sh", "--verify-vendor-only"])
        else:
            self.assertEqual(command, ["rustup", "run", "1.85.0", "cargo", "update", "--offline", "--workspace"])
            cwd = Path(kwargs["cwd"])
            self.assertNotEqual(cwd, self.repository / DIAG.HARNESS)
            self.assertTrue((cwd / "src/resolver.rs").is_file())
            self.assertEqual(kwargs["env"]["CARGO_NET_OFFLINE"], "true")
            (cwd / "Cargo.lock").write_bytes(AFTER)
        return subprocess.CompletedProcess(command, 0)

    def test_source_policy_rejection_precedes_offline_cargo_and_preserves_nonacceptance(self):
        with patch.dict(DIAG.POLICY, validate_diagnostic=Mock(side_effect=ValueError('fixed policy rejection'))):
            result = DIAG.diagnose(self.repository, self.output, 101, self.runner)
        self.assertEqual(len(self.calls), 1)  # Source-only vendor verification, no Cargo.
        self.assertFalse(result['acceptance_evidence'])
        self.assertEqual(result['original_fetch_status'], 101)
        self.assertEqual(result['normalization'], 'diagnostic_input_error')

    def test_isolated_four_file_export_never_accepts_original_failure(self):
        result = DIAG.diagnose(self.repository, self.output, 101, self.runner)
        self.assertEqual(result["normalization"], "resolved")
        self.assertTrue(result["existing_registry_pins_preserved"])
        self.assertTrue(result["workspace_locks_unchanged"])
        self.assertFalse(result["acceptance_evidence"])
        self.assertEqual(result["original_fetch_status"], 101)
        self.assertEqual({p.name for p in self.output.iterdir()}, DIAG.EXPORTS)
        self.assertEqual((self.output / "before.Cargo.lock").read_bytes(), BEFORE)
        self.assertEqual((self.output / "after.Cargo.lock").read_bytes(), AFTER)
        self.assertEqual(json.loads((self.output / "status.json").read_text()), result)
        for path in DIAG.REGISTRY_LOCKS:
            self.assertEqual((self.repository / path).read_bytes(), BEFORE)

    def test_failed_source_verification_never_invokes_cargo(self):
        def failed(command, **kwargs):
            self.calls.append(command)
            return subprocess.CompletedProcess(command, 1)
        result = DIAG.diagnose(self.repository, self.output, 101, failed)
        self.assertEqual(result["source_verification"], "failed")
        self.assertEqual(result["normalization"], "not_run")
        self.assertEqual(len(self.calls), 1)

    def test_offline_resolution_failure_is_finite_not_success(self):
        def failed(command, **kwargs):
            result = self.runner(command, **kwargs)
            return subprocess.CompletedProcess(command, 101) if command[0] != "sh" else result
        result = DIAG.diagnose(self.repository, self.output, 101, failed)
        self.assertEqual(result["normalization"], "failed")
        self.assertEqual(result["normalization_exit_status"], 101)
        self.assertFalse(result["acceptance_evidence"])

    def test_timeout_exports_no_process_output(self):
        def timed(command, **kwargs):
            if command[0] == "sh":
                return self.runner(command, **kwargs)
            raise subprocess.TimeoutExpired(command, 120, output=b"DO_NOT_EXPORT")
        result = DIAG.diagnose(self.repository, self.output, 101, timed)
        self.assertEqual(result["normalization"], "timed_out")
        self.assertNotIn("DO_NOT_EXPORT", (self.output / "status.json").read_text())
        self.assertTrue(result["workspace_locks_unchanged"])

    def test_existing_pin_change_is_explicit(self):
        def changed(command, **kwargs):
            result = self.runner(command, **kwargs)
            if command[0] != "sh":
                (Path(kwargs["cwd"]) / "Cargo.lock").write_bytes(AFTER.replace(b'checksum = "original"', b'checksum = "changed"'))
            return result
        result = DIAG.diagnose(self.repository, self.output, 101, changed)
        self.assertEqual(result["normalization"], "registry_pins_changed")
        self.assertFalse(result["existing_registry_pins_preserved"])

    def test_vendor_symlink_is_rejected_before_cargo(self):
        vendor = self.repository / "third_party/rust/vendor" / DIAG.VENDORS[0]
        (vendor / "secret").symlink_to(self.repository / "Cargo.lock")
        result = DIAG.diagnose(self.repository, self.output, 101, self.runner)
        self.assertEqual(result["normalization"], "diagnostic_input_error")
        self.assertEqual(len(self.calls), 1)

    def test_oversized_after_lock_is_not_exported(self):
        def oversized(command, **kwargs):
            result = self.runner(command, **kwargs)
            if command[0] != "sh":
                (Path(kwargs["cwd"]) / "Cargo.lock").write_bytes(b"x" * (DIAG.LIMIT + 1))
            return result
        result = DIAG.diagnose(self.repository, self.output, 101, oversized)
        self.assertEqual(result["normalization"], "diagnostic_input_error")
        self.assertFalse((self.output / "after.Cargo.lock").exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        (self.output / "status.json").write_text("retained", encoding="ascii")
        with self.assertRaises(FileExistsError):
            DIAG.diagnose(self.repository, self.output, 101, self.runner)
        self.assertEqual((self.output / "status.json").read_text(), "retained")
        self.assertFalse(self.calls)

    def test_success_status_is_not_a_diagnostic_trigger(self):
        with self.assertRaises(ValueError):
            DIAG.diagnose(self.repository, self.output, 0, self.runner)
        self.assertFalse(self.calls)

    def test_cli_rejects_non_hosted_execution_before_creating_output(self):
        environment = os.environ.copy()
        environment["GITHUB_ACTIONS"] = "false"
        result = subprocess.run(
            [sys.executable, "-B", str(Path(DIAG.__file__)),
             "--fetch-status", "101", "--output", str(self.output)],
            env=environment, capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("require a non-root Linux GitHub-hosted runner", result.stderr)
        self.assertFalse(self.output.exists())


class WorkflowTests(unittest.TestCase):
    def run_fetch(self, fail_at, diagnostic_status=0):
        step = workflow_step("Fetch locked Rust dependencies")
        self.assertIn("        id: fetch-dependencies", step)
        start = step.index("        run: |") + 1
        script = "\n".join(line[10:] for line in step[start:])
        # Shell functions shadow both executables. This test can never invoke Cargo.
        stubs = '''
attempt=0
cargo() {
  attempt=$((attempt + 1))
  printf 'FETCH %s %s\\n' "$attempt" "$*"
  if [ "$attempt" -eq "$FAIL_AT" ]; then
    return 101
  fi
  return 0
}
python3() {
  printf 'DIAGNOSTIC %s\\n' "$*"
  return "$DIAGNOSTIC_STATUS"
}
'''
        with tempfile.TemporaryDirectory(prefix="volparossa-lock-shell-inert-") as directory:
            output = Path(directory) / "step-output"
            environment = os.environ.copy()
            environment.update({
                "FAIL_AT": str(fail_at), "DIAGNOSTIC_STATUS": str(diagnostic_status),
                "GITHUB_OUTPUT": str(output), "RUNNER_TEMP": directory,
            })
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", stubs + script],
                env=environment, capture_output=True, text=True, timeout=5, check=False,
            )
            outputs = output.read_text() if output.exists() else ""
        self.assertEqual(result.stderr, "")
        return result, outputs

    def test_all_fetches_successful_never_runs_diagnostics(self):
        result, outputs = self.run_fetch(0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(outputs, "")
        self.assertEqual(result.stdout.splitlines(), [
            "FETCH 1 fetch --locked",
            "FETCH 2 fetch --locked --manifest-path fuzz/Cargo.toml",
            "FETCH 3 fetch --locked --manifest-path third_party/rust/backport-regressions/Cargo.toml",
        ])

    def test_root_or_fuzz_failure_never_runs_harness_diagnostics(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                result, outputs = self.run_fetch(fail_at)
                self.assertEqual(result.returncode, 101)
                self.assertEqual(len(result.stdout.splitlines()), fail_at)
                self.assertNotIn("DIAGNOSTIC", result.stdout)
                self.assertEqual(outputs, "")

    def test_harness_failure_preserved_after_diagnostic_success_or_failure(self):
        for diagnostic_status in (0, 17):
            with self.subTest(diagnostic_status=diagnostic_status):
                result, outputs = self.run_fetch(3, diagnostic_status)
                self.assertEqual(result.returncode, 101)
                self.assertEqual(outputs, "backport_lock_diagnostic=true\n")
                self.assertEqual(len(result.stdout.splitlines()), 4)
                self.assertIn("DIAGNOSTIC -B scripts/diagnose-backport-lock.py --fetch-status 101 --output ", result.stdout)

    def test_failure_only_exact_artifact_allowlist(self):
        step = workflow_step("Preserve failed standalone lock reconciliation")
        self.assertIn("        if: ${{ failure() && steps.fetch-dependencies.outputs.backport_lock_diagnostic == 'true' }}", step)
        self.assertIn("        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2", step)
        start = step.index("          path: |") + 1
        paths = []
        for line in step[start:]:
            if not line.startswith("            "):
                break
            paths.append(line.strip())
        self.assertEqual(len(paths), 4)
        self.assertEqual(set(paths), {
            "${{ runner.temp }}/backport-lock-diagnostic/" + name for name in DIAG.EXPORTS
        })
        self.assertIn("          if-no-files-found: error", step)


if __name__ == "__main__":
    unittest.main()
