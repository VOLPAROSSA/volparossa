#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert argument, scratch-path and memory-gate checks; no VM/browser/service."""
from pathlib import Path
import json
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RUNNERS = ("run-alpha-topology-vm.sh", "kvm-alpha-topology.sh")


class BrowserFilterArguments(unittest.TestCase):
    def call(self, runner, *args):
        return subprocess.run(["/bin/sh", str(HERE / runner), *args],
                              capture_output=True, timeout=5)

    def test_shell_syntax(self):
        for runner in RUNNERS:
            subprocess.run(["/bin/sh", "-n", str(HERE / runner)], check=True, timeout=5)

    def test_original_provider_preview_is_inert_and_available(self):
        for runner in RUNNERS:
            result = self.call(runner, "--preview", "--scenario", "content-provider")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"PREVIEW ONLY", result.stdout)

    def test_bundle_flags_cannot_authorize_preview_execution(self):
        for runner in RUNNERS:
            for flag in ("--browser-filter-bundle", "--browser-filter-manifest-sha256"):
                for value in (None, "", "/unread-fixture"):
                    args = ["--preview", "--scenario", "content-provider", flag]
                    if value is not None:
                        args.append(value)
                    self.assertEqual(self.call(runner, *args).returncode, 64)

    def test_duplicate_flags_are_refused_before_files_or_vm(self):
        for runner in RUNNERS:
            for flag in ("--browser-filter-bundle", "--browser-filter-manifest-sha256"):
                self.assertEqual(self.call(runner, "--execute", "--scenario", "content-provider",
                                           flag, "/unread-one", flag, "/unread-two").returncode, 64)

    def test_bundle_is_not_authorized_by_environment(self):
        for runner in RUNNERS:
            source = (HERE / runner).read_text()
            self.assertIn("\nbrowser_filter_bundle=\n", source)
            self.assertIn("\nbrowser_filter_manifest_sha256=\n", source)
            self.assertIn('[ "$scenario" = content-provider ] || exit 64', source)

    def directory_fragment(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        return source.split("RUN_DIRECTORY_PARENT=/tmp\n", 1)[1].split("QEMU_PID=\n", 1)[0]

    def test_standalone_and_joined_provider_scratch_is_private_disk_sibling(self):
        # Run only the actual path-selection/mktemp/chmod fragment, not the
        # VM driver. This temporary directory itself is on the workspace disk.
        with tempfile.TemporaryDirectory(prefix="filter-runner-test-", dir=HERE) as temporary:
            parent = Path(temporary).resolve(); output = parent / "evidence"; output.mkdir()
            script = ('set -eu\nscenario=content-provider\nbrowser_filter_bundle=$2\n'
                      'output_directory=$1\nRUN_DIRECTORY_PARENT=/tmp\n' + self.directory_fragment()
                      + 'printf "%s\\n" "$RUN_DIRECTORY"\n')
            for bundle, prefix in (("", "content-provider-kvm."), ("/selected/bundle", "browser-filter-kvm.")):
                with self.subTest(bundle=bundle):
                    result = subprocess.run(["/bin/sh", "-c", script, "fixture", str(output), bundle],
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    scratch = Path(result.stdout.decode().strip())
                    self.assertEqual(scratch.parent, parent)
                    self.assertTrue(scratch.name.startswith(prefix))
                    self.assertNotEqual(scratch, output)
                    self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
                    self.assertEqual(list(output.iterdir()), [])

    def test_standalone_and_joined_provider_reject_symlink_output_and_memory_backed_parent(self):
        with tempfile.TemporaryDirectory(prefix="filter-runner-test-", dir=HERE) as temporary:
            parent = Path(temporary).resolve(); output = parent / "evidence"; output.mkdir()
            alias = parent / "alias"; alias.symlink_to(output)
            prefix = 'set -eu\nscenario=content-provider\nbrowser_filter_bundle=$2\noutput_directory=$1\nRUN_DIRECTORY_PARENT=/tmp\n'
            for bundle in ("", "/selected/bundle"):
                for path, filesystem, expected in ((alias, None, 64), (output, "tmpfs", 69),
                                                  (output, "ramfs", 69), (output, "failed", 69)):
                    with self.subTest(bundle=bundle, path=path, filesystem=filesystem):
                        stub = '' if filesystem is None else ('stat() { return 1; }\n' if filesystem == "failed"
                            else 'stat() { printf "%s\\n" "' + filesystem + '"; }\n')
                        result = subprocess.run(["/bin/sh", "-c", prefix + stub + self.directory_fragment(),
                                                 "fixture", str(path), bundle], capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, expected, result.stderr)
                        self.assertEqual({entry.name for entry in parent.iterdir()}, {"evidence", "alias"})

    def test_standalone_provider_selects_disk_and_other_scenario_paths_are_unchanged(self):
        # Stub mktemp/chmod so an ordinary /tmp-path check creates no files.
        script = ('set -eu\nscenario=$1\nbrowser_filter_bundle=$2\noutput_directory=$3\nRUN_DIRECTORY_PARENT=/tmp\n'
                  'mktemp() { printf "%s\\n" "${2%XXXXXX}abcdef"; }\nchmod() { :; }\n'
                  + self.directory_fragment() + 'printf "%s\\n" "$RUN_DIRECTORY"\n')
        with tempfile.TemporaryDirectory(prefix="filter-runner-test-", dir=HERE) as temporary:
            output = Path(temporary).resolve() / "evidence"; output.mkdir()
            for scenario, bundle, prefix in (("content-provider", "", str(output.parent / "content-provider-kvm.")),
                ("alpha", "", "/tmp/volparossa-alpha-kvm."),
                ("agent-native-editor", "", str(output.parent / "native-editor-kvm.")),
                ("agent-cooperative-code", "", str(output.parent / "cooperative-code-kvm."))):
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", scenario, bundle, str(output)],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().strip(), prefix + "abcdef")

    def test_memory_preflight_requires_original_four_gib_guest_plus_two_gib_reserve(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        memory_function = "guest_memory_for_scenario() {\n" + source.split("guest_memory_for_scenario() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        gate = "guest_memory_mib=$(guest_memory_for_scenario)\n" + source.split("guest_memory_mib=$(guest_memory_for_scenario)\n", 1)[1].split("qemu_usernet=", 1)[0]
        script = ('set -eu\nscenario=$1\nbrowser_filter_bundle=$2\nfixture_available=$3\n'
                  'awk() { printf "%s\\n" "$fixture_available"; }\n' + memory_function + gate
                  + 'printf "%s:%s\\n" "$guest_memory_mib" "$runner_reserve_mib"\n')
        cases = (("content-provider", "bundle", 6144 * 1024 - 1, 69, None),
                 ("content-provider", "bundle", 6144 * 1024, 0, "4096:2048"),
                 ("content-provider", "bundle", "unknown", 69, None),
                 ("content-provider", "", 0, 69, None),
                 ("content-provider", "", 6144 * 1024 - 1, 69, None),
                 ("content-provider", "", 6144 * 1024, 0, "4096:2048"),
                 ("content-provider", "", "unknown", 69, None),
                 ("alpha", "", 0, 0, "4096:1024"),
                 ("agent-native-editor", "", 9216 * 1024 - 1, 69, None),
                 ("agent-native-editor", "", 9216 * 1024, 0, "8192:1024"))
        for scenario, bundle, available, code, expected in cases:
            with self.subTest(scenario=scenario, available=available):
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", scenario, bundle, str(available)],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, code, result.stderr)
                if expected is not None: self.assertEqual(result.stdout.decode().strip(), expected)


class BrowserFilterEmergencyExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        body = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        cls.api = {"__name__": "inert_guest_diagnostics_fixture"}
        exec(compile(body, "guest-diagnostics-fixture", "exec"), cls.api)

    def run_collector(self, temporary, raw, diagnostic=None):
        base = Path(temporary).resolve()
        home, opt, proc, cgroups = (base / name for name in ("home", "opt", "proc", "cgroups"))
        for directory in (home, opt, proc, cgroups): directory.mkdir()
        (home / "alpha-output").mkdir()
        work = opt / ("va." + "a" * 32 + ".ABC123"); work.mkdir()
        report = work / "browser-filter-delivery-original-report.json"
        report.write_bytes(raw); report.chmod(0o600)
        if diagnostic is not None:
            path = work / "browser-filter-delivery-original-diagnostic.json"
            path.write_bytes(diagnostic); path.chmod(0o400)
        # These are never candidates, even though their basename is related.
        (work / "browser-filter-delivery.err").write_text("private raw log")
        (work / "browser-filter-delivery-private.json").write_text('{"private_code":"secret"}')
        (work / "client-fixtures").mkdir()
        (work / "client-fixtures/expected.json").write_text('{"private_key":"secret"}')
        # Only the immutable-root staging gate is replaced for this unprivileged
        # unit fixture. The actual closed production JSON validator still runs.
        with patch.dict(self.api, {"browser_filter_helper": lambda root: HERE / "browser-filter-delivery.py"}):
            archive = self.api["collect"](home, opt, "b" * 40, "content-provider", 124, cgroups, proc)
        with tarfile.open(archive, "r:gz") as bundle:
            return {member.name: bundle.extractfile(member).read() for member in bundle.getmembers()}

    def test_validated_original_bytes_survive_without_claiming_acceptance(self):
        raw = b'{ "schema": 1, "passed": true, "failure": null }\n'
        with tempfile.TemporaryDirectory() as temporary:
            files = self.run_collector(temporary, raw)
        name = "work-1/browser-filter-delivery-original-report.json"
        self.assertEqual(files[name], raw)
        summary = json.loads(files["vm-incomplete.json"])
        self.assertFalse(summary["success"])
        self.assertEqual(summary["cleanup"], {"complete": False, "verified": False})
        self.assertEqual(summary["observed_blocker"], "GUEST_EXECUTION_TIMEOUT")
        receipt = next(item for item in summary["diagnostics"]["files"] if item["file"] == name)
        self.assertEqual(receipt["captured_bytes"], len(raw))
        self.assertFalse(receipt["truncated"])
        self.assertFalse(any("private" in name or name.endswith(".err") for name in files))
        manifest = json.loads(files["work-1/browser-filter-delivery-artifacts.json"])
        self.assertFalse(manifest["successful_native_execution_claimed"])

    def test_private_unknown_nested_and_duplicate_fields_are_not_exported(self):
        cases = (
            b'{"schema":1,"passed":true,"failure":null,"private_code":"secret"}',
            b'{"schema":1,"passed":true,"failure":null,"logs":{"browser":{"private_code":"secret"}}}',
            b'{"schema":1,"passed":true,"failure":null,"logs":{"browser":"/private/file"}}',
            b'{"schema":1,"passed":true,"passed":false,"failure":null}',
            b'{"schema":1,"passed":true,"failure":null} trailing',
            b" " * 65537,
        )
        for raw in cases:
            with self.subTest(raw=raw[:90]), tempfile.TemporaryDirectory() as temporary:
                files = self.run_collector(temporary, raw)
            self.assertNotIn("work-1/browser-filter-delivery-original-report.json", files)
            self.assertNotIn("work-1/browser-filter-delivery-artifacts.json", files)
            self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])

    def test_untrusted_helper_cannot_be_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            (work / "bin").mkdir()
            for name in self.api["BROWSER_FILTER_HELPERS"]:
                path = work / "bin" / name
                path.write_text("raise RuntimeError('must not execute')\n")
                path.chmod(0o555)
            # A writable staging directory is rejected even when tests run as root.
            (work / "bin").chmod(0o777)
            self.assertIsNone(self.api["browser_filter_helper"](work))

    def test_closed_failure_phase_survives_emergency_export_without_private_errors(self):
        diagnostic = b'{"schema":1,"success":false,"phase":"topology_namespace","cleanup_failed":false}'
        with tempfile.TemporaryDirectory() as temporary:
            files = self.run_collector(temporary, b'', diagnostic)
        self.assertEqual(files["work-1/browser-filter-delivery-original-diagnostic.json"], diagnostic)
        self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])
        with tempfile.TemporaryDirectory() as temporary:
            files = self.run_collector(temporary, b'', diagnostic.replace(b'topology_namespace', b'private_value'))
        self.assertNotIn("work-1/browser-filter-delivery-original-diagnostic.json", files)


if __name__ == "__main__":
    unittest.main()
