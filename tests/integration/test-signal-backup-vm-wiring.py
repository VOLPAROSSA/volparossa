#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure guest dispatch and private artifact boundaries; no network, VM or native execution."""

import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "run-alpha-topology-vm.sh").read_text()
DRIVER = SOURCE.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
COLLECTOR = SOURCE.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
MODULE = {"__name__": "signal_backup_wiring_test"}
exec(compile(COLLECTOR, "guest_diagnostics", "exec"), MODULE)


class SignalBackupWiring(unittest.TestCase):
    def test_preview_resource_and_guest_command_contract(self):
        result = subprocess.run(["sh", str(HERE / "run-alpha-topology-vm.sh"), "--preview",
                                 "--scenario", "signal-backup"], capture_output=True, text=True,
                                timeout=10, check=True)
        self.assertIn("PREVIEW ONLY", result.stdout)
        self.assertIn("6144 MiB", result.stdout)
        self.assertIn("32 GiB disposable disk", result.stdout)
        self.assertIn("real Signal encrypted backup export/import", result.stdout)
        syntax = subprocess.run(["sh", "-n"], input=DRIVER, capture_output=True, text=True,
                                timeout=3, check=False)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertIn('signal-backup ] || guest_disk_size=32G', SOURCE)
        self.assertIn('signal-backup ] || driver_time_bound=7200s', SOURCE)
        self.assertIn("bubblewrap xvfb xauth libgtk-3-0t64", DRIVER)
        self.assertIn("python3 -B tests/integration/signal-backup-provision.py provision", DRIVER)
        self.assertIn("/home/vpci/signal-backup-runtime --download", DRIVER)
        self.assertLess(DRIVER.index("guest_phase signal-backup-provision"), DRIVER.index("guest_phase build"))
        self.assertNotIn("chmod 4755", DRIVER)

    def test_exact_failure_exports_never_include_raw_app_or_credentials(self):
        fixture = runpy.run_path(str(HERE / "signal-backup-smoke.py"))
        extras = {"signal-backup-provision.json", "host-state-before.json", "host-state-after.json",
                  "guest-exit-status", "current-phase"}
        self.assertEqual(MODULE["SIGNAL_NAMES"], set(fixture["EXPORT_NAMES"]) | extras)
        with tempfile.TemporaryDirectory(prefix="volparossa-signal-export-") as directory:
            root = Path(directory)
            home = root / "home"
            published = home / "alpha-output"
            published.mkdir(parents=True)
            runtime = home / "signal-backup-runtime"
            runtime.mkdir()
            (runtime / "provision.json").write_text('{"success":false}\n')
            (home / "guest-phase.txt").write_text("signal-backup-provision\n")
            for name in MODULE["SIGNAL_NAMES"]:
                (published / name).write_text("{}\n")
            for parent, name in ((home, "cargo-build.log"), (published, "runner.stdout"),
                                 (published, "runner.stderr"), (published, "native.log"),
                                 (published, "config.json"), (published, "grant-a.bin"),
                                 (published, "content-provider-private.log"),
                                 (published, "signal-backup-unapproved.json"),
                                 (published, "archive.signal")):
                (parent / name).write_text("PRIVATE_DO_NOT_EXPORT\n")
            archive = MODULE["collect"](home, root / "missing-opt", "a" * 40, "signal-backup", 1,
                                        root / "missing-cgroups", root / "missing-proc")
            with tarfile.open(archive) as bundle:
                self.assertEqual(set(bundle.getnames()),
                    {f"published/{name}" for name in MODULE["SIGNAL_NAMES"]}
                    | {"driver/guest-phase.txt", "driver/signal-backup-provision.json", "vm-incomplete.json"})
                for member in bundle.getmembers():
                    self.assertNotIn(b"PRIVATE_DO_NOT_EXPORT", bundle.extractfile(member).read())
                report = json.load(bundle.extractfile("vm-incomplete.json"))
            self.assertFalse(report["success"])
            self.assertFalse(report["cleanup"]["verified"])
            self.assertEqual(report["driver_phase"], "signal-backup-provision")

    def test_complete_archive_and_workflow_use_dedicated_proof(self):
        archive = DRIVER.split("# The exact closed receipt files", 1)[1].split("\nelse\n", 1)[0]
        self.assertIn("signal-backup-smoke.py export-names", archive)
        self.assertIn('stat -Lc', archive)
        self.assertIn(' -le 131072', archive)
        self.assertIn(' -T /home/vpci/signal-backup-export.list', archive)
        self.assertNotIn('tar.gz .', archive)
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("          - signal-backup\n", workflow)
        self.assertIn("inputs.scenario == 'signal-backup' && 150", workflow)
        gate = workflow.split("      - name: Require real Signal encrypted backup", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('signal-backup-smoke.py report "$report" "$GITHUB_SHA"', gate)
        self.assertIn("host-state-before.json", gate)
        self.assertIn("host-state-after.json", gate)
        self.assertEqual(workflow.count("env.VOLPAROSSA_ALPHA_SCENARIO != 'signal-backup'"), 2)


if __name__ == "__main__":
    unittest.main()
